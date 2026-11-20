/**
 * Flag evaluation engine: targeting rules + deterministic, sticky percentage rollouts.
 * Pure functions with no I/O: the same code runs on the server and can be shipped to SDKs.
 */

export type AttrValue = string | number | boolean | string[];
export interface EvalContext {
  key: string;
  attributes?: Record<string, AttrValue>;
}

export type Operator =
  | "eq" | "neq" | "in" | "not_in" | "contains" | "starts_with" | "ends_with"
  | "gt" | "gte" | "lt" | "lte" | "semver_gte" | "semver_lt";

export interface Clause {
  attribute: string; // "key" refers to the context key itself
  op: Operator;
  values: (string | number | boolean)[];
}

export interface WeightedVariant {
  variant: string;
  weight: number; // in thousandths of a percent: 100000 = 100%
}

export type Serve = { variant: string } | { rollout: WeightedVariant[] };

export interface Rule {
  id: string;
  description?: string;
  clauses: Clause[]; // all must match (AND)
  serve: Serve;
}

export interface Variant {
  key: string;
  value: unknown;
}

export interface FlagConfig {
  key: string;
  variants: Variant[];
  enabled: boolean;
  offVariant: string;
  rules: Rule[];
  fallthrough: Serve;
  salt?: string;
}

export type Reason =
  | { kind: "OFF" }
  | { kind: "RULE_MATCH"; ruleIndex: number; ruleId: string; inRollout?: boolean }
  | { kind: "FALLTHROUGH"; inRollout?: boolean }
  | { kind: "ERROR"; error: string };

export interface Evaluation {
  value: unknown;
  variant: string | null;
  reason: Reason;
}

export const BUCKETS = 100_000;

/** MurmurHash3 (x86, 32-bit). Stable across languages, so SDKs in any language bucket identically. */
export function murmur3(input: string, seed = 0): number {
  const data = new TextEncoder().encode(input);
  let h = seed >>> 0;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  const nblocks = data.length >> 2;
  for (let i = 0; i < nblocks; i++) {
    let k = data[i * 4] | (data[i * 4 + 1] << 8) | (data[i * 4 + 2] << 16) | (data[i * 4 + 3] << 24);
    k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2);
    h ^= k; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  let k = 0;
  const tail = nblocks * 4;
  switch (data.length & 3) {
    case 3: k ^= data[tail + 2] << 16; // falls through
    case 2: k ^= data[tail + 1] << 8; // falls through
    case 1:
      k ^= data[tail];
      k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k;
  }
  h ^= data.length;
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return h >>> 0;
}

/** Bucket in [0, BUCKETS). Depends only on flag key, salt and context key, so it is sticky per user. */
export function bucket(flagKey: string, salt: string, contextKey: string): number {
  return murmur3(`${flagKey}.${salt}.${contextKey}`) % BUCKETS;
}

/**
 * Pick a variant from a weighted rollout. Variants occupy contiguous bucket ranges in order,
 * so growing the first variant's weight from 10% to 20% keeps everyone who was already in it.
 */
export function pickFromRollout(rollout: WeightedVariant[], b: number): string | null {
  let upper = 0;
  for (const wv of rollout) {
    upper += wv.weight;
    if (b < upper) return wv.variant;
  }
  return null;
}

function parseSemver(v: unknown): [number, number, number] | null {
  const m = String(v).trim().replace(/^v/, "").match(/^(\d+)\.(\d+)\.(\d+)/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function compareSemver(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

function asNumber(v: unknown): number | null {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
}

function matchOne(actual: unknown, op: Operator, expected: string | number | boolean): boolean {
  switch (op) {
    case "eq": case "in": return String(actual) === String(expected);
    case "neq": case "not_in": return String(actual) !== String(expected);
    case "contains": return String(actual).includes(String(expected));
    case "starts_with": return String(actual).startsWith(String(expected));
    case "ends_with": return String(actual).endsWith(String(expected));
    case "gt": case "gte": case "lt": case "lte": {
      const a = asNumber(actual), e = asNumber(expected);
      if (a === null || e === null) return false;
      return op === "gt" ? a > e : op === "gte" ? a >= e : op === "lt" ? a < e : a <= e;
    }
    case "semver_gte": case "semver_lt": {
      const a = parseSemver(actual), e = parseSemver(expected);
      if (!a || !e) return false;
      const c = compareSemver(a, e);
      return op === "semver_gte" ? c >= 0 : c < 0;
    }
  }
}

export function clauseMatches(clause: Clause, ctx: EvalContext): boolean {
  const raw = clause.attribute === "key" ? ctx.key : ctx.attributes?.[clause.attribute];
  if (raw === undefined || raw === null) return clause.op === "neq" || clause.op === "not_in";
  const actuals = Array.isArray(raw) ? raw : [raw];
  const negative = clause.op === "neq" || clause.op === "not_in";
  if (negative) {
    // "not in [a, b]" holds only if no actual value equals any listed value
    return actuals.every((a) => clause.values.every((v) => matchOne(a, clause.op, v)));
  }
  return actuals.some((a) => clause.values.some((v) => matchOne(a, clause.op, v)));
}

function serveVariant(flag: FlagConfig, serve: Serve, ctx: EvalContext): { variant: string | null; inRollout: boolean } {
  if ("variant" in serve) return { variant: serve.variant, inRollout: false };
  const b = bucket(flag.key, flag.salt ?? flag.key, ctx.key);
  return { variant: pickFromRollout(serve.rollout, b), inRollout: true };
}

export function evaluate(flag: FlagConfig, ctx: EvalContext): Evaluation {
  const variantValue = (key: string | null): Evaluation | null => {
    const v = flag.variants.find((x) => x.key === key);
    return v ? { value: v.value, variant: v.key, reason: { kind: "OFF" } } : null;
  };
  if (!ctx || typeof ctx.key !== "string" || ctx.key === "") {
    return { value: variantValue(flag.offVariant)?.value ?? null, variant: flag.offVariant, reason: { kind: "ERROR", error: "context.key is required" } };
  }
  if (!flag.enabled) {
    const off = variantValue(flag.offVariant);
    return off ?? { value: null, variant: null, reason: { kind: "ERROR", error: `unknown off variant '${flag.offVariant}'` } };
  }
  for (let i = 0; i < flag.rules.length; i++) {
    const rule = flag.rules[i];
    if (rule.clauses.every((c) => clauseMatches(c, ctx))) {
      const { variant, inRollout } = serveVariant(flag, rule.serve, ctx);
      const v = variantValue(variant);
      if (!v) return { value: null, variant: null, reason: { kind: "ERROR", error: `rule '${rule.id}' serves an unknown variant` } };
      return { ...v, reason: { kind: "RULE_MATCH", ruleIndex: i, ruleId: rule.id, ...(inRollout ? { inRollout } : {}) } };
    }
  }
  const { variant, inRollout } = serveVariant(flag, flag.fallthrough, ctx);
  const v = variantValue(variant);
  if (!v) return { value: null, variant: null, reason: { kind: "ERROR", error: "fallthrough serves an unknown variant" } };
  return { ...v, reason: { kind: "FALLTHROUGH", ...(inRollout ? { inRollout } : {}) } };
}

/** Validate a configuration against its variants; returns human-readable problems (empty = valid). */
export function validateConfig(flag: Pick<FlagConfig, "variants" | "offVariant" | "rules" | "fallthrough">): string[] {
  const problems: string[] = [];
  const keys = new Set(flag.variants.map((v) => v.key));
  const checkServe = (serve: Serve, where: string) => {
    if ("variant" in serve) {
      if (!keys.has(serve.variant)) problems.push(`${where}: unknown variant '${serve.variant}'`);
      return;
    }
    const total = serve.rollout.reduce((s, w) => s + w.weight, 0);
    if (total !== BUCKETS) problems.push(`${where}: rollout weights must sum to ${BUCKETS} (100%), got ${total}`);
    for (const w of serve.rollout) {
      if (!keys.has(w.variant)) problems.push(`${where}: unknown variant '${w.variant}'`);
      if (w.weight < 0 || !Number.isInteger(w.weight)) problems.push(`${where}: weights must be non-negative integers`);
    }
  };
  if (!keys.has(flag.offVariant)) problems.push(`offVariant: unknown variant '${flag.offVariant}'`);
  const ids = new Set<string>();
  flag.rules.forEach((r, i) => {
    if (ids.has(r.id)) problems.push(`rules[${i}]: duplicate rule id '${r.id}'`);
    ids.add(r.id);
    if (!r.clauses.length) problems.push(`rules[${i}]: a rule needs at least one clause`);
    checkServe(r.serve, `rules[${i}]`);
  });
  checkServe(flag.fallthrough, "fallthrough");
  return problems;
}
