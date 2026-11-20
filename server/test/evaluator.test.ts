import { describe, expect, it } from "vitest";
import { BUCKETS, bucket, clauseMatches, evaluate, murmur3, pickFromRollout, validateConfig, type FlagConfig } from "../src/evaluator.js";

const pct = (p: number) => Math.round(p * 1000);
const boolFlag = (over: Partial<FlagConfig> = {}): FlagConfig => ({
  key: "new-checkout",
  variants: [{ key: "on", value: true }, { key: "off", value: false }],
  enabled: true,
  offVariant: "off",
  rules: [],
  fallthrough: { variant: "off" },
  ...over,
});

describe("murmur3", () => {
  it("matches the reference MurmurHash3 x86_32 test vectors", () => {
    expect(murmur3("", 0)).toBe(0);
    expect(murmur3("", 1)).toBe(0x514e28b7);
    expect(murmur3("hello", 0)).toBe(0x248bfa47);
    expect(murmur3("Hello, world!", 0)).toBe(0xc0363e43);
    expect(murmur3("The quick brown fox jumps over the lazy dog", 0)).toBe(0x2e4ff723);
    expect(murmur3("नमस्ते")).toBe(murmur3("नमस्ते")); // utf-8 safe and deterministic
  });
});

describe("rollouts", () => {
  it("are deterministic, roughly uniform and independent per flag", () => {
    expect(bucket("f", "f", "user-1")).toBe(bucket("f", "f", "user-1"));
    const n = 20000;
    let inTen = 0, sameAcrossFlags = 0;
    for (let i = 0; i < n; i++) {
      const b = bucket("flag-a", "flag-a", `user-${i}`);
      if (b < pct(10)) inTen++;
      if ((bucket("flag-b", "flag-b", `user-${i}`) < pct(10)) === (b < pct(10))) sameAcrossFlags++;
    }
    expect(inTen / n).toBeGreaterThan(0.09);
    expect(inTen / n).toBeLessThan(0.11);
    expect(sameAcrossFlags / n).toBeLessThan(0.85); // not the same 10% of users for every flag
  });

  it("are sticky: increasing a rollout keeps everyone who already had it", () => {
    const at = (p: number) => [{ variant: "on", weight: pct(p) }, { variant: "off", weight: BUCKETS - pct(p) }];
    for (let i = 0; i < 2000; i++) {
      const b = bucket("f", "f", `u${i}`);
      if (pickFromRollout(at(10), b) === "on") expect(pickFromRollout(at(25), b)).toBe("on");
    }
  });
});

describe("clauses", () => {
  const ctx = { key: "u1", attributes: { country: "IN", plan: "pro", age: 31, version: "2.10.1", groups: ["beta", "staff"], email: "a@acme.io" } };
  it.each([
    [{ attribute: "country", op: "in", values: ["US", "IN"] }, true],
    [{ attribute: "country", op: "not_in", values: ["US", "IN"] }, false],
    [{ attribute: "country", op: "neq", values: ["US"] }, true],
    [{ attribute: "email", op: "ends_with", values: ["@acme.io"] }, true],
    [{ attribute: "email", op: "starts_with", values: ["b"] }, false],
    [{ attribute: "plan", op: "contains", values: ["ro"] }, true],
    [{ attribute: "age", op: "gte", values: [31] }, true],
    [{ attribute: "age", op: "lt", values: ["18"] }, false],
    [{ attribute: "version", op: "semver_gte", values: ["2.9.0"] }, true], // numeric, not lexicographic
    [{ attribute: "version", op: "semver_lt", values: ["2.10.0"] }, false],
    [{ attribute: "groups", op: "in", values: ["beta"] }, true],
    [{ attribute: "groups", op: "not_in", values: ["staff"] }, false],
    [{ attribute: "key", op: "eq", values: ["u1"] }, true],
    [{ attribute: "missing", op: "eq", values: ["x"] }, false],
    [{ attribute: "missing", op: "not_in", values: ["x"] }, true],
    [{ attribute: "plan", op: "gt", values: [3] }, false], // non-numeric never satisfies numeric ops
  ] as const)("%j -> %s", (clause, expected) => {
    expect(clauseMatches(clause as never, ctx)).toBe(expected);
  });
});

describe("evaluate", () => {
  it("serves the off variant when disabled", () => {
    expect(evaluate(boolFlag({ enabled: false, fallthrough: { variant: "on" } }), { key: "u" })).toEqual({ value: false, variant: "off", reason: { kind: "OFF" } });
  });

  it("applies the first matching rule, then falls through", () => {
    const flag = boolFlag({
      rules: [
        { id: "staff", clauses: [{ attribute: "email", op: "ends_with", values: ["@acme.io"] }], serve: { variant: "on" } },
        { id: "india-beta", clauses: [{ attribute: "country", op: "eq", values: ["IN"] }, { attribute: "beta", op: "eq", values: [true] }], serve: { variant: "on" } },
      ],
    });
    expect(evaluate(flag, { key: "1", attributes: { email: "x@acme.io" } }).reason).toEqual({ kind: "RULE_MATCH", ruleIndex: 0, ruleId: "staff" });
    expect(evaluate(flag, { key: "2", attributes: { country: "IN", beta: true } }).reason).toMatchObject({ ruleId: "india-beta" });
    expect(evaluate(flag, { key: "3", attributes: { country: "IN", beta: false } })).toEqual({ value: false, variant: "off", reason: { kind: "FALLTHROUGH" } });
  });

  it("supports multivariate percentage rollouts", () => {
    const flag: FlagConfig = {
      key: "checkout-button", enabled: true, offVariant: "control", rules: [],
      variants: [{ key: "control", value: "blue" }, { key: "green", value: "green" }, { key: "orange", value: "orange" }],
      fallthrough: { rollout: [{ variant: "control", weight: pct(50) }, { variant: "green", weight: pct(25) }, { variant: "orange", weight: pct(25) }] },
    };
    const counts: Record<string, number> = {};
    for (let i = 0; i < 10000; i++) {
      const e = evaluate(flag, { key: `u${i}` });
      counts[e.value as string] = (counts[e.value as string] ?? 0) + 1;
      expect(e.reason).toEqual({ kind: "FALLTHROUGH", inRollout: true });
    }
    expect(counts.blue / 10000).toBeCloseTo(0.5, 1);
    expect(counts.green / 10000).toBeCloseTo(0.25, 1);
  });

  it("reports errors instead of throwing", () => {
    expect(evaluate(boolFlag(), { key: "" }).reason.kind).toBe("ERROR");
    expect(evaluate(boolFlag({ fallthrough: { variant: "ghost" } }), { key: "u" }).reason).toEqual({ kind: "ERROR", error: "fallthrough serves an unknown variant" });
  });
});

describe("validateConfig", () => {
  it("accepts a valid config and lists every problem in an invalid one", () => {
    expect(validateConfig(boolFlag())).toEqual([]);
    const problems = validateConfig({
      variants: [{ key: "on", value: true }],
      offVariant: "nope",
      rules: [{ id: "r", clauses: [], serve: { variant: "on" } }, { id: "r", clauses: [{ attribute: "a", op: "eq", values: [1] }], serve: { variant: "x" } }],
      fallthrough: { rollout: [{ variant: "on", weight: 50000 }] },
    });
    expect(problems).toEqual([
      "offVariant: unknown variant 'nope'",
      "rules[0]: a rule needs at least one clause",
      "rules[1]: duplicate rule id 'r'",
      "rules[1]: unknown variant 'x'",
      "fallthrough: rollout weights must sum to 100000 (100%), got 50000",
    ]);
  });
});
