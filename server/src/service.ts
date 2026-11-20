import { createHash, randomBytes } from "node:crypto";
import type { Database, Sql } from "./db.js";
import { evaluate, validateConfig, type EvalContext, type FlagConfig, type Rule, type Serve, type Variant } from "./evaluator.js";

export class ApiError extends Error {
  constructor(public status: number, message: string, public details?: unknown) {
    super(message);
  }
}

export type Role = "admin" | "viewer";
export interface Principal { tenantId: string; role: Role; actor: string }
export interface SdkPrincipal { tenantId: string; environmentId: string; environmentKey: string }

export const hashKey = (key: string) => createHash("sha256").update(key).digest("hex");
const newKey = (prefix: string) => `${prefix}_${randomBytes(24).toString("base64url")}`;

export interface EnvConfig {
  enabled: boolean;
  offVariant: string;
  rules: Rule[];
  fallthrough: Serve;
  version: number;
  updatedAt: string;
}

export interface Flag {
  key: string;
  name: string;
  description: string;
  kind: "boolean" | "multivariate";
  variants: Variant[];
  archived: boolean;
  createdAt: string;
  environments: Record<string, EnvConfig>;
}

type Row = Record<string, any>;

const DEFAULT_ENVIRONMENTS = [["development", "Development"], ["staging", "Staging"], ["production", "Production"]] as const;

export class FlagService {
  constructor(private db: Database) {}

  // ------------------------------------------------------------- tenants & keys

  async signup(tenantName: string) {
    return this.db.system(async (q) => {
      const { rows: [tenant] } = await q.query<Row>("INSERT INTO tenants (name) VALUES ($1) RETURNING id, name, created_at", [tenantName]);
      const adminKey = newKey("ffa");
      await q.query("INSERT INTO api_keys (tenant_id, name, role, key_hash, prefix) VALUES ($1, 'owner', 'admin', $2, $3)",
        [tenant.id, hashKey(adminKey), adminKey.slice(0, 10)]);
      const environments: { key: string; name: string; sdkKey: string }[] = [];
      for (const [key, name] of DEFAULT_ENVIRONMENTS) {
        const sdkKey = newKey("ffs");
        await q.query("INSERT INTO environments (tenant_id, key, name, sdk_key_hash, sdk_key_prefix) VALUES ($1, $2, $3, $4, $5)",
          [tenant.id, key, name, hashKey(sdkKey), sdkKey.slice(0, 10)]);
        environments.push({ key, name, sdkKey });
      }
      return { tenant: { id: tenant.id, name: tenant.name }, adminKey, environments };
    });
  }

  async authenticateAdmin(key: string): Promise<Principal | null> {
    const { rows } = await this.db.system((q) =>
      q.query<Row>("SELECT tenant_id, role, name FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL", [hashKey(key)]));
    return rows[0] ? { tenantId: rows[0].tenant_id, role: rows[0].role, actor: rows[0].name } : null;
  }

  async authenticateSdk(key: string): Promise<SdkPrincipal | null> {
    const { rows } = await this.db.system((q) =>
      q.query<Row>("SELECT tenant_id, id, key FROM environments WHERE sdk_key_hash = $1", [hashKey(key)]));
    return rows[0] ? { tenantId: rows[0].tenant_id, environmentId: rows[0].id, environmentKey: rows[0].key } : null;
  }

  createApiKey(p: Principal, name: string, role: Role) {
    return this.db.tenant(p.tenantId, async (q) => {
      const key = newKey("ffa");
      const { rows: [row] } = await q.query<Row>(
        "INSERT INTO api_keys (tenant_id, name, role, key_hash, prefix) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, role, prefix, created_at",
        [p.tenantId, name, role, hashKey(key), key.slice(0, 10)]);
      await audit(q, p, "api_key.created", null, null, null, { name, role });
      return { ...row, key };
    });
  }

  listApiKeys(p: Principal) {
    return this.db.tenant(p.tenantId, async (q) =>
      (await q.query<Row>("SELECT id, name, role, prefix, created_at, revoked_at FROM api_keys ORDER BY created_at")).rows);
  }

  revokeApiKey(p: Principal, id: string) {
    return this.db.tenant(p.tenantId, async (q) => {
      const { rows } = await q.query<Row>("UPDATE api_keys SET revoked_at = now() WHERE id::text = $1 AND revoked_at IS NULL RETURNING name", [id]);
      if (!rows.length) throw new ApiError(404, "api key not found");
      await audit(q, p, "api_key.revoked", null, null, null, { name: rows[0].name });
    });
  }

  listEnvironments(p: Principal) {
    return this.db.tenant(p.tenantId, async (q) =>
      (await q.query<Row>("SELECT key, name, sdk_key_prefix FROM environments ORDER BY CASE key WHEN 'development' THEN 0 WHEN 'staging' THEN 1 WHEN 'production' THEN 2 ELSE 3 END, key")).rows
        .map((r) => ({ key: r.key, name: r.name, sdkKeyPrefix: r.sdk_key_prefix })));
  }

  rotateSdkKey(p: Principal, envKey: string) {
    return this.db.tenant(p.tenantId, async (q) => {
      const sdkKey = newKey("ffs");
      const { rows } = await q.query<Row>("UPDATE environments SET sdk_key_hash = $1, sdk_key_prefix = $2 WHERE key = $3 RETURNING key",
        [hashKey(sdkKey), sdkKey.slice(0, 10), envKey]);
      if (!rows.length) throw new ApiError(404, `environment '${envKey}' not found`);
      await audit(q, p, "sdk_key.rotated", null, envKey, null, null);
      return { environment: envKey, sdkKey };
    });
  }

  // ------------------------------------------------------------- flags

  createFlag(p: Principal, input: { key: string; name: string; description?: string; kind: "boolean" | "multivariate"; variants?: Variant[] }) {
    const variants = input.kind === "boolean" ? [{ key: "on", value: true }, { key: "off", value: false }] : input.variants ?? [];
    if (input.kind === "multivariate") {
      if (variants.length < 2) throw new ApiError(422, "multivariate flags need at least two variants");
      if (new Set(variants.map((v) => v.key)).size !== variants.length) throw new ApiError(422, "variant keys must be unique");
    }
    const off = input.kind === "boolean" ? "off" : variants[0].key;
    return this.db.tenant(p.tenantId, async (q) => {
      const existing = await q.query("SELECT 1 FROM flags WHERE key = $1", [input.key]);
      if (existing.rows.length) throw new ApiError(409, `flag '${input.key}' already exists`);
      const { rows: [flag] } = await q.query<Row>(
        "INSERT INTO flags (tenant_id, key, name, description, kind, variants) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        [p.tenantId, input.key, input.name, input.description ?? "", input.kind, JSON.stringify(variants)]);
      await q.query(
        `INSERT INTO flag_configs (flag_id, environment_id, tenant_id, enabled, off_variant, fallthrough)
         SELECT $1, e.id, $2, false, $3, $4 FROM environments e`,
        [flag.id, p.tenantId, off, JSON.stringify({ variant: off })]);
      await audit(q, p, "flag.created", input.key, null, null, { ...input, variants });
      return this.loadFlag(q, input.key);
    });
  }

  listFlags(p: Principal, includeArchived = false) {
    return this.db.tenant(p.tenantId, async (q) => {
      const { rows } = await q.query<Row>(`SELECT key FROM flags ${includeArchived ? "" : "WHERE NOT archived"} ORDER BY created_at, key`);
      const out: Flag[] = [];
      for (const r of rows) out.push((await this.loadFlag(q, r.key))!);
      return out;
    });
  }

  getFlag(p: Principal, key: string) {
    return this.db.tenant(p.tenantId, async (q) => {
      const flag = await this.loadFlag(q, key);
      if (!flag) throw new ApiError(404, `flag '${key}' not found`);
      return flag;
    });
  }

  updateFlag(p: Principal, key: string, patch: { name?: string; description?: string; archived?: boolean }) {
    return this.db.tenant(p.tenantId, async (q) => {
      const before = await this.loadFlag(q, key);
      if (!before) throw new ApiError(404, `flag '${key}' not found`);
      await q.query("UPDATE flags SET name = COALESCE($2, name), description = COALESCE($3, description), archived = COALESCE($4, archived) WHERE key = $1",
        [key, patch.name ?? null, patch.description ?? null, patch.archived ?? null]);
      const after = (await this.loadFlag(q, key))!;
      await audit(q, p, patch.archived === true ? "flag.archived" : "flag.updated", key, null,
        { name: before.name, description: before.description, archived: before.archived },
        { name: after.name, description: after.description, archived: after.archived });
      return after;
    });
  }

  /** Replace one environment's targeting. Optimistic concurrency: the caller must send the version it edited. */
  updateConfig(p: Principal, key: string, envKey: string, input: Omit<EnvConfig, "updatedAt">) {
    return this.db.tenant(p.tenantId, async (q) => {
      const flag = await this.loadFlag(q, key);
      if (!flag) throw new ApiError(404, `flag '${key}' not found`);
      const current = flag.environments[envKey];
      if (!current) throw new ApiError(404, `environment '${envKey}' not found`);
      if (flag.archived) throw new ApiError(409, "archived flags cannot be changed");
      if (input.version !== current.version) {
        throw new ApiError(409, `version conflict: you edited version ${input.version}, current is ${current.version}`, { current });
      }
      const problems = validateConfig({ variants: flag.variants, offVariant: input.offVariant, rules: input.rules, fallthrough: input.fallthrough });
      if (problems.length) throw new ApiError(422, "invalid flag configuration", problems);
      await q.query(
        `UPDATE flag_configs c SET enabled = $3, off_variant = $4, rules = $5, fallthrough = $6, version = version + 1, updated_at = now()
         FROM flags f, environments e WHERE c.flag_id = f.id AND c.environment_id = e.id AND f.key = $1 AND e.key = $2`,
        [key, envKey, input.enabled, input.offVariant, JSON.stringify(input.rules), JSON.stringify(input.fallthrough)]);
      const updated = (await this.loadFlag(q, key))!;
      const { version: _v, updatedAt: _u, ...beforeCfg } = current;
      const { version: _v2, updatedAt: _u2, ...afterCfg } = updated.environments[envKey];
      const action = beforeCfg.enabled !== afterCfg.enabled && JSON.stringify({ ...beforeCfg, enabled: afterCfg.enabled }) === JSON.stringify(afterCfg)
        ? (afterCfg.enabled ? "flag.enabled" : "flag.disabled") : "flag.targeting_updated";
      await audit(q, p, action, key, envKey, beforeCfg, afterCfg);
      return updated;
    });
  }

  auditLog(p: Principal, limit = 50, flagKey?: string) {
    return this.db.tenant(p.tenantId, async (q) =>
      (await q.query<Row>(
        `SELECT id, actor, action, flag_key, environment, before, after, at FROM audit_log
         WHERE ($1::text IS NULL OR flag_key = $1) ORDER BY id DESC LIMIT $2`, [flagKey ?? null, limit])).rows
        .map((r) => ({ id: Number(r.id), actor: r.actor, action: r.action, flagKey: r.flag_key, environment: r.environment, before: r.before, after: r.after, at: iso(r.at) })));
  }

  // ------------------------------------------------------------- evaluation

  /** Configs for one environment, as SDKs consume them for local evaluation. */
  environmentConfigs(tenantId: string, environmentKey: string) {
    return this.db.tenant(tenantId, async (q) => {
      const { rows } = await q.query<Row>(
        `SELECT f.key, f.variants, f.archived, c.enabled, c.off_variant, c.rules, c.fallthrough, c.version
         FROM flag_configs c JOIN flags f ON f.id = c.flag_id JOIN environments e ON e.id = c.environment_id
         WHERE e.key = $1 AND NOT f.archived ORDER BY f.key`, [environmentKey]);
      const flags: FlagConfig[] = rows.map((r) => ({
        key: r.key, variants: r.variants, enabled: r.enabled, offVariant: r.off_variant, rules: r.rules, fallthrough: r.fallthrough,
      }));
      const etag = `"${createHash("sha1").update(rows.map((r) => `${r.key}:${r.version}`).join("|")).digest("hex").slice(0, 20)}"`;
      return { flags, etag };
    });
  }

  async evaluateAll(tenantId: string, environmentKey: string, ctx: EvalContext) {
    const { flags } = await this.environmentConfigs(tenantId, environmentKey);
    return Object.fromEntries(flags.map((f) => [f.key, evaluate(f, ctx)]));
  }

  // ------------------------------------------------------------- helpers

  private async loadFlag(q: Sql, key: string): Promise<Flag | null> {
    const { rows } = await q.query<Row>(
      `SELECT f.key, f.name, f.description, f.kind, f.variants, f.archived, f.created_at,
              e.key AS env_key, c.enabled, c.off_variant, c.rules, c.fallthrough, c.version, c.updated_at
       FROM flags f JOIN flag_configs c ON c.flag_id = f.id JOIN environments e ON e.id = c.environment_id
       WHERE f.key = $1`, [key]);
    if (!rows.length) return null;
    const f = rows[0];
    return {
      key: f.key, name: f.name, description: f.description, kind: f.kind, variants: f.variants, archived: f.archived, createdAt: iso(f.created_at),
      environments: Object.fromEntries(rows.map((r) => [r.env_key, {
        enabled: r.enabled, offVariant: r.off_variant, rules: r.rules, fallthrough: r.fallthrough, version: r.version, updatedAt: iso(r.updated_at),
      }])),
    };
  }
}

function iso(v: unknown): string {
  return v instanceof Date ? v.toISOString() : String(v);
}

async function audit(q: Sql, p: Principal, action: string, flagKey: string | null, env: string | null, before: unknown, after: unknown) {
  await q.query("INSERT INTO audit_log (tenant_id, actor, action, flag_key, environment, before, after) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    [p.tenantId, p.actor, action, flagKey, env, before === null ? null : JSON.stringify(before), after === null ? null : JSON.stringify(after)]);
}
