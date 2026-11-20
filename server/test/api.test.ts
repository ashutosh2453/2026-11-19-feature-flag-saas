import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { PgliteDatabase, PostgresDatabase, type Database } from "../src/db.js";

// Runs against real PostgreSQL when TEST_DATABASE_URL is set (CI), otherwise in-process PGlite.
const db: Database = process.env.TEST_DATABASE_URL ? new PostgresDatabase(process.env.TEST_DATABASE_URL) : new PgliteDatabase();
let app: Awaited<ReturnType<typeof buildApp>>;
let acme: { adminKey: string; tenant: { id: string }; environments: { key: string; sdkKey: string }[] };
let globex: typeof acme;

const call = async (method: string, url: string, key?: string, body?: unknown, headers: Record<string, string> = {}) => {
  const res = await app.inject({ method: method as any, url, payload: body as any, headers: { ...(key ? { authorization: `Bearer ${key}` } : {}), ...headers } });
  return { status: res.statusCode, body: res.body ? safeJson(res.body) : null, headers: res.headers };
};
const safeJson = (s: string) => { try { return JSON.parse(s); } catch { return s; } };
const sdk = (t: typeof acme, env: string) => t.environments.find((e) => e.key === env)!.sdkKey;

beforeAll(async () => {
  await db.migrate();
  app = await buildApp(db, { bootstrapToken: "boot" });
  acme = (await call("POST", "/api/signup", undefined, { name: "Acme" }, { "x-bootstrap-token": "boot" })).body;
  globex = (await call("POST", "/api/signup", undefined, { name: "Globex" }, { "x-bootstrap-token": "boot" })).body;
});
afterAll(async () => { await app.close(); await db.close(); });

describe("signup and auth", () => {
  it("creates a tenant with an admin key and three environments", () => {
    expect(acme.adminKey).toMatch(/^ffa_/);
    expect(acme.environments.map((e) => e.key)).toEqual(["development", "staging", "production"]);
  });

  it("requires the bootstrap token and valid keys", async () => {
    expect((await call("POST", "/api/signup", undefined, { name: "X" })).status).toBe(403);
    expect((await call("GET", "/api/flags")).status).toBe(401);
    expect((await call("GET", "/api/flags", "ffa_wrong")).status).toBe(401);
    expect((await call("GET", "/api/flags", sdk(acme, "production"))).status).toBe(401); // SDK keys can't manage
    expect((await call("POST", "/sdk/v1/evaluate", acme.adminKey, { key: "u" })).status).toBe(401); // admin keys aren't SDK keys
  });

  it("enforces read-only viewer keys and revocation", async () => {
    const viewer = (await call("POST", "/api/keys", acme.adminKey, { name: "dashboard", role: "viewer" })).body;
    expect(viewer.key).toMatch(/^ffa_/);
    expect((await call("GET", "/api/flags", viewer.key)).status).toBe(200);
    expect((await call("POST", "/api/flags", viewer.key, { key: "x1", name: "X", kind: "boolean" })).status).toBe(403);
    expect((await call("DELETE", `/api/keys/${viewer.id}`, acme.adminKey)).status).toBe(204);
    expect((await call("GET", "/api/flags", viewer.key)).status).toBe(401);
  });
});

describe("flags lifecycle", () => {
  it("creates boolean and multivariate flags with a config per environment", async () => {
    const res = await call("POST", "/api/flags", acme.adminKey, { key: "new-checkout", name: "New checkout", kind: "boolean" });
    expect(res.status).toBe(201);
    expect(Object.keys(res.body.environments)).toEqual(expect.arrayContaining(["development", "staging", "production"]));
    expect(res.body.environments.production).toMatchObject({ enabled: false, offVariant: "off", version: 1 });
    const mv = await call("POST", "/api/flags", acme.adminKey, {
      key: "button-color", name: "Button colour", kind: "multivariate",
      variants: [{ key: "blue", value: "#00f" }, { key: "green", value: "#0a0" }],
    });
    expect(mv.status).toBe(201);
    expect((await call("POST", "/api/flags", acme.adminKey, { key: "new-checkout", name: "dup", kind: "boolean" })).status).toBe(409);
    expect((await call("POST", "/api/flags", acme.adminKey, { key: "Bad Key!", name: "x", kind: "boolean" })).status).toBe(422);
    expect((await call("POST", "/api/flags", acme.adminKey, { key: "solo", name: "x", kind: "multivariate", variants: [{ key: "a", value: 1 }] })).status).toBe(422);
  });

  it("updates targeting with validation and optimistic concurrency", async () => {
    const config = {
      enabled: true, offVariant: "off", version: 1,
      rules: [{ id: "staff", clauses: [{ attribute: "email", op: "ends_with", values: ["@acme.io"] }], serve: { variant: "on" } }],
      fallthrough: { rollout: [{ variant: "on", weight: 20000 }, { variant: "off", weight: 80000 }] },
    };
    const ok = await call("PUT", "/api/flags/new-checkout/environments/production", acme.adminKey, config);
    expect(ok.status).toBe(200);
    expect(ok.body.environments.production).toMatchObject({ enabled: true, version: 2 });
    expect(ok.body.environments.development.enabled).toBe(false); // other environments untouched

    const stale = await call("PUT", "/api/flags/new-checkout/environments/production", acme.adminKey, config);
    expect(stale.status).toBe(409);
    expect(stale.body.details.current.version).toBe(2);

    const bad = await call("PUT", "/api/flags/new-checkout/environments/production", acme.adminKey,
      { ...config, version: 2, fallthrough: { rollout: [{ variant: "on", weight: 50000 }] } });
    expect(bad.status).toBe(422);
    expect(bad.body.details).toEqual(["fallthrough: rollout weights must sum to 100000 (100%), got 50000"]);
    expect((await call("PUT", "/api/flags/nope/environments/production", acme.adminKey, config)).status).toBe(404);
    expect((await call("PUT", "/api/flags/new-checkout/environments/moon", acme.adminKey, { ...config, version: 2 })).status).toBe(404);
  });

  it("archives flags and blocks further edits", async () => {
    await call("POST", "/api/flags", acme.adminKey, { key: "old-banner", name: "Old banner", kind: "boolean" });
    expect((await call("PATCH", "/api/flags/old-banner", acme.adminKey, { archived: true })).body.archived).toBe(true);
    expect((await call("GET", "/api/flags", acme.adminKey)).body.map((f: any) => f.key)).not.toContain("old-banner");
    expect((await call("GET", "/api/flags?archived=true", acme.adminKey)).body.map((f: any) => f.key)).toContain("old-banner");
    const res = await call("PUT", "/api/flags/old-banner/environments/production", acme.adminKey,
      { enabled: true, offVariant: "off", rules: [], fallthrough: { variant: "on" }, version: 1 });
    expect(res.status).toBe(409);
  });

  it("records an audit trail with before/after", async () => {
    const log = (await call("GET", "/api/audit?flag=new-checkout", acme.adminKey)).body;
    expect(log.map((e: any) => e.action)).toEqual(["flag.targeting_updated", "flag.created"]);
    expect(log[0]).toMatchObject({ actor: "owner", environment: "production", before: { enabled: false }, after: { enabled: true } });
  });
});

describe("SDK evaluation", () => {
  it("evaluates every flag for a context with reasons", async () => {
    const res = await call("POST", "/sdk/v1/evaluate", undefined, { key: "u-1", attributes: { email: "dev@acme.io" } }, { "x-sdk-key": sdk(acme, "production") });
    expect(res.status).toBe(200);
    expect(res.body["new-checkout"]).toEqual({ value: true, variant: "on", reason: { kind: "RULE_MATCH", ruleIndex: 0, ruleId: "staff" } });
    expect(res.body["button-color"]).toEqual({ value: "#00f", variant: "blue", reason: { kind: "OFF" } });
    expect(res.body["old-banner"]).toBeUndefined(); // archived flags are not served
    const dev = await call("POST", "/sdk/v1/evaluate", undefined, { key: "u-1", attributes: { email: "dev@acme.io" } }, { "x-sdk-key": sdk(acme, "development") });
    expect(dev.body["new-checkout"].reason.kind).toBe("OFF");
  });

  it("serves roughly the configured rollout percentage", async () => {
    let on = 0;
    for (let i = 0; i < 400; i++) {
      const r = await call("POST", "/sdk/v1/evaluate", undefined, { key: `user-${i}` }, { "x-sdk-key": sdk(acme, "production") });
      if (r.body["new-checkout"].value === true) on++;
    }
    expect(on / 400).toBeGreaterThan(0.13);
    expect(on / 400).toBeLessThan(0.27);
  });

  it("serves configs for local evaluation with ETag caching", async () => {
    const first = await call("GET", "/sdk/v1/flags", undefined, undefined, { "x-sdk-key": sdk(acme, "production") });
    expect(first.body.flags.map((f: any) => f.key)).toEqual(["button-color", "new-checkout"]);
    const etag = String(first.headers.etag);
    expect((await call("GET", "/sdk/v1/flags", undefined, undefined, { "x-sdk-key": sdk(acme, "production"), "if-none-match": etag })).status).toBe(304);
    await call("PATCH", "/api/flags/button-color", acme.adminKey, { name: "Button colour v2" }); // name change doesn't affect configs
    const cfg = (await call("GET", "/api/flags/button-color", acme.adminKey)).body.environments.production;
    await call("PUT", "/api/flags/button-color/environments/production", acme.adminKey, { ...cfg, enabled: true, version: cfg.version, updatedAt: undefined });
    expect((await call("GET", "/sdk/v1/flags", undefined, undefined, { "x-sdk-key": sdk(acme, "production"), "if-none-match": etag })).status).toBe(200);
  });

  it("rejects malformed contexts and rotated keys", async () => {
    expect((await call("POST", "/sdk/v1/evaluate", undefined, { attributes: {} }, { "x-sdk-key": sdk(acme, "production") })).status).toBe(422);
    const old = sdk(acme, "staging");
    const rotated = (await call("POST", "/api/environments/staging/rotate-sdk-key", acme.adminKey)).body;
    expect((await call("POST", "/sdk/v1/evaluate", undefined, { key: "u" }, { "x-sdk-key": old })).status).toBe(401);
    expect((await call("POST", "/sdk/v1/evaluate", undefined, { key: "u" }, { "x-sdk-key": rotated.sdkKey })).status).toBe(200);
  });
});

describe("tenant isolation", () => {
  it("never exposes another tenant's flags through the API", async () => {
    await call("POST", "/api/flags", globex.adminKey, { key: "new-checkout", name: "Globex checkout", kind: "boolean" });
    expect((await call("GET", "/api/flags", globex.adminKey)).body.map((f: any) => f.name)).toEqual(["Globex checkout"]);
    expect((await call("GET", "/api/flags/button-color", globex.adminKey)).status).toBe(404);
    const ev = await call("POST", "/sdk/v1/evaluate", undefined, { key: "u", attributes: { email: "x@acme.io" } }, { "x-sdk-key": sdk(globex, "production") });
    expect(Object.keys(ev.body)).toEqual(["new-checkout"]);
    expect(ev.body["new-checkout"].reason.kind).toBe("OFF");
    expect((await call("GET", "/api/audit", globex.adminKey)).body.every((e: any) => e.flagKey !== "button-color")).toBe(true);
  });

  it("is enforced by Postgres row-level security, not just WHERE clauses", async () => {
    // A deliberately unfiltered query run in Globex's context still sees only Globex rows.
    const keys = await db.tenant(globex.tenant.id, async (q) => (await q.query<{ key: string }>("SELECT key FROM flags")).rows.map((r) => r.key));
    expect(keys).toEqual(["new-checkout"]);
    // Writing a row for another tenant is rejected by the database itself.
    await expect(db.tenant(globex.tenant.id, (q) => q.query(
      "INSERT INTO flags (tenant_id, key, name, kind, variants) VALUES ($1, 'sneaky', 'x', 'boolean', '[]')", [acme.tenant.id]))).rejects.toThrow(/row-level security/);
    const updated = await db.tenant(globex.tenant.id, async (q) => (await q.query("UPDATE flags SET name = 'pwned' WHERE key = 'button-color' RETURNING key")).rows);
    expect(updated).toEqual([]);
    await expect(db.tenant("not-a-uuid", async () => 1)).rejects.toThrow("invalid tenant id");
  });
});
