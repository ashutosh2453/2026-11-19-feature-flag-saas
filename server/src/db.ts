/**
 * Database access with tenant isolation enforced by PostgreSQL Row-Level Security.
 *
 * Every tenant-scoped request runs in a transaction that switches to the unprivileged
 * `app_user` role and sets `app.tenant_id`. RLS policies then make other tenants' rows
 * invisible and unwritable, even if application code forgets a WHERE clause.
 * Only key lookup and sign-up use the privileged `system` path.
 *
 * Two drivers: PGlite (Postgres compiled to WASM, in-process, for dev and tests) and
 * node-postgres for a real server (DATABASE_URL).
 */

import { PGlite } from "@electric-sql/pglite";
import pg from "pg";

export interface Sql {
  query<T = Record<string, unknown>>(text: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

export interface Database {
  migrate(): Promise<void>;
  tenant<T>(tenantId: string, fn: (q: Sql) => Promise<T>): Promise<T>;
  system<T>(fn: (q: Sql) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export const SCHEMA = `
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
END $$;

CREATE TABLE IF NOT EXISTS tenants (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        text NOT NULL,
  role        text NOT NULL CHECK (role IN ('admin', 'viewer')),
  key_hash    text NOT NULL UNIQUE,
  prefix      text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  revoked_at  timestamptz
);

CREATE TABLE IF NOT EXISTS environments (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  key            text NOT NULL,
  name           text NOT NULL,
  sdk_key_hash   text NOT NULL UNIQUE,
  sdk_key_prefix text NOT NULL,
  UNIQUE (tenant_id, key)
);

CREATE TABLE IF NOT EXISTS flags (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  key          text NOT NULL,
  name         text NOT NULL,
  description  text NOT NULL DEFAULT '',
  kind         text NOT NULL CHECK (kind IN ('boolean', 'multivariate')),
  variants     jsonb NOT NULL,
  archived     boolean NOT NULL DEFAULT false,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, key)
);

CREATE TABLE IF NOT EXISTS flag_configs (
  flag_id         uuid NOT NULL REFERENCES flags(id) ON DELETE CASCADE,
  environment_id  uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  enabled         boolean NOT NULL DEFAULT false,
  off_variant     text NOT NULL,
  rules           jsonb NOT NULL DEFAULT '[]',
  fallthrough     jsonb NOT NULL,
  version         integer NOT NULL DEFAULT 1,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (flag_id, environment_id)
);
CREATE INDEX IF NOT EXISTS idx_flag_configs_env ON flag_configs (environment_id);

CREATE TABLE IF NOT EXISTS audit_log (
  id           bigserial PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  actor        text NOT NULL,
  action       text NOT NULL,
  flag_key     text,
  environment  text,
  before       jsonb,
  after        jsonb,
  at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_at ON audit_log (tenant_id, at DESC);
`;

const TENANT_TABLES = ["api_keys", "environments", "flags", "flag_configs", "audit_log"];

export const POLICIES = TENANT_TABLES.map((t) => `
ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ${t};
CREATE POLICY tenant_isolation ON ${t}
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON ${t} TO app_user;
`).join("\n") + `
GRANT SELECT ON tenants TO app_user;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO app_user;
`;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertTenantId(tenantId: string) {
  if (!UUID_RE.test(tenantId)) throw new Error("invalid tenant id");
}

export class PgliteDatabase implements Database {
  private db: PGlite;
  constructor(dataDir?: string) {
    this.db = new PGlite(dataDir);
  }
  async migrate() {
    await this.db.exec(SCHEMA);
    await this.db.exec(POLICIES);
  }
  async tenant<T>(tenantId: string, fn: (q: Sql) => Promise<T>): Promise<T> {
    assertTenantId(tenantId);
    return this.db.transaction(async (tx) => {
      await tx.query("SET LOCAL ROLE app_user");
      await tx.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      return fn(tx as unknown as Sql);
    });
  }
  system<T>(fn: (q: Sql) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => fn(tx as unknown as Sql));
  }
  async close() {
    await this.db.close();
  }
}

export class PostgresDatabase implements Database {
  private pool: pg.Pool;
  constructor(connectionString: string) {
    this.pool = new pg.Pool({ connectionString, max: 10 });
  }
  async migrate() {
    await this.pool.query(SCHEMA);
    await this.pool.query(POLICIES);
    // The connecting role must be allowed to SET ROLE app_user.
    await this.pool.query("DO $$ BEGIN EXECUTE format('GRANT app_user TO %I', current_user); EXCEPTION WHEN others THEN NULL; END $$;");
  }
  private async tx<T>(setup: (c: pg.PoolClient) => Promise<void>, fn: (q: Sql) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await setup(client);
      const result = await fn(client as unknown as Sql);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }
  async tenant<T>(tenantId: string, fn: (q: Sql) => Promise<T>): Promise<T> {
    assertTenantId(tenantId);
    return this.tx(async (c) => {
      await c.query("SET LOCAL ROLE app_user");
      await c.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
    }, fn);
  }
  system<T>(fn: (q: Sql) => Promise<T>): Promise<T> {
    return this.tx(async () => {}, fn);
  }
  async close() {
    await this.pool.end();
  }
}

export function databaseFromEnv(): Database {
  return process.env.DATABASE_URL ? new PostgresDatabase(process.env.DATABASE_URL) : new PgliteDatabase(process.env.PGLITE_DIR || undefined);
}
