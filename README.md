# Multi-Tenant Feature-Flag SaaS

A self-hostable feature-flag service in the style of LaunchDarkly or Unleash:
- multi-tenant workspaces isolated by **PostgreSQL Row-Level Security**
- targeting rules
- **deterministic, sticky percentage rollouts** with MurmurHash3
- per-environment configurations with optimistic concurrency
- an audit trail
- an SDK API with ETag caching
- a React admin console

> Built on 20 Nov 2026 for the 19 Nov slot of the daily project challenge.

## Problem

Shipping behind flags means "turn it on for staff, then 5% of India, then everyone" without a deploy. A hosted flag service has to get three things right:

- **Correct, stable bucketing.** A user must not flip between variants on every request, and widening a rollout from 10% to 20% must keep the original 10%.
- **Tenant isolation.** One customer can never see or change another customer's flags, even if the application code has a bug.
- **Safe changes.** Two people editing the same flag must not silently overwrite each other, and every change needs an audit trail.

## Solution

```mermaid
flowchart LR
    UI[React console] -->|Bearer admin/viewer key| API
    SDK[Your services / SDKs] -->|X-SDK-Key| API
    API[Fastify + zod] --> SVC[FlagService]
    SVC -->|SET LOCAL ROLE app_user<br/>set_config app.tenant_id| PG[(PostgreSQL<br/>RLS policies)]
    SVC --> EVAL[Evaluator<br/>rules + MurmurHash3 buckets]
```

| Concern | How it's handled |
|---|---|
| Tenant isolation | Every tenant request runs in a transaction that switches to the unprivileged `app_user` role and sets `app.tenant_id`. RLS policies on all tenant tables filter reads and reject cross-tenant writes **inside Postgres**. A test runs a deliberately unfiltered `SELECT` and a cross-tenant `INSERT` to prove it |
| Bucketing | `murmur3(flagKey.salt.userKey) % 100000`. It's checked against the reference MurmurHash3 test vectors, so SDKs in any language bucket identically. Variants own contiguous bucket ranges, so rollouts are sticky as they grow |
| Targeting | Rules are ANDed clauses using `eq, neq, in, not_in, contains, starts_with, ends_with, gt(e), lt(e), semver_gte, semver_lt`. The first matching rule wins, then the default (fallthrough). Array attributes such as `groups` are supported. Semver compares numerically, so 2.10 > 2.9 |
| Explainability | Every evaluation returns a reason: `OFF`, `RULE_MATCH` (rule index and id, rollout or not), `FALLTHROUGH`, or `ERROR`. A malformed config never throws |
| Safe edits | `PUT …/environments/:env` must carry the `version` it edited; stale writes get `409` along with the current config. Configs are validated (known variants, weights summing to 100%, unique rule ids) before saving |
| Auditing | Every change writes `actor, action, flag, environment, before, after` in the same transaction. A plain toggle is recorded as `flag.enabled`/`flag.disabled` |
| Keys | Admin, viewer and SDK keys are random 192-bit tokens. Only SHA-256 hashes are stored; the full key is shown once. Viewer keys are read-only, keys can be revoked, and SDK keys can be rotated per environment |
| SDK delivery | `POST /sdk/v1/evaluate` for server-side evaluation. `GET /sdk/v1/flags` returns configs for local evaluation with an `ETag`, so polling SDKs get `304 Not Modified` until something changes |

## Database design

```
tenants(id, name)
api_keys(id, tenant_id, name, role admin|viewer, key_hash UNIQUE, prefix, revoked_at)          RLS
environments(id, tenant_id, key, name, sdk_key_hash UNIQUE, sdk_key_prefix)  UNIQUE(tenant,key) RLS
flags(id, tenant_id, key, name, description, kind, variants jsonb, archived)  UNIQUE(tenant,key) RLS
flag_configs(flag_id, environment_id, tenant_id, enabled, off_variant, rules jsonb,
             fallthrough jsonb, version, updated_at)  PK(flag, env)                              RLS
audit_log(id, tenant_id, actor, action, flag_key, environment, before jsonb, after jsonb, at)    RLS
```

## Getting started

```bash
npm install
npm run build
npm start                      # http://localhost:3000, embedded Postgres (PGlite), data in memory
PGLITE_DIR=./data npm start    # embedded Postgres persisted to disk
DATABASE_URL=postgres://user:pass@localhost:5432/flags npm start   # external PostgreSQL
```

Open the console and choose **New workspace**. Copy the admin and SDK keys (shown once), then create flags.

Development with hot reload: `npm run dev -w server` and `npm run dev -w web` (port 5173, proxies `/api` and `/sdk`).

Docker:

```bash
docker build -t feature-flags .
docker run -p 3000:3000 -e BOOTSTRAP_TOKEN=change-me feature-flags
```

| Env var | Purpose |
|---|---|
| `DATABASE_URL` | Use an external PostgreSQL server (otherwise embedded PGlite) |
| `PGLITE_DIR` | Persist the embedded database to this directory |
| `BOOTSTRAP_TOKEN` | If set, `POST /api/signup` requires header `x-bootstrap-token` |
| `PORT`, `HOST`, `LOG_LEVEL` | Server settings (`LOG_LEVEL=silent` disables request logs) |

## Using it from a service

```bash
curl -X POST http://localhost:3000/sdk/v1/evaluate \
  -H "X-SDK-Key: ffs_…" -H "content-type: application/json" \
  -d '{"key": "user-42", "attributes": {"email": "dev@acme.io", "country": "IN", "appVersion": "2.10.1"}}'
```

```json
{
  "new-checkout": { "value": true, "variant": "on", "reason": { "kind": "RULE_MATCH", "ruleIndex": 0, "ruleId": "staff" } },
  "button-color": { "value": "green", "variant": "green", "reason": { "kind": "FALLTHROUGH", "inRollout": true } }
}
```

## API

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/signup` | bootstrap token | Create a workspace: returns the admin key and 3 environment SDK keys (development, staging, production) |
| GET/POST | `/api/flags` | viewer / admin | List (`?archived=true`) or create flags (boolean or multivariate) |
| GET/PATCH | `/api/flags/:key` | viewer / admin | Read, rename or archive |
| PUT | `/api/flags/:key/environments/:env` | admin | Replace targeting `{enabled, offVariant, rules, fallthrough, version}` |
| POST | `/api/environments/:env/evaluate` | viewer | Playground evaluation |
| POST | `/api/environments/:env/rotate-sdk-key` | admin | Rotate an SDK key |
| GET | `/api/environments`, `/api/audit?flag=&limit=` | viewer | Environments, audit log |
| GET/POST/DELETE | `/api/keys` | admin | Manage admin and viewer keys |
| POST | `/sdk/v1/evaluate` | SDK key | Evaluate all flags for a context |
| GET | `/sdk/v1/flags` | SDK key | Configs for local evaluation (`ETag` / `If-None-Match`) |

Errors return `{error, details?}` with status `401`, `403`, `404`, `409` (duplicate, stale version or archived) or `422` (validation).

## Tests

```bash
npm test                                          # against embedded PGlite
TEST_DATABASE_URL=postgres://… npm test -w server  # against a real PostgreSQL (CI does both)
```

37 tests:
- **Evaluator:** MurmurHash3 reference vectors, uniform and per-flag-independent buckets, rollout stickiness when increasing percentages, every operator (including arrays, semver and missing attributes), rule order, multivariate distribution, error reasons, config validation.
- **API:** sign-up and bootstrap token, admin/viewer/SDK key separation, revocation, flag lifecycle, optimistic concurrency, validation messages, archiving, audit before/after, evaluation reasons, rollout share, ETag 304s, SDK key rotation.
- **Tenant isolation through the API and directly in Postgres:** an unfiltered query and a cross-tenant insert/update are both blocked by RLS.

The UI was exercised in a browser: workspace login, toggling, building a rule and a 50/50 rollout, saving with versioning, the playground and the audit view.

## Future enhancements

- Streaming updates to SDKs (SSE) instead of polling
- Flag prerequisites, scheduled changes and approval workflows for production
- Segments (reusable audiences) and experiment metrics
- Official SDKs (Node, Python, Go) sharing the evaluator test vectors
- SSO/OIDC for console users on top of API keys

## License

MIT
