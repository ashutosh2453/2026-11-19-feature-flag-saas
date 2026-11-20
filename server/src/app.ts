import { existsSync } from "node:fs";
import { timingSafeEqual } from "node:crypto";
import fastifyStatic from "@fastify/static";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { z } from "zod";
import type { Database } from "./db.js";
import { BUCKETS } from "./evaluator.js";
import { ApiError, FlagService, type Principal, type SdkPrincipal } from "./service.js";

const KEY_RE = /^[a-z0-9][a-z0-9-_.]{1,63}$/;

const scalar = z.union([z.string().max(500), z.number(), z.boolean()]);
const clause = z.object({
  attribute: z.string().min(1).max(100),
  op: z.enum(["eq", "neq", "in", "not_in", "contains", "starts_with", "ends_with", "gt", "gte", "lt", "lte", "semver_gte", "semver_lt"]),
  values: z.array(scalar).min(1).max(1000),
});
const serve = z.union([
  z.object({ variant: z.string() }).strict(),
  z.object({ rollout: z.array(z.object({ variant: z.string(), weight: z.number().int().min(0).max(BUCKETS) })).min(1) }).strict(),
]);
const rule = z.object({ id: z.string().min(1).max(64), description: z.string().max(300).optional(), clauses: z.array(clause).max(50), serve });

const FlagIn = z.object({
  key: z.string().regex(KEY_RE, "lowercase letters, digits, '-', '_' or '.'; 2-64 chars"),
  name: z.string().trim().min(1).max(120),
  description: z.string().max(1000).optional(),
  kind: z.enum(["boolean", "multivariate"]),
  variants: z.array(z.object({
    key: z.string().regex(KEY_RE),
    value: z.union([z.string().max(10_000), z.number(), z.boolean(), z.null(), z.array(z.unknown()), z.record(z.string(), z.unknown())]),
  })).max(20).optional(),
});
const FlagPatch = z.object({ name: z.string().trim().min(1).max(120).optional(), description: z.string().max(1000).optional(), archived: z.boolean().optional() }).strict();
const ConfigIn = z.object({
  enabled: z.boolean(), offVariant: z.string(), rules: z.array(rule).max(100), fallthrough: serve, version: z.number().int().min(1),
}).strict();
const Context = z.object({
  key: z.string().min(1).max(256),
  attributes: z.record(z.string(), z.union([scalar, z.array(z.string().max(500)).max(100)])).optional(),
}).strict();

declare module "fastify" {
  interface FastifyRequest { principal?: Principal; sdk?: SdkPrincipal }
}

export interface AppOptions { bootstrapToken?: string; staticDir?: string; logger?: boolean }

export async function buildApp(db: Database, opts: AppOptions = {}) {
  const svc = new FlagService(db);
  const app = Fastify({ logger: opts.logger ?? false, bodyLimit: 512 * 1024 });

  app.setErrorHandler((err: any, _req, reply) => {
    if (err instanceof z.ZodError) return reply.status(422).send({ error: "validation failed", details: err.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    if (err instanceof ApiError) return reply.status(err.status).send({ error: err.message, ...(err.details ? { details: err.details } : {}) });
    if (err.validation || err.statusCode === 400) return reply.status(400).send({ error: err.message });
    if (err.statusCode === 413) return reply.status(413).send({ error: "request body too large" });
    app.log.error(err);
    return reply.status(500).send({ error: "internal server error" });
  });

  const bearer = (req: FastifyRequest) => {
    const h = req.headers.authorization ?? "";
    return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  };

  const requireAdmin = (write: boolean) => async (req: FastifyRequest) => {
    const key = bearer(req);
    const principal = key ? await svc.authenticateAdmin(key) : null;
    if (!principal) throw new ApiError(401, "missing or invalid API key");
    if (write && principal.role !== "admin") throw new ApiError(403, "this API key is read-only");
    req.principal = principal;
  };
  const read = { preHandler: requireAdmin(false) };
  const write = { preHandler: requireAdmin(true) };

  const requireSdk = async (req: FastifyRequest) => {
    const key = String(req.headers["x-sdk-key"] ?? "") || bearer(req);
    const sdk = key ? await svc.authenticateSdk(key) : null;
    if (!sdk) throw new ApiError(401, "missing or invalid SDK key");
    req.sdk = sdk;
  };

  // ---------------------------------------------------------------- public
  app.get("/api/health", async () => ({ status: "ok" }));

  app.post("/api/signup", async (req, reply) => {
    if (opts.bootstrapToken) {
      const given = Buffer.from(String(req.headers["x-bootstrap-token"] ?? ""));
      const expected = Buffer.from(opts.bootstrapToken);
      if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new ApiError(403, "invalid bootstrap token");
    }
    const { name } = z.object({ name: z.string().trim().min(1).max(120) }).parse(req.body);
    reply.status(201);
    return svc.signup(name);
  });

  // ---------------------------------------------------------------- management API
  app.get("/api/flags", read, async (req) => svc.listFlags(req.principal!, (req.query as any)?.archived === "true"));
  app.post("/api/flags", write, async (req, reply) => {
    reply.status(201);
    return svc.createFlag(req.principal!, FlagIn.parse(req.body));
  });
  app.get("/api/flags/:key", read, async (req) => svc.getFlag(req.principal!, (req.params as any).key));
  app.patch("/api/flags/:key", write, async (req) => svc.updateFlag(req.principal!, (req.params as any).key, FlagPatch.parse(req.body)));
  app.put("/api/flags/:key/environments/:env", write, async (req) => {
    const { key, env } = req.params as { key: string; env: string };
    return svc.updateConfig(req.principal!, key, env, ConfigIn.parse(req.body));
  });
  app.get("/api/environments", read, async (req) => svc.listEnvironments(req.principal!));
  app.post("/api/environments/:env/rotate-sdk-key", write, async (req) => svc.rotateSdkKey(req.principal!, (req.params as any).env));
  app.get("/api/audit", read, async (req) => {
    const q = z.object({ limit: z.coerce.number().int().min(1).max(500).default(50), flag: z.string().optional() }).parse(req.query);
    return svc.auditLog(req.principal!, q.limit, q.flag);
  });
  app.get("/api/keys", write, async (req) => svc.listApiKeys(req.principal!));
  app.post("/api/keys", write, async (req, reply) => {
    const body = z.object({ name: z.string().trim().min(1).max(60), role: z.enum(["admin", "viewer"]) }).parse(req.body);
    reply.status(201);
    return svc.createApiKey(req.principal!, body.name, body.role);
  });
  app.delete("/api/keys/:id", write, async (req, reply) => {
    await svc.revokeApiKey(req.principal!, (req.params as any).id);
    reply.status(204);
  });
  // Playground: evaluate a context in any environment with an admin/viewer key.
  app.post("/api/environments/:env/evaluate", read, async (req) => {
    const env = (req.params as any).env;
    const envs = await svc.listEnvironments(req.principal!);
    if (!envs.some((e) => e.key === env)) throw new ApiError(404, `environment '${env}' not found`);
    return svc.evaluateAll(req.principal!.tenantId, env, Context.parse(req.body));
  });

  // ---------------------------------------------------------------- SDK API
  app.post("/sdk/v1/evaluate", { preHandler: requireSdk }, async (req) =>
    svc.evaluateAll(req.sdk!.tenantId, req.sdk!.environmentKey, Context.parse(req.body)));

  app.get("/sdk/v1/flags", { preHandler: requireSdk }, async (req, reply: FastifyReply) => {
    const { flags, etag } = await svc.environmentConfigs(req.sdk!.tenantId, req.sdk!.environmentKey);
    reply.header("etag", etag).header("cache-control", "no-cache");
    if (req.headers["if-none-match"] === etag) return reply.status(304).send();
    return { environment: req.sdk!.environmentKey, flags };
  });

  app.setNotFoundHandler((req, reply) => {
    if (req.url.startsWith("/api") || req.url.startsWith("/sdk") || !opts.staticDir) return reply.status(404).send({ error: "not found" });
    return reply.sendFile("index.html");
  });
  if (opts.staticDir && existsSync(opts.staticDir)) {
    await app.register(fastifyStatic, { root: opts.staticDir });
  }
  return app;
}
