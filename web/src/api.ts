export type Serve = { variant: string } | { rollout: { variant: string; weight: number }[] };
export interface Clause { attribute: string; op: string; values: (string | number | boolean)[] }
export interface Rule { id: string; description?: string; clauses: Clause[]; serve: Serve }
export interface EnvConfig { enabled: boolean; offVariant: string; rules: Rule[]; fallthrough: Serve; version: number; updatedAt: string }
export interface Flag {
  key: string; name: string; description: string; kind: "boolean" | "multivariate";
  variants: { key: string; value: unknown }[]; archived: boolean; createdAt: string;
  environments: Record<string, EnvConfig>;
}
export interface Environment { key: string; name: string; sdkKeyPrefix: string }
export interface AuditEntry { id: number; actor: string; action: string; flagKey: string | null; environment: string | null; before: unknown; after: unknown; at: string }

export const OPS = ["eq", "neq", "in", "not_in", "contains", "starts_with", "ends_with", "gt", "gte", "lt", "lte", "semver_gte", "semver_lt"];

export class ApiError extends Error {
  constructor(public status: number, message: string, public details?: unknown) { super(message); }
}

export function client(key: string) {
  const call = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
    const res = await fetch(path, {
      method,
      headers: { authorization: `Bearer ${key}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (res.status === 204) return undefined as T;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const details = Array.isArray(data.details)
        ? data.details.map((d: any) => (typeof d === "string" ? d : `${d.path}: ${d.message}`)).join("; ")
        : "";
      throw new ApiError(res.status, [data.error || res.statusText, details].filter(Boolean).join(": "), data.details);
    }
    return data as T;
  };
  return {
    flags: () => call<Flag[]>("GET", "/api/flags"),
    flag: (k: string) => call<Flag>("GET", `/api/flags/${encodeURIComponent(k)}`),
    createFlag: (body: unknown) => call<Flag>("POST", "/api/flags", body),
    patchFlag: (k: string, body: unknown) => call<Flag>("PATCH", `/api/flags/${encodeURIComponent(k)}`, body),
    saveConfig: (k: string, env: string, cfg: Omit<EnvConfig, "updatedAt">) =>
      call<Flag>("PUT", `/api/flags/${encodeURIComponent(k)}/environments/${env}`, cfg),
    environments: () => call<Environment[]>("GET", "/api/environments"),
    evaluate: (env: string, ctx: unknown) => call<Record<string, { value: unknown; variant: string | null; reason: any }>>("POST", `/api/environments/${env}/evaluate`, ctx),
    audit: () => call<AuditEntry[]>("GET", "/api/audit?limit=100"),
  };
}

export async function signup(name: string, bootstrapToken: string) {
  const res = await fetch("/api/signup", {
    method: "POST",
    headers: { "content-type": "application/json", ...(bootstrapToken ? { "x-bootstrap-token": bootstrapToken } : {}) },
    body: JSON.stringify({ name }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "sign-up failed");
  return data as { tenant: { id: string; name: string }; adminKey: string; environments: { key: string; sdkKey: string }[] };
}
