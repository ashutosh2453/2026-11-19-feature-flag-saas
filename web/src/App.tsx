import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, client, OPS, signup, type AuditEntry, type EnvConfig, type Environment, type Flag, type Rule, type Serve } from "./api";

type Api = ReturnType<typeof client>;
const STORAGE_KEY = "ff-admin-key";
const pct = (w: number) => Math.round(w / 100) / 10;

export default function App() {
  const [key, setKey] = useState(() => sessionStorage.getItem(STORAGE_KEY) ?? "");
  const api = useMemo(() => (key ? client(key) : null), [key]);
  const logout = () => { sessionStorage.removeItem(STORAGE_KEY); setKey(""); };
  if (!api) return <Login onKey={(k) => { sessionStorage.setItem(STORAGE_KEY, k); setKey(k); }} />;
  return <Console api={api} onLogout={logout} />;
}

function Login({ onKey }: { onKey: (k: string) => void }) {
  const [key, setKey] = useState("");
  const [name, setName] = useState("");
  const [token, setToken] = useState("");
  const [created, setCreated] = useState<Awaited<ReturnType<typeof signup>> | null>(null);
  const [error, setError] = useState("");
  return (
    <div className="center">
      <h1>Feature flags</h1>
      {created ? (
        <section className="card">
          <h2>Workspace "{created.tenant.name}" created</h2>
          <p className="warn">Copy these keys now. They are stored hashed and won't be shown again.</p>
          <label>Admin API key<input readOnly value={created.adminKey} onFocus={(e) => e.target.select()} /></label>
          {created.environments.map((e) => (
            <label key={e.key}>{e.key} SDK key<input readOnly value={e.sdkKey} onFocus={(ev) => ev.target.select()} /></label>
          ))}
          <button className="primary" onClick={() => onKey(created.adminKey)}>Continue to console</button>
        </section>
      ) : (
        <div className="grid2">
          <section className="card">
            <h2>Sign in</h2>
            <label>Admin or viewer API key<input value={key} onChange={(e) => setKey(e.target.value.trim())} placeholder="ffa_…" /></label>
            <button className="primary" disabled={!key} onClick={() => onKey(key)}>Open console</button>
          </section>
          <section className="card">
            <h2>New workspace</h2>
            <label>Organisation name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
            <label>Bootstrap token (if the server requires one)<input value={token} onChange={(e) => setToken(e.target.value)} /></label>
            <button disabled={!name.trim()} onClick={() => signup(name, token).then(setCreated).catch((e) => setError(e.message))}>Create workspace</button>
          </section>
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

type Tab = "flags" | "playground" | "audit";

function Console({ api, onLogout }: { api: Api; onLogout: () => void }) {
  const [envs, setEnvs] = useState<Environment[]>([]);
  const [env, setEnv] = useState("production");
  const [tab, setTab] = useState<Tab>("flags");
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState("");
  const fail = useCallback((e: unknown) => {
    if (e instanceof ApiError && e.status === 401) onLogout();
    setError(e instanceof Error ? e.message : String(e));
  }, [onLogout]);

  useEffect(() => { api.environments().then(setEnvs).catch(fail); }, [api, fail]);

  return (
    <div className="shell">
      <header className="top">
        <h1>Feature flags</h1>
        <nav>
          {(["flags", "playground", "audit"] as Tab[]).map((t) => (
            <button key={t} className={tab === t ? "tab on" : "tab"} onClick={() => { setTab(t); setSelected(null); }}>{t}</button>
          ))}
        </nav>
        <div className="row">
          <select aria-label="Environment" value={env} onChange={(e) => setEnv(e.target.value)}>
            {envs.map((e) => <option key={e.key} value={e.key}>{e.name}</option>)}
          </select>
          <button onClick={onLogout}>Sign out</button>
        </div>
      </header>
      {error && <div className="error" role="alert" onClick={() => setError("")}>{error}</div>}
      {tab === "flags" && !selected && <FlagList api={api} env={env} onOpen={setSelected} onError={fail} />}
      {tab === "flags" && selected && <FlagEditor api={api} env={env} flagKey={selected} onBack={() => setSelected(null)} onError={fail} />}
      {tab === "playground" && <Playground api={api} env={env} onError={fail} />}
      {tab === "audit" && <Audit api={api} onError={fail} />}
    </div>
  );
}

function summary(cfg: EnvConfig): string {
  if (!cfg.enabled) return `off → serves "${cfg.offVariant}"`;
  const fall = "variant" in cfg.fallthrough ? `"${cfg.fallthrough.variant}"` : cfg.fallthrough.rollout.map((r) => `${r.variant} ${pct(r.weight)}%`).join(" / ");
  return `${cfg.rules.length} rule${cfg.rules.length === 1 ? "" : "s"}, default ${fall}`;
}

function FlagList({ api, env, onOpen, onError }: { api: Api; env: string; onOpen: (k: string) => void; onError: (e: unknown) => void }) {
  const [flags, setFlags] = useState<Flag[]>([]);
  const [form, setForm] = useState({ key: "", name: "", kind: "boolean", variants: "control, treatment" });
  const load = useCallback(() => api.flags().then(setFlags).catch(onError), [api, onError]);
  useEffect(() => { load(); }, [load]);

  async function toggle(f: Flag) {
    const cfg = f.environments[env];
    const { updatedAt: _, ...rest } = cfg;
    try { await api.saveConfig(f.key, env, { ...rest, enabled: !cfg.enabled }); load(); } catch (e) { onError(e); }
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    const variants = form.kind === "multivariate" ? form.variants.split(",").map((v) => v.trim()).filter(Boolean).map((v) => ({ key: v, value: v })) : undefined;
    try {
      await api.createFlag({ key: form.key, name: form.name || form.key, kind: form.kind, variants });
      setForm({ ...form, key: "", name: "" });
      load();
    } catch (err) { onError(err); }
  }

  return (
    <div className="stack">
      <section className="card">
        <table>
          <thead><tr><th>Flag</th><th>Kind</th><th>{env}</th><th>Targeting</th></tr></thead>
          <tbody>
            {flags.map((f) => {
              const cfg = f.environments[env];
              return (
                <tr key={f.key}>
                  <td><button className="link" onClick={() => onOpen(f.key)}>{f.name}</button><div className="muted small mono">{f.key}</div></td>
                  <td>{f.kind}</td>
                  <td>{cfg && <label className="switch"><input type="checkbox" checked={cfg.enabled} onChange={() => toggle(f)} aria-label={`Toggle ${f.key} in ${env}`} /><span /></label>}</td>
                  <td className="muted small">{cfg && summary(cfg)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!flags.length && <p className="muted">No flags yet.</p>}
      </section>
      <section className="card">
        <h2>New flag</h2>
        <form className="row" onSubmit={create}>
          <input required placeholder="key (e.g. new-checkout)" value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} />
          <input placeholder="Display name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
            <option value="boolean">boolean</option><option value="multivariate">multivariate</option>
          </select>
          {form.kind === "multivariate" && <input placeholder="variants, comma separated" value={form.variants} onChange={(e) => setForm({ ...form, variants: e.target.value })} />}
          <button className="primary">Create</button>
        </form>
      </section>
    </div>
  );
}

function ServeEditor({ value, variants, onChange }: { value: Serve; variants: string[]; onChange: (s: Serve) => void }) {
  const mode = "variant" in value ? "variant" : "rollout";
  const weights = "rollout" in value ? value.rollout : variants.map((v, i) => ({ variant: v, weight: i === 0 ? 100000 : 0 }));
  const total = weights.reduce((s, w) => s + w.weight, 0);
  return (
    <div className="serve">
      <select value={mode} onChange={(e) => onChange(e.target.value === "variant" ? { variant: variants[0] } : { rollout: variants.map((v, i) => ({ variant: v, weight: i === 0 ? 100000 : 0 })) })}>
        <option value="variant">serve</option><option value="rollout">percentage rollout</option>
      </select>
      {"variant" in value ? (
        <select value={value.variant} onChange={(e) => onChange({ variant: e.target.value })}>{variants.map((v) => <option key={v}>{v}</option>)}</select>
      ) : (
        <span className="row">
          {weights.map((w, i) => (
            <label key={w.variant} className="inline">{w.variant}
              <input type="number" min={0} max={100} step={0.1} value={pct(w.weight)}
                onChange={(e) => onChange({ rollout: weights.map((x, j) => (j === i ? { ...x, weight: Math.round(Number(e.target.value) * 1000) } : x)) })} />%
            </label>
          ))}
          <span className={total === 100000 ? "muted small" : "error-text small"}>total {pct(total)}%</span>
        </span>
      )}
    </div>
  );
}

function FlagEditor({ api, env, flagKey, onBack, onError }: { api: Api; env: string; flagKey: string; onBack: () => void; onError: (e: unknown) => void }) {
  const [flag, setFlag] = useState<Flag | null>(null);
  const [draft, setDraft] = useState<EnvConfig | null>(null);
  const [saved, setSaved] = useState("");
  const load = useCallback(() => api.flag(flagKey).then((f) => { setFlag(f); setDraft(f.environments[env]); }).catch(onError), [api, flagKey, env, onError]);
  useEffect(() => { load(); }, [load]);
  if (!flag || !draft) return <p className="muted">Loading…</p>;
  const variants = flag.variants.map((v) => v.key);
  const setRule = (i: number, r: Rule) => setDraft({ ...draft, rules: draft.rules.map((x, j) => (j === i ? r : x)) });

  async function save() {
    const { updatedAt: _, ...cfg } = draft!;
    try {
      const f = await api.saveConfig(flagKey, env, cfg);
      setFlag(f); setDraft(f.environments[env]); setSaved(`Saved version ${f.environments[env].version}`);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setSaved("Someone else changed this flag. Reload to see their version.");
      onError(e);
    }
  }

  return (
    <div className="stack">
      <div className="row between">
        <button className="link" onClick={onBack}>← All flags</button>
        <button onClick={() => api.patchFlag(flagKey, { archived: !flag.archived }).then(load).catch(onError)}>{flag.archived ? "Unarchive" : "Archive"}</button>
      </div>
      <h2>{flag.name} <span className="muted mono small">{flag.key} · {env} · v{draft.version}</span></h2>
      <section className="card stack">
        <label className="row"><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} /> Targeting enabled in {env}</label>
        <div className="row">When off, serve
          <select value={draft.offVariant} onChange={(e) => setDraft({ ...draft, offVariant: e.target.value })}>{variants.map((v) => <option key={v}>{v}</option>)}</select>
        </div>
        <h3>Rules <span className="muted small">(first match wins)</span></h3>
        {draft.rules.map((r, i) => (
          <div key={i} className="rule">
            <div className="row between"><strong>Rule {i + 1}</strong><button onClick={() => setDraft({ ...draft, rules: draft.rules.filter((_, j) => j !== i) })}>Remove</button></div>
            {r.clauses.map((c, ci) => (
              <div key={ci} className="row">
                <span className="muted">{ci === 0 ? "If" : "and"}</span>
                <input aria-label="Attribute" value={c.attribute} onChange={(e) => setRule(i, { ...r, clauses: r.clauses.map((x, k) => (k === ci ? { ...x, attribute: e.target.value } : x)) })} />
                <select aria-label="Operator" value={c.op} onChange={(e) => setRule(i, { ...r, clauses: r.clauses.map((x, k) => (k === ci ? { ...x, op: e.target.value } : x)) })}>{OPS.map((o) => <option key={o}>{o}</option>)}</select>
                <input aria-label="Values" value={c.values.join(", ")} placeholder="comma-separated values"
                  onChange={(e) => setRule(i, { ...r, clauses: r.clauses.map((x, k) => (k === ci ? { ...x, values: e.target.value.split(",").map((v) => v.trim()).filter(Boolean) } : x)) })} />
              </div>
            ))}
            <button onClick={() => setRule(i, { ...r, clauses: [...r.clauses, { attribute: "", op: "eq", values: [] }] })}>+ condition</button>
            <ServeEditor value={r.serve} variants={variants} onChange={(s) => setRule(i, { ...r, serve: s })} />
          </div>
        ))}
        <button onClick={() => setDraft({ ...draft, rules: [...draft.rules, { id: `rule-${Date.now().toString(36)}`, clauses: [{ attribute: "email", op: "ends_with", values: [] }], serve: { variant: variants[0] } }] })}>+ Add rule</button>
        <h3>Default (no rule matched)</h3>
        <ServeEditor value={draft.fallthrough} variants={variants} onChange={(s) => setDraft({ ...draft, fallthrough: s })} />
        <div className="row"><button className="primary" onClick={save}>Save {env}</button><span className="muted small">{saved}</span></div>
      </section>
    </div>
  );
}

function Playground({ api, env, onError }: { api: Api; env: string; onError: (e: unknown) => void }) {
  const [ctx, setCtx] = useState('{\n  "key": "user-42",\n  "attributes": { "email": "dev@acme.io", "country": "IN", "plan": "pro" }\n}');
  const [result, setResult] = useState<Awaited<ReturnType<Api["evaluate"]>> | null>(null);
  async function run() {
    try { setResult(await api.evaluate(env, JSON.parse(ctx))); } catch (e) { onError(e instanceof SyntaxError ? new Error(`Invalid JSON: ${e.message}`) : e); }
  }
  return (
    <div className="grid2">
      <section className="card stack">
        <h2>Evaluation playground ({env})</h2>
        <textarea rows={10} className="mono" value={ctx} onChange={(e) => setCtx(e.target.value)} aria-label="Context JSON" />
        <button className="primary" onClick={run}>Evaluate all flags</button>
      </section>
      <section className="card">
        <table>
          <thead><tr><th>Flag</th><th>Value</th><th>Reason</th></tr></thead>
          <tbody>{result && Object.entries(result).map(([k, r]) => (
            <tr key={k}><td className="mono">{k}</td><td className="mono">{JSON.stringify(r.value)}</td>
              <td className="small">{r.reason.kind}{r.reason.ruleId ? ` (${r.reason.ruleId})` : ""}{r.reason.inRollout ? " · rollout" : ""}{r.reason.error ? `: ${r.reason.error}` : ""}</td></tr>
          ))}</tbody>
        </table>
      </section>
    </div>
  );
}

function Audit({ api, onError }: { api: Api; onError: (e: unknown) => void }) {
  const [rows, setRows] = useState<AuditEntry[]>([]);
  useEffect(() => { api.audit().then(setRows).catch(onError); }, [api, onError]);
  return (
    <section className="card">
      <table>
        <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Flag</th><th>Env</th></tr></thead>
        <tbody>{rows.map((r) => (
          <tr key={r.id} title={JSON.stringify({ before: r.before, after: r.after }, null, 2)}>
            <td className="small">{new Date(r.at).toLocaleString()}</td><td>{r.actor}</td><td className="mono small">{r.action}</td><td className="mono">{r.flagKey ?? ""}</td><td>{r.environment ?? ""}</td>
          </tr>
        ))}</tbody>
      </table>
    </section>
  );
}
