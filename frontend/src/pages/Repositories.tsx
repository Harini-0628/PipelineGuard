import { useState, type SyntheticEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { RepositoryCreated } from "../api/types";
import { useAuth } from "../auth";
import { Button, Card, DecisionBadge, Empty, ErrorBox, Mono, Spinner, Table, Td, Th } from "../components/ui";
import { fmtDate, short, useAsync } from "../hooks";

const field = "mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm";

export default function Repositories() {
  const { can } = useAuth();
  const repos = useAsync(() => api.repositories({ limit: 100 }), []);
  const projects = useAsync(() => api.projects(), []);
  const [form, setForm] = useState({ project_id: "", full_name: "", ci_provider: "github", default_branch: "main", criticality: "medium", internet_facing: false });
  const [created, setCreated] = useState<RepositoryCreated | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [pname, setPname] = useState("");

  async function register(e: SyntheticEvent) {
    e.preventDefault(); setErr(null);
    try { setCreated(await api.registerRepository({ ...form, project_id: form.project_id || projects.data?.[0]?.id || "" })); repos.reload(); }
    catch (x) { setErr(x instanceof Error ? x.message : "Failed"); }
  }
  async function newProject(e: SyntheticEvent) {
    e.preventDefault(); setErr(null);
    try { await api.createProject(pname); setPname(""); projects.reload(); } catch (x) { setErr(x instanceof Error ? x.message : "Failed"); }
  }
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Repositories</h1>
      {repos.error && <ErrorBox message={repos.error} onRetry={repos.reload} />}
      {repos.loading && !repos.data ? <Spinner /> : repos.data && repos.data.items.length === 0 ? <Empty>No repositories registered yet.</Empty> : repos.data && (
        <Card><Table>
          <thead><tr><Th>Repository</Th><Th>Latest scan</Th><Th>Decision</Th><Th>Open (crit/high/med)</Th><Th>Default branch</Th></tr></thead>
          <tbody className="divide-y divide-slate-100">{repos.data.items.map((r) => (
            <tr key={r.id} className="hover:bg-slate-50">
              <Td><Link className="font-medium text-indigo-700 hover:underline" to={`/repositories/${r.id}`}>{r.full_name}</Link><div className="text-xs text-slate-500">{r.ci_provider} · criticality {r.criticality}</div></Td>
              <Td className="text-xs">{r.latest_scan ? <><Link className="text-indigo-700 hover:underline" to={`/scans/${r.latest_scan.id}`}>{short(r.latest_scan.commit_sha)}</Link> · {r.latest_scan.status}<div className="text-slate-500">{fmtDate(r.latest_scan.created_at)}</div></> : "never scanned"}</Td>
              <Td><DecisionBadge decision={r.latest_scan?.decision} /></Td>
              <Td className="font-mono text-xs">{r.open_findings?.critical ?? 0} / {r.open_findings?.high ?? 0} / {r.open_findings?.medium ?? 0}</Td>
              <Td className="text-xs"><Mono>{r.default_branch}</Mono></Td>
            </tr>))}</tbody></Table></Card>)}
      {can("admin", "security_engineer") && (
        <Card title="Register a repository">
          {err && <ErrorBox message={err} />}
          {created ? (
            <div className="space-y-2 text-sm" role="status">
              <p className="font-semibold text-emerald-800">Registered {created.full_name}.</p>
              <p>Copy this ingest token now — it is shown only once. Store it as the CI secret <Mono>PIPELINEGUARD_TOKEN</Mono>.</p>
              <pre className="overflow-x-auto rounded bg-slate-900 p-3 text-xs text-emerald-300">{created.ingest_token}</pre>
              <Button variant="secondary" onClick={() => setCreated(null)}>Done</Button>
            </div>) : (
            <form onSubmit={register} className="grid gap-3 md:grid-cols-3">
              <label className="text-sm font-medium">Project
                <select className={field} value={form.project_id} onChange={(e) => setForm({ ...form, project_id: e.target.value })}>
                  {(projects.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
              <label className="text-sm font-medium">Repository (org/name)
                <input required pattern="[A-Za-z0-9_.\-/]+" className={field} value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></label>
              <label className="text-sm font-medium">CI provider
                <select className={field} value={form.ci_provider} onChange={(e) => setForm({ ...form, ci_provider: e.target.value })}><option>github</option><option>gitlab</option><option>other</option></select></label>
              <label className="text-sm font-medium">Default branch
                <input required className={field} value={form.default_branch} onChange={(e) => setForm({ ...form, default_branch: e.target.value })} /></label>
              <label className="text-sm font-medium">Asset criticality
                <select className={field} value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })}>{["low", "medium", "high", "critical"].map((c) => <option key={c}>{c}</option>)}</select></label>
              <label className="flex items-end gap-2 pb-2 text-sm font-medium"><input type="checkbox" checked={form.internet_facing} onChange={(e) => setForm({ ...form, internet_facing: e.target.checked })} />Internet-facing</label>
              <div className="md:col-span-3"><Button type="submit" disabled={!projects.data?.length}>Register repository</Button>{projects.data?.length === 0 && <span className="ml-3 text-sm text-slate-500">Create a project first.</span>}</div>
            </form>)}
        </Card>)}
      {can("admin") && (
        <Card title="Create a project">
          <form onSubmit={newProject} className="flex gap-2"><input required minLength={2} aria-label="Project name" placeholder="Project name" className={`${field} mt-0`} value={pname} onChange={(e) => setPname(e.target.value)} /><Button type="submit">Create</Button></form>
        </Card>)}
    </div>
  );
}
