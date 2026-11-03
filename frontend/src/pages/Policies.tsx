import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Evaluation, PolicyDoc } from "../api/types";
import { useAuth } from "../auth";
import { Button, Card, DecisionBadge, Empty, ErrorBox, Mono, SeverityBadge, Spinner, Table, Td, Th } from "../components/ui";
import { fmtDate, short, useAsync } from "../hooks";

export default function Policies() {
  const { can, user } = useAuth();
  const policies = useAsync(() => api.policies(), []);
  const scans = useAsync(() => api.scans({ limit: 30 }), []);
  const projects = useAsync(() => api.projects(), []);
  const [sel, setSel] = useState<string>("");
  const [text, setText] = useState("");
  const [note, setNote] = useState("");
  const [scanId, setScanId] = useState("");
  const [preview, setPreview] = useState<Evaluation | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [newProject, setNewProject] = useState("");

  const policy = policies.data?.find((p) => p.id === sel) ?? policies.data?.[0];
  const versions = useAsync(() => (policy ? api.policyVersions(policy.id) : Promise.resolve([])), [policy?.id, policy?.current_version]);
  useEffect(() => { if (policy) { setText(JSON.stringify(policy.document, null, 2)); setPreview(null); setMsg(null); } }, [policy?.id, policy?.current_version]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (!scanId && scans.data?.items[0]) setScanId(scans.data.items[0].id); }, [scans.data, scanId]);

  if (policies.loading && !policies.data) return <Spinner />;
  if (policies.error) return <ErrorBox message={policies.error} onRetry={policies.reload} />;
  if (!policy) return <Empty>No policies found.</Empty>;

  const canEdit = policy.project_id === null ? user?.role === "admin" : can("admin", "security_engineer");
  const parse = (): PolicyDoc | null => { try { return JSON.parse(text) as PolicyDoc; } catch { setMsg({ ok: false, text: "The policy is not valid JSON." }); return null; } };
  const fail = (e: unknown) => setMsg({ ok: false, text: e instanceof Error ? e.message : "Failed" });

  async function runPreview() {
    const doc = parse(); if (!doc || !scanId) return;
    try { setPreview(await api.previewPolicy(policy!.id, scanId, doc)); setMsg(null); } catch (e) { fail(e); }
  }
  async function save() {
    const doc = parse(); if (!doc) return;
    try { await api.newPolicyVersion(policy!.id, doc, note); setNote(""); setMsg({ ok: true, text: "New version saved (audited). It applies to scans evaluated from now on." }); policies.reload(); } catch (e) { fail(e); }
  }
  async function createProjectPolicy() {
    const doc = parse(); if (!doc || !newProject) return;
    try { await api.createPolicy(`${projects.data?.find((p) => p.id === newProject)?.name ?? "project"} policy`, newProject, doc, "Created from the UI"); policies.reload(); setMsg({ ok: true, text: "Project policy created and activated." }); } catch (e) { fail(e); }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Policies</h1>
      <div className="flex flex-wrap items-center gap-3">
        <label className="text-sm font-medium">Policy
          <select className="ml-2 rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm" value={policy.id} onChange={(e) => setSel(e.target.value)}>
            {policies.data!.map((p) => <option key={p.id} value={p.id}>{p.name} {p.project_id ? "(project)" : "(global)"} v{p.current_version}{p.is_active ? "" : " — inactive"}</option>)}</select></label>
        {!canEdit && <span className="text-xs text-slate-500">Read-only for your role{policy.project_id === null ? " (global policies need an administrator)" : ""}.</span>}
      </div>
      {msg && <div role={msg.ok ? "status" : "alert"} className={`rounded p-2 text-sm ${msg.ok ? "bg-emerald-50 text-emerald-900" : "bg-red-50 text-red-900"}`}>{msg.text}</div>}
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={`Policy document · v${policy.current_version}`}>
          <label className="sr-only" htmlFor="doc">Policy JSON</label>
          <textarea id="doc" spellCheck={false} readOnly={!canEdit} className="h-96 w-full rounded-md border border-slate-300 p-2 font-mono text-xs" value={text} onChange={(e) => setText(e.target.value)} />
          <p className="mt-2 text-xs text-slate-500">Rules: mandatory scanners, max critical/high, medium warning threshold, known-exploited and secret handling, per environment. Branch patterns map branches to environments; for pull requests the target branch decides.</p>
          {canEdit && (<div className="mt-3 flex flex-wrap items-center gap-2">
            <input aria-label="Change note" placeholder="Change note (recorded in the audit log)" className="min-w-52 flex-1 rounded-md border border-slate-300 px-2 py-1.5 text-sm" value={note} onChange={(e) => setNote(e.target.value)} />
            <Button onClick={save}>Save as new version</Button></div>)}
        </Card>
        <Card title="Preview (does not enforce anything)">
          <div className="flex flex-wrap items-center gap-2">
            <select aria-label="Scan to preview against" className="min-w-0 flex-1 rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm" value={scanId} onChange={(e) => setScanId(e.target.value)}>
              {(scans.data?.items ?? []).map((s) => <option key={s.id} value={s.id}>{s.repository} · {s.branch} · {short(s.commit_sha)} · {s.decision ?? s.status}</option>)}</select>
            <Button onClick={runPreview} disabled={!scanId}>Preview</Button></div>
          {!scans.data?.items.length && <p className="mt-2 text-sm text-slate-500">No scans available to preview against yet.</p>}
          {preview && (
            <div className="mt-4 space-y-3 text-sm">
              <div className="flex items-center gap-3">Would be: <DecisionBadge decision={preview.decision} large />{preview.previous_decision && <span className="text-xs text-slate-500">stored decision: {preview.previous_decision}</span>}</div>
              <p className="text-slate-600">{preview.summary}</p>
              {preview.rules.filter((r) => r.triggered).map((r) => (
                <div key={r.id} className="rounded border border-slate-200 p-2"><Mono>{r.id}</Mono> <strong>{r.name}</strong> ({r.effect}) — {r.explanation}
                  <ul className="mt-1 list-disc pl-5 text-xs">{r.findings.slice(0, 8).map((f) => <li key={f.finding_id}><SeverityBadge severity={f.severity} /> <Link className="text-indigo-700 hover:underline" to={`/findings/${f.finding_id}`}>{f.title}</Link></li>)}</ul></div>))}
              {preview.rules.every((r) => !r.triggered) && <p className="text-emerald-800">No rules would trigger.</p>}
            </div>)}
        </Card>
      </div>
      {policy.project_id === null && can("admin", "security_engineer") && (
        <Card title="Project-specific thresholds">
          <p className="mb-2 text-sm text-slate-600">Create a project policy from the document above (edit the thresholds first). It overrides the global policy for that project.</p>
          <div className="flex gap-2"><select aria-label="Project" className="rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm" value={newProject} onChange={(e) => setNewProject(e.target.value)}>
            <option value="">Select project…</option>{(projects.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
            <Button variant="secondary" disabled={!newProject} onClick={createProjectPolicy}>Create project policy</Button></div>
        </Card>)}
      <Card title="Version history">
        {versions.data && (<Table><thead><tr><Th>Version</Th><Th>Created</Th><Th>Note</Th></tr></thead>
          <tbody className="divide-y divide-slate-100">{versions.data.map((v) => <tr key={v.version}><Td>v{v.version}</Td><Td className="text-xs">{fmtDate(v.created_at)}</Td><Td className="text-xs">{v.change_note || "-"}</Td></tr>)}</tbody></Table>)}
      </Card>
    </div>
  );
}
