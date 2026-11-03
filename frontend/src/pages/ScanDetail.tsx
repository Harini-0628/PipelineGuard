import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, download } from "../api/client";
import { useAuth } from "../auth";
import FindingsTable from "../components/FindingsTable";
import { Button, Card, DecisionBadge, ErrorBox, Mono, SeverityBadge, Spinner, StatusBadge, Table, Td, Th } from "../components/ui";
import { fmtDate, useAsync } from "../hooks";

export default function ScanDetail() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const { data: s, error, loading, reload } = useAsync(() => api.scan(id), [id]);
  const [msg, setMsg] = useState<string | null>(null);
  if (loading && !s) return <Spinner />;
  if (error || !s) return <ErrorBox message={error ?? "Not found"} onRetry={reload} />;
  const ev = s.evaluation;
  const failedExec = s.executions.filter((e) => e.status !== "succeeded");
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><h1 className="text-2xl font-bold">Scan {s.id.slice(0, 8)}</h1>
          <p className="text-sm text-slate-500"><Link className="text-indigo-700 hover:underline" to={`/repositories/${s.repository_id}`}>{s.repository}</Link> · <Mono>{s.branch}</Mono>{s.base_branch && <> → <Mono>{s.base_branch}</Mono></>} · <Mono>{s.commit_sha.slice(0, 12)}</Mono>{s.pr_number && ` · PR #${s.pr_number}`}{s.build_id && ` · build ${s.build_id}`}</p></div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" onClick={() => download(`/scans/${id}/report.json`, `pipelineguard-${id}.json`).catch((e) => setMsg(e.message))}>Download JSON</Button>
          {can("admin", "security_engineer") && <Button variant="secondary" onClick={async () => { try { await api.reevaluate(id); reload(); setMsg("Re-evaluated against the current policy."); } catch (e) { setMsg(e instanceof Error ? e.message : "Failed"); } }}>Re-evaluate</Button>}
        </div>
      </div>
      {msg && <div role="status" className="rounded bg-indigo-50 p-2 text-sm text-indigo-900">{msg}</div>}
      <Card>
        <div className="flex flex-wrap items-center gap-4"><DecisionBadge decision={s.decision} large /><StatusBadge status={s.status} />
          <span className="text-sm text-slate-600">{ev?.summary}</span></div>
        {failedExec.length > 0 && <div className="mt-3"><ErrorBox message={`Scanner problems: ${failedExec.map((e) => `${e.scanner} ${e.status}`).join(", ")}. Missing results are never treated as a clean scan.`} /></div>}
        <div className="mt-4 flex flex-wrap gap-2 text-sm">{(["critical", "high", "medium", "low", "info"] as const).map((k) => (
          <span key={k} className="flex items-center gap-1"><SeverityBadge severity={k} /><strong>{s.severity_counts[k] ?? 0}</strong>{(s.new_counts[k] ?? 0) > 0 && <span className="text-xs text-red-700">({s.new_counts[k]} new)</span>}</span>))}</div>
      </Card>
      {ev && (
        <Card title={`Policy evaluation — ${ev.policy.name} v${ev.policy.version} · environment ${ev.environment}`}>
          <ul className="space-y-3">{ev.rules.map((r) => (
            <li key={r.id} className={`rounded-md border p-3 text-sm ${r.triggered ? (r.effect === "FAIL" ? "border-red-300 bg-red-50" : "border-amber-300 bg-amber-50") : "border-slate-200"}`}>
              <div className="flex flex-wrap items-center gap-2"><Mono>{r.id}</Mono><strong>{r.name}</strong>
                <span className="text-xs">{r.triggered ? `TRIGGERED (${r.effect})` : r.effect === "NONE" ? "informational" : "ok"}</span></div>
              <p className="mt-1 text-slate-700">{r.explanation}</p>
              {r.triggered && r.findings.length > 0 && <ul className="mt-2 list-disc pl-5 text-xs">{r.findings.slice(0, 10).map((f) => (
                <li key={f.finding_id}><SeverityBadge severity={f.severity} /> <Link className="text-indigo-700 hover:underline" to={`/findings/${f.finding_id}`}>{f.title}</Link> <span className="text-slate-500">{f.location}</span></li>))}
                {r.findings.length > 10 && <li>…and {r.findings.length - 10} more</li>}</ul>}
            </li>))}</ul>
          {ev.suppressions_applied.length > 0 && <div className="mt-3 text-sm"><strong>Suppressions applied:</strong><ul className="list-disc pl-5 text-xs">{ev.suppressions_applied.map((x) => <li key={x.finding_id}>{x.title} — {x.reason} (expires {fmtDate(x.expires_at)})</li>)}</ul></div>}
          {ev.suppressions_expired.length > 0 && <p className="mt-2 text-xs text-amber-800">{ev.suppressions_expired.length} expired suppression(s) were NOT applied.</p>}
        </Card>)}
      <Card title="Scanner executions">
        <Table><thead><tr><Th>Scanner</Th><Th>Mode</Th><Th>Status</Th><Th>Version</Th><Th>Duration</Th><Th>Findings</Th><Th>Error</Th></tr></thead>
          <tbody className="divide-y divide-slate-100">{s.executions.map((e) => (
            <tr key={e.scanner}><Td>{e.scanner}</Td><Td className="text-xs">{e.scan_mode || "-"}</Td><Td><StatusBadge status={e.status} /></Td><Td className="text-xs">{e.version ?? "-"}</Td>
              <Td className="text-xs">{e.duration_ms !== null ? `${(e.duration_ms / 1000).toFixed(1)}s` : "-"}</Td><Td>{e.findings_count}</Td>
              <Td className="max-w-md break-words text-xs text-red-800">{e.error ?? ""}{e.stderr_tail && e.status !== "succeeded" && <details><summary className="cursor-pointer text-slate-600">stderr</summary><pre className="whitespace-pre-wrap">{e.stderr_tail}</pre></details>}</Td></tr>))}</tbody></Table>
        <p className="mt-2 text-xs text-slate-500">Started {fmtDate(s.started_at)} · finished {fmtDate(s.finished_at)}</p>
      </Card>
      <Card title="Findings in this scan"><FindingsTable scanId={id} /></Card>
    </div>
  );
}
