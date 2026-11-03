import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { RepositoryCreated } from "../api/types";
import { useAuth } from "../auth";
import FindingsTable from "../components/FindingsTable";
import { Button, Card, DecisionBadge, Empty, ErrorBox, Mono, Spinner, Stat, StatusBadge, Table, Td, Th } from "../components/ui";
import { fmtDate, short, useAsync } from "../hooks";

export default function RepositoryDetail() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const repo = useAsync(() => api.repository(id), [id]);
  const scans = useAsync(() => api.scans({ repository_id: id, limit: 15 }), [id]);
  const listing = useAsync(() => api.repositories({ limit: 200 }), []);
  const policies = useAsync(() => api.policies(), []);
  const [token, setToken] = useState<RepositoryCreated | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (repo.loading && !repo.data) return <Spinner />;
  if (repo.error || !repo.data) return <ErrorBox message={repo.error ?? "Not found"} onRetry={repo.reload} />;
  const r = repo.data;
  const summary = listing.data?.items.find((x) => x.id === id);
  const policy = policies.data?.find((p) => p.project_id === r.project_id && p.is_active) ?? policies.data?.find((p) => p.project_id === null && p.is_active);
  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold">{r.full_name}</h1>
        <p className="text-sm text-slate-500">{r.ci_provider} · default branch <Mono>{r.default_branch}</Mono> · criticality {r.criticality}{r.internet_facing ? " · internet-facing" : ""} · token <Mono>{r.ingest_token_prefix}…</Mono></p></div>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {["critical", "high", "medium", "low"].map((s) => <Stat key={s} label={`Open ${s}`} value={summary?.open_findings?.[s] ?? 0} tone={s === "critical" && summary?.open_findings?.critical ? "text-red-700" : undefined} />)}
      </div>
      <Card title="Security posture & policy">
        <div className="flex flex-wrap items-center gap-4 text-sm">
          <span>Latest decision: <DecisionBadge decision={summary?.latest_scan?.decision} /></span>
          <span>Effective policy: {policy ? <Link className="text-indigo-700 underline" to="/policies">{policy.name} v{policy.current_version}{policy.project_id ? " (project)" : " (global)"}</Link> : "-"}</span>
        </div>
      </Card>
      <Card title="Scan history">
        {scans.error && <ErrorBox message={scans.error} onRetry={scans.reload} />}
        {scans.data && scans.data.items.length === 0 && <Empty>No scans yet. Add the PipelineGuard step to your CI workflow.</Empty>}
        {scans.data && scans.data.items.length > 0 && (
          <Table><thead><tr><Th>When</Th><Th>Branch</Th><Th>Commit</Th><Th>Status</Th><Th>Decision</Th></tr></thead>
            <tbody className="divide-y divide-slate-100">{scans.data.items.map((s) => (
              <tr key={s.id}><Td className="text-xs">{fmtDate(s.created_at)}</Td><Td><Mono>{s.branch}</Mono>{s.pr_number && <span className="ml-1 text-xs">PR #{s.pr_number}</span>}</Td>
                <Td><Link className="text-indigo-700 hover:underline" to={`/scans/${s.id}`}>{short(s.commit_sha)}</Link></Td><Td><StatusBadge status={s.status} /></Td><Td><DecisionBadge decision={s.decision} /></Td></tr>))}</tbody></Table>)}
      </Card>
      <Card title="Findings"><FindingsTable repositoryId={id} defaultStatus="open" /></Card>
      {can("admin", "security_engineer") && (
        <Card title="Ingest token">
          {err && <ErrorBox message={err} />}
          {token ? <div className="space-y-2 text-sm"><p>New token (shown once). The previous token no longer works.</p><pre className="overflow-x-auto rounded bg-slate-900 p-3 text-xs text-emerald-300">{token.ingest_token}</pre></div> :
            <Button variant="secondary" onClick={async () => { if (confirm("Rotate the ingest token? CI jobs using the old token will fail until updated.")) { try { setToken(await api.rotateToken(id)); repo.reload(); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); } } }}>Rotate ingest token</Button>}
        </Card>)}
    </div>
  );
}
