import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api/client";
import { Card, DecisionBadge, Empty, ErrorBox, SEVERITY_COLORS, SeverityBadge, Spinner, Stat } from "../components/ui";
import { fmtDate, short, useAsync } from "../hooks";

export default function Overview() {
  const ov = useAsync(() => api.overview(30), []);
  const tr = useAsync(() => api.trends(30), []);
  if (ov.loading && !ov.data) return <Spinner />;
  if (ov.error || !ov.data) return <ErrorBox message={ov.error ?? "No data"} onRetry={ov.reload} />;
  const d = ov.data;
  const openTotal = Object.values(d.open_findings).reduce((a, b) => a + b, 0);
  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold">Security overview</h1><p className="text-sm text-slate-500">Last {d.window_days} days. Open findings are counted on each repository's default branch.</p></div>
      {d.repositories === 0 && <Empty>No repositories yet. <Link className="text-indigo-700 underline" to="/repositories">Register one</Link> to start receiving scans.</Empty>}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Repositories" value={d.repositories} />
        <Stat label="Scans (window)" value={d.scans.window} hint={`${d.scans.total} total`} />
        <Stat label="Pass rate" value={d.pass_rate === null ? "-" : `${d.pass_rate}%`} hint="PASS + WARN of decided scans" tone={d.pass_rate !== null && d.pass_rate < 70 ? "text-red-700" : undefined} />
        <Stat label="Open findings" value={openTotal} hint={`${d.suppressed_findings} suppressed`} tone={d.open_findings.critical ? "text-red-700" : undefined} />
        <Stat label="New in window" value={d.new_in_window} />
        <Stat label="Resolved in window" value={d.resolved_in_window} tone="text-emerald-700" />
        <Stat label="Failed builds" value={d.decisions.FAIL} tone={d.decisions.FAIL ? "text-red-700" : undefined} />
        <Stat label="Warnings" value={d.decisions.WARN} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Open findings by severity">
          <div className="h-56" role="img" aria-label="Open findings by severity bar chart">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={Object.entries(d.open_findings).map(([severity, count]) => ({ severity, count }))}>
                <CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="severity" /><YAxis allowDecimals={false} /><Tooltip />
                <Bar dataKey="count" fill="#4f46e5" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Risk exposure & finding flow">
          {tr.error ? <ErrorBox message={`Trends unavailable: ${tr.error}`} onRetry={tr.reload} /> : tr.loading ? <Spinner /> :
            !tr.data || tr.data.points.length === 0 ? <Empty>No scans in this window yet.</Empty> : (
              <div className="h-56" role="img" aria-label="Risk and new versus resolved findings over time">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={tr.data.points}>
                    <CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="date" /><YAxis yAxisId="l" allowDecimals={false} /><YAxis yAxisId="r" orientation="right" />
                    <Tooltip /><Legend />
                    <Line yAxisId="l" dataKey="new" name="New" stroke="#dc2626" />
                    <Line yAxisId="l" dataKey="resolved" name="Resolved" stroke="#059669" />
                    <Line yAxisId="r" dataKey="risk" name="Risk (sum)" stroke="#4f46e5" strokeDasharray="4 2" />
                  </LineChart>
                </ResponsiveContainer>
              </div>)}
          <p className="mt-2 text-xs text-slate-500">Risk = total heuristic risk score of the last default-branch scan per repository per day. Only days with scans appear.</p>
        </Card>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Recent pipeline failures">
          {d.recent_failures.length === 0 ? <Empty>No failed builds in the recorded history.</Empty> : (
            <ul className="divide-y divide-slate-100">{d.recent_failures.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-2 py-2 text-sm">
                <Link to={`/scans/${s.id}`} className="min-w-0 truncate text-indigo-700 hover:underline">{s.repository} · {s.branch} · {short(s.commit_sha)}</Link>
                <span className="shrink-0 text-xs text-slate-500">{fmtDate(s.created_at)}</span>
              </li>))}</ul>)}
        </Card>
        <Card title="Highest-priority remediation">
          {d.top_remediation.length === 0 ? <Empty>No open findings.</Empty> : (
            <ul className="divide-y divide-slate-100">{d.top_remediation.map((f) => (
              <li key={f.id} className="py-2 text-sm">
                <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} />
                  <Link to={`/findings/${f.id}`} className="truncate font-medium text-indigo-700 hover:underline">{f.title}</Link>
                  <span className="ml-auto font-mono text-xs" style={{ color: SEVERITY_COLORS[f.severity] }}>{f.risk_score.toFixed(1)}</span></div>
                <div className="text-xs text-slate-500">{f.repository}{f.package ? ` · ${f.package}${f.fixed_version ? ` → ${f.fixed_version}` : ""}` : f.file_path ? ` · ${f.file_path}` : ""}</div>
              </li>))}</ul>)}
        </Card>
      </div>
      <Card title="Recent scans">
        {d.recent_scans.length === 0 ? <Empty>No scans yet.</Empty> : (
          <ul className="divide-y divide-slate-100">{d.recent_scans.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-2 py-2 text-sm">
              <Link to={`/scans/${s.id}`} className="min-w-0 truncate text-indigo-700 hover:underline">{s.repository} · {s.branch} · {short(s.commit_sha)}</Link>
              <span className="flex shrink-0 items-center gap-3"><DecisionBadge decision={s.decision} /><span className="hidden text-xs text-slate-500 sm:inline">{fmtDate(s.created_at)}</span></span>
            </li>))}</ul>)}
      </Card>
    </div>
  );
}
