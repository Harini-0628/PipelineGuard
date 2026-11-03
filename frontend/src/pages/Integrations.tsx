import { Fragment, useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth";
import { Button, Card, Empty, ErrorBox, Mono, Spinner, StatusBadge, Table, Td, Th } from "../components/ui";
import { fmtDate, useAsync } from "../hooks";

export default function Integrations() {
  const { can } = useAuth();
  const st = useAsync(() => api.integrations(), []);
  const audit = useAsync(() => (can("admin", "security_engineer") ? api.audit({ limit: 25 }) : Promise.resolve(null)), []);
  const [msg, setMsg] = useState<string | null>(null);
  if (st.loading && !st.data) return <Spinner />;
  if (st.error || !st.data) return <ErrorBox message={st.error ?? "No data"} onRetry={st.reload} />;
  const d = st.data;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Integrations & settings</h1>
      {msg && <div role="status" className="rounded bg-indigo-50 p-2 text-sm text-indigo-900">{msg}</div>}
      <Card title="Scanners (as observed from real executions)">
        <Table><thead><tr><Th>Scanner</Th><Th>Last version</Th><Th>Last status</Th><Th>Last run</Th><Th>Executions</Th></tr></thead>
          <tbody className="divide-y divide-slate-100">{d.scanners.map((s) => (
            <tr key={s.scanner}><Td>{s.scanner}</Td><Td className="text-xs">{s.last_version ?? "never reported"}</Td><Td>{s.last_status ? <StatusBadge status={s.last_status} /> : "-"}</Td>
              <Td className="text-xs">{fmtDate(s.last_run_at)}</Td><Td className="text-xs">{Object.entries(s.executions_by_status).map(([k, v]) => `${k}: ${v}`).join(", ") || "-"}
                {s.last_error && <div className="text-red-800">{s.last_error}</div>}</Td></tr>))}</tbody></Table>
        <p className="mt-2 text-xs text-slate-500">Scanners run in your CI jobs, not on this server; versions are reported by the jobs themselves.</p>
      </Card>
      <Card title="CI providers">
        {d.ci_providers.length === 0 ? <Empty>No repositories registered.</Empty> : <ul className="text-sm">{d.ci_providers.map((c) => <li key={c.provider}><strong>{c.provider}</strong> — {c.repositories} repo(s) · {c.integration}</li>)}</ul>}
      </Card>
      <Card title="Notifications (webhooks)">
        {d.notifications.length === 0 ? <Empty>No webhooks configured. Administrators can add them through the API (POST /api/v1/integrations/webhooks).</Empty> : (
          <Table><thead><Th>Name</Th><Th>Target</Th><Th>Notify on</Th><Th>Last status</Th><Th>Last error</Th></thead>
            <tbody className="divide-y divide-slate-100">{d.notifications.map((n) => <tr key={n.id}><Td>{n.name}{!n.enabled && " (disabled)"}</Td><Td className="text-xs"><Mono>{n.url}</Mono></Td><Td className="text-xs">{n.notify_on.join(", ")}</Td>
              <Td>{n.last_status ? <StatusBadge status={n.last_status === "ok" ? "succeeded" : "failed"} /> : "never"}</Td><Td className="text-xs text-red-800">{n.last_error}</Td></tr>)}</tbody></Table>)}
      </Card>
      <Card title="Vulnerability intelligence (CISA KEV)" actions={can("admin") && <Button variant="secondary" onClick={async () => { const r = await api.refreshKev(); setMsg(r.ok ? `KEV catalog refreshed (${r.count} entries).` : `KEV refresh failed: ${r.error}`); st.reload(); }}>Refresh now</Button>}>
        <p className="text-sm">{d.enrichment.cisa_kev.loaded ? `${d.enrichment.cisa_kev.entries} entries, retrieved ${fmtDate(d.enrichment.cisa_kev.retrieved_at)}.` : "Not loaded. Known-exploited status is reported as unknown (never as safe) until the catalog is refreshed."}</p>
      </Card>
      <Card title="Safe configuration status"><dl className="grid grid-cols-[auto,1fr] gap-x-4 gap-y-1 text-sm">
        {Object.entries(d.config).map(([k, v]) => <Fragment key={k}><dt className="text-slate-500">{k}</dt><dd className="break-all"><Mono>{JSON.stringify(v)}</Mono></dd></Fragment>)}</dl>
        <p className="mt-2 text-xs text-slate-500">Secrets are never returned by the API; only whether they are configured.</p></Card>
      {audit.data && (
        <Card title="Recent audit events">
          <Table><thead><tr><Th>When</Th><Th>Actor</Th><Th>Action</Th><Th>Target</Th></tr></thead>
            <tbody className="divide-y divide-slate-100">{audit.data.items.map((e) => <tr key={e.id}><Td className="text-xs">{fmtDate(e.at)}</Td><Td className="text-xs">{e.actor}</Td><Td><Mono>{e.action}</Mono></Td><Td className="text-xs">{e.target_type} {e.target_id.slice(0, 8)}</Td></tr>)}</tbody></Table>
        </Card>)}
    </div>
  );
}
