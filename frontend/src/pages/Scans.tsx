import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Card, DecisionBadge, Empty, ErrorBox, Mono, Pager, Spinner, StatusBadge, Table, Td, Th } from "../components/ui";
import { fmtDate, short, useAsync } from "../hooks";

export default function Scans() {
  const [decision, setDecision] = useState("");
  const [offset, setOffset] = useState(0);
  const { data, error, loading, reload } = useAsync(() => api.scans({ decision, limit: 25, offset }), [decision, offset]);
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between"><h1 className="text-2xl font-bold">Scans</h1>
        <select aria-label="Decision" className="rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm" value={decision} onChange={(e) => { setDecision(e.target.value); setOffset(0); }}>
          <option value="">All decisions</option><option>PASS</option><option>WARN</option><option>FAIL</option></select></div>
      {error && <ErrorBox message={error} onRetry={reload} />}
      {loading && !data && <Spinner />}
      {data && data.items.length === 0 && <Empty>No scans found.</Empty>}
      {data && data.items.length > 0 && (
        <Card><Table><thead><tr><Th>When</Th><Th>Repository</Th><Th>Branch</Th><Th>Commit</Th><Th>Env</Th><Th>Status</Th><Th>Decision</Th></tr></thead>
          <tbody className="divide-y divide-slate-100">{data.items.map((s) => (
            <tr key={s.id} className="hover:bg-slate-50"><Td className="text-xs">{fmtDate(s.created_at)}</Td><Td>{s.repository}</Td>
              <Td><Mono>{s.branch}</Mono>{s.pr_number && <span className="ml-1 text-xs">PR #{s.pr_number}</span>}</Td>
              <Td><Link className="text-indigo-700 hover:underline" to={`/scans/${s.id}`}>{short(s.commit_sha)}</Link></Td><Td className="text-xs">{s.environment}</Td>
              <Td><StatusBadge status={s.status} /></Td><Td><DecisionBadge decision={s.decision} /></Td></tr>))}</tbody></Table>
          <Pager total={data.total} limit={25} offset={offset} onChange={setOffset} /></Card>)}
    </div>
  );
}
