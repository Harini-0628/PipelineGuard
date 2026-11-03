import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../hooks";
import { Empty, ErrorBox, Mono, Pager, SeverityBadge, Spinner, Table, Td, Th } from "./ui";

const sel = "rounded-md border border-slate-300 bg-white px-2 py-1.5 text-sm";

export default function FindingsTable({ repositoryId, scanId, defaultStatus = "" }: { repositoryId?: string; scanId?: string; defaultStatus?: string }) {
  const [f, setF] = useState({ severity: "", status: defaultStatus, scanner: "", category: "", q: "", branch: "" });
  const [offset, setOffset] = useState(0);
  const limit = 20;
  const set = (k: keyof typeof f, v: string) => { setF({ ...f, [k]: v }); setOffset(0); };
  const { data, error, loading, reload } = useAsync(
    () => api.findings({ ...f, repository_id: repositoryId, scan_id: scanId, limit, offset, sort: "severity" }),
    [f.severity, f.status, f.scanner, f.category, f.q, f.branch, repositoryId, scanId, offset],
  );
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2" role="search">
        <input aria-label="Search findings" placeholder="Search title, file, package, CVE…" value={f.q} onChange={(e) => set("q", e.target.value)} className={`${sel} min-w-52 flex-1`} />
        <select aria-label="Severity" className={sel} value={f.severity} onChange={(e) => set("severity", e.target.value)}>
          <option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select aria-label="Status" className={sel} value={f.status} onChange={(e) => set("status", e.target.value)}>
          <option value="">All statuses</option>{["open", "acknowledged", "suppressed", "resolved"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select aria-label="Scanner" className={sel} value={f.scanner} onChange={(e) => set("scanner", e.target.value)}>
          <option value="">All scanners</option>{["semgrep", "trivy", "trivy-image"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select aria-label="Category" className={sel} value={f.category} onChange={(e) => set("category", e.target.value)}>
          <option value="">All categories</option>{["sast", "dependency", "container", "misconfig", "secret"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      {error && <ErrorBox message={error} onRetry={reload} />}
      {loading && !data && <Spinner />}
      {data && data.items.length === 0 && <Empty>No findings match these filters.</Empty>}
      {data && data.items.length > 0 && (
        <>
          <Table>
            <thead><tr><Th>Severity</Th><Th>Finding</Th><Th>Location</Th><Th>Scanner</Th><Th>Risk</Th><Th>Status</Th></tr></thead>
            <tbody className="divide-y divide-slate-100">
              {data.items.map((x) => (
                <tr key={x.id} className="hover:bg-slate-50">
                  <Td><SeverityBadge severity={x.severity} /></Td>
                  <Td><Link className="font-medium text-indigo-700 hover:underline" to={`/findings/${x.id}`}>{x.title}</Link>
                    {x.vuln_id && <div className="text-xs text-slate-500">{x.vuln_id}{x.known_exploited && <span className="ml-1 font-semibold text-red-700">KEV</span>}</div>}</Td>
                  <Td className="max-w-xs break-words text-xs">{x.package_name ? <><Mono>{x.package_name}</Mono> {x.installed_version}{x.fixed_version && <> → <strong>{x.fixed_version}</strong></>}</> : <Mono>{(x.file_path ?? "-") + (x.line ? `:${x.line}` : "")}</Mono>}</Td>
                  <Td className="text-xs">{x.scanner}<div className="text-slate-500">{x.category}</div></Td>
                  <Td className="font-mono text-xs">{x.risk_score.toFixed(1)}</Td>
                  <Td className="text-xs">{x.effective_status}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <Pager total={data.total} limit={limit} offset={offset} onChange={setOffset} />
        </>
      )}
    </div>
  );
}
