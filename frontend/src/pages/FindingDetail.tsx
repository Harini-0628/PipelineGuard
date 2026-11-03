import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../auth";
import { Button, Card, ErrorBox, Mono, SeverityBadge, Spinner } from "../components/ui";
import { fmtDate, useAsync } from "../hooks";

const input = "mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm";

export default function FindingDetail() {
  const { id = "" } = useParams();
  const { can, user } = useAuth();
  const { data: f, error, loading, reload } = useAsync(() => api.finding(id), [id]);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(14);
  const [msg, setMsg] = useState<string | null>(null);
  if (loading && !f) return <Spinner />;
  if (error || !f) return <ErrorBox message={error ?? "Not found"} onRetry={reload} />;
  const act = async (fn: () => Promise<unknown>, ok: string) => { try { await fn(); setMsg(ok); reload(); } catch (e) { setMsg(e instanceof Error ? e.message : "Failed"); } };
  const writer = can("admin", "security_engineer");
  const canSuppress = writer && (f.severity !== "critical" || user?.role === "admin");
  const comps = f.risk_factors.components ?? {};
  return (
    <div className="space-y-6">
      <div><div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={f.severity} /><h1 className="text-xl font-bold">{f.title}</h1></div>
        <p className="mt-1 text-sm text-slate-500"><Mono>{f.scanner}</Mono> · <Mono>{f.scanner_finding_id}</Mono> · {f.category} · branch <Mono>{f.branch}</Mono> · status <strong>{f.effective_status}</strong></p></div>
      {msg && <div role="status" className="rounded bg-indigo-50 p-2 text-sm text-indigo-900">{msg}</div>}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Description & evidence">
          <p className="whitespace-pre-wrap text-sm">{f.description || "No description supplied by the scanner."}</p>
          <dl className="mt-3 grid grid-cols-[auto,1fr] gap-x-3 gap-y-1 text-sm">
            {f.vuln_id && <><dt className="text-slate-500">Vulnerability</dt><dd>{f.vuln_id}{f.known_exploited === true && <strong className="ml-2 text-red-700">Known exploited (CISA KEV)</strong>}{f.known_exploited === null && <span className="ml-2 text-xs text-slate-500">exploitation status unknown</span>}</dd></>}
            {f.package_name && <><dt className="text-slate-500">Component</dt><dd><Mono>{f.package_name}</Mono> {f.installed_version} {f.fixed_version ? <>→ fixed in <strong>{f.fixed_version}</strong></> : "(no fixed version published)"}</dd></>}
            {f.file_path && <><dt className="text-slate-500">Location</dt><dd><Mono>{f.file_path}{f.line ? `:${f.line}` : ""}</Mono></dd></>}
            {f.resource && <><dt className="text-slate-500">Resource</dt><dd className="break-all"><Mono>{f.resource}</Mono></dd></>}
            {f.cwe.length > 0 && <><dt className="text-slate-500">CWE</dt><dd>{f.cwe.join(", ")}</dd></>}
            {f.confidence && <><dt className="text-slate-500">Confidence</dt><dd>{f.confidence}</dd></>}
            <dt className="text-slate-500">First / last seen</dt><dd>{fmtDate(f.first_seen_at)} / {fmtDate(f.last_seen_at)}</dd>
          </dl>
          {f.references.length > 0 && <ul className="mt-3 list-disc pl-5 text-xs">{f.references.slice(0, 6).map((r) => <li key={r} className="break-all">{/^https?:\/\//.test(r) ? <a className="text-indigo-700 underline" href={r} target="_blank" rel="noopener noreferrer">{r}</a> : r}</li>)}</ul>}
        </Card>
        <Card title="Risk prioritization">
          <p className="text-3xl font-bold">{f.risk_score.toFixed(1)}<span className="text-sm font-normal text-slate-500"> / 100 (heuristic)</span></p>
          <ul className="mt-2 text-sm">{Object.entries(comps).map(([k, v]) => <li key={k} className="flex justify-between border-b border-slate-100 py-1"><span>{k.replace(/_/g, " ")}</span><span className="font-mono">+{v}</span></li>)}</ul>
          {(f.risk_factors.missing?.length ?? 0) > 0 && <p className="mt-2 text-xs text-amber-800">Intelligence not available: {f.risk_factors.missing?.join(", ")}. Missing data adds 0 and is not evidence of safety.</p>}
          <p className="mt-2 text-xs text-slate-500">The risk score informs ordering only. The policy decision never reads it.</p>
        </Card>
      </div>
      <Card title="Remediation"><p className="whitespace-pre-wrap text-sm">{f.remediation || "No remediation guidance supplied."}</p></Card>
      {writer && (
        <Card title="Lifecycle">
          <div className="flex flex-wrap gap-2">
            {f.status !== "resolved" && <Button variant="secondary" onClick={() => act(() => api.setFindingStatus(f.id, f.status === "acknowledged" ? "open" : "acknowledged"), "Status updated")}>{f.status === "acknowledged" ? "Re-open" : "Acknowledge"}</Button>}
          </div>
          {f.suppression ? (
            <div className="mt-3 rounded-md bg-amber-50 p-3 text-sm">Suppressed until {fmtDate(f.suppression.expires_at)}: {f.suppression.reason}
              <div className="mt-2"><Button variant="danger" onClick={() => act(() => api.revokeSuppression(f.id, f.suppression!.id), "Suppression revoked")}>Revoke suppression</Button></div></div>
          ) : f.status !== "resolved" && canSuppress ? (
            <form className="mt-3 space-y-2" onSubmit={(e) => { e.preventDefault(); act(() => api.suppress(f.id, reason, new Date(Date.now() + days * 86400000).toISOString()), "Suppression created (audited)"); }}>
              <label className="block text-sm font-medium">Suppression reason (min. 10 characters, recorded in the audit log)
                <textarea required minLength={10} className={input} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
              <label className="block text-sm font-medium">Expires in (days)<input type="number" min={1} max={180} className={`${input} w-32`} value={days} onChange={(e) => setDays(Number(e.target.value))} /></label>
              <Button type="submit">Suppress finding</Button>
            </form>) : f.severity === "critical" && writer && <p className="mt-3 text-xs text-slate-500">Only administrators may suppress critical findings.</p>}
        </Card>)}
      <Card title="Audit history">
        {f.history.length === 0 ? <p className="text-sm text-slate-500">No lifecycle events recorded.</p> :
          <ul className="space-y-1 text-sm">{f.history.map((h, i) => <li key={i}><span className="text-xs text-slate-500">{fmtDate(h.at)}</span> · <Mono>{h.action}</Mono> by {h.actor}{h.details && "to" in h.details ? ` → ${String(h.details.to)}` : ""}</li>)}</ul>}
      </Card>
      <Link className="text-sm text-indigo-700 hover:underline" to={`/repositories/${f.repository_id}`}>← Repository</Link>
    </div>
  );
}
