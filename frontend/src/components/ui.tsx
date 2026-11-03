import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { Decision, Severity } from "../api/types";

const SEV: Record<string, string> = {
  critical: "bg-red-700 text-white", high: "bg-orange-100 text-orange-900 ring-1 ring-orange-300",
  medium: "bg-amber-100 text-amber-900 ring-1 ring-amber-300", low: "bg-sky-100 text-sky-900 ring-1 ring-sky-300",
  info: "bg-slate-100 text-slate-700 ring-1 ring-slate-300",
};
export const SEVERITY_COLORS: Record<string, string> = { critical: "#b91c1c", high: "#ea580c", medium: "#d97706", low: "#0284c7", info: "#64748b" };

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEV[severity] ?? SEV.info}`}>{severity}</span>;
}

const DEC: Record<string, string> = {
  PASS: "bg-emerald-100 text-emerald-900 ring-emerald-300", WARN: "bg-amber-100 text-amber-900 ring-amber-300", FAIL: "bg-red-100 text-red-900 ring-red-300",
};
export function DecisionBadge({ decision, large }: { decision: Decision | null | undefined; large?: boolean }) {
  if (!decision) return <span className="text-sm text-slate-500">pending</span>;
  const mark = decision === "PASS" ? "✓" : decision === "WARN" ? "!" : "✕";
  return (
    <span className={`inline-flex items-center gap-1 rounded-full font-bold ring-1 ${DEC[decision]} ${large ? "px-4 py-1.5 text-lg" : "px-2.5 py-0.5 text-xs"}`}>
      <span aria-hidden>{mark}</span>{decision}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const bad = ["failed", "timeout", "missing", "cancelled"].includes(status);
  const good = ["completed", "succeeded"].includes(status);
  return <span className={`rounded px-2 py-0.5 text-xs font-medium ${bad ? "bg-red-50 text-red-800" : good ? "bg-emerald-50 text-emerald-800" : "bg-slate-100 text-slate-700"}`}>{status}</span>;
}

export function Card({ title, children, actions, className = "" }: { title?: ReactNode; children: ReactNode; actions?: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-slate-200 bg-white shadow-sm ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-2 border-b border-slate-100 px-4 py-3">
          <h2 className="text-sm font-semibold text-slate-800">{title}</h2>{actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Button({ variant = "primary", className = "", ...p }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" }) {
  const v = { primary: "bg-indigo-600 text-white hover:bg-indigo-700", secondary: "bg-white text-slate-800 ring-1 ring-slate-300 hover:bg-slate-50", danger: "bg-red-600 text-white hover:bg-red-700" }[variant];
  return <button {...p} className={`rounded-md px-3 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 ${v} ${className}`} />;
}

export const Spinner = ({ label = "Loading…" }: { label?: string }) => (
  <div role="status" className="flex items-center gap-2 p-6 text-sm text-slate-500">
    <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-indigo-600" />{label}
  </div>
);

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-center justify-between gap-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
      <span>{message}</span>{onRetry && <Button variant="secondary" onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export const Empty = ({ children }: { children: ReactNode }) => (
  <div className="rounded-md border border-dashed border-slate-300 p-6 text-center text-sm text-slate-500">{children}</div>
);

export function Stat({ label, value, tone, hint }: { label: string; value: ReactNode; tone?: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`mt-1 text-2xl font-bold ${tone ?? "text-slate-900"}`}>{value}</div>
      {hint && <div className="mt-0.5 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function Pager({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (o: number) => void }) {
  if (total <= limit) return null;
  return (
    <div className="mt-3 flex items-center justify-between text-sm text-slate-600">
      <span>{offset + 1}–{Math.min(offset + limit, total)} of {total}</span>
      <div className="flex gap-2">
        <Button variant="secondary" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</Button>
        <Button variant="secondary" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</Button>
      </div>
    </div>
  );
}

export const Table = ({ children }: { children: ReactNode }) => (
  <div className="overflow-x-auto"><table className="min-w-full text-left text-sm">{children}</table></div>
);
export const Th = ({ children }: { children?: ReactNode }) => <th scope="col" className="whitespace-nowrap px-3 py-2 text-xs font-semibold uppercase tracking-wide text-slate-500">{children}</th>;
export const Td = ({ children, className = "" }: { children?: ReactNode; className?: string }) => <td className={`px-3 py-2 align-top ${className}`}>{children}</td>;
export const Mono = ({ children }: { children: ReactNode }) => <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs">{children}</code>;
