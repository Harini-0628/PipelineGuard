import type {
  AuditEvent, Finding, FindingDetail, IntegrationStatus, Overview, Page, Policy, PolicyDoc, PolicyVersion, Project, Repository,
  RepositoryCreated, Scan, ScanDetail, TrendPoint, User, Evaluation,
} from "./types";

const BASE = "/api/v1";
const TOKEN_KEY = "pg_token";

/** The access token lives in sessionStorage (cleared when the tab closes). Trade-off documented in README. */
export const tokenStore = {
  get: () => sessionStorage.getItem(TOKEN_KEY),
  set: (t: string) => sessionStorage.setItem(TOKEN_KEY, t),
  clear: () => sessionStorage.removeItem(TOKEN_KEY),
};

export class ApiError extends Error {
  constructor(public status: number, message: string, public requestId?: string) {
    super(message);
  }
}

let onUnauthorized: () => void = () => {};
export const setUnauthorizedHandler = (fn: () => void) => { onUnauthorized = fn; };

function messageFrom(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => (typeof d === "object" && d && "msg" in d ? `${(d as { loc?: string[] }).loc?.join(".") ?? ""}: ${(d as { msg: string }).msg}` : String(d))).join("; ");
  return "Request failed";
}

async function request<T>(method: string, path: string, body?: unknown, params?: Record<string, string | number | undefined | null>): Promise<T> {
  const qs = params ? "?" + new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => [k, String(v)])).toString() : "";
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = tokenStore.get();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}${qs}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError(0, "Cannot reach the PipelineGuard API. Check your connection and that the backend is running.");
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* non-JSON error body */ }
  if (!res.ok) {
    if (res.status === 401 && path !== "/auth/login") onUnauthorized();
    const d = data as { detail?: unknown; request_id?: string } | null;
    throw new ApiError(res.status, messageFrom(d?.detail ?? res.statusText), d?.request_id);
  }
  return (data ?? text) as T;
}

export async function download(path: string, filename: string): Promise<void> {
  const res = await fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${tokenStore.get() ?? ""}` } });
  if (!res.ok) throw new ApiError(res.status, "Download failed");
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

type P = Record<string, string | number | undefined | null>;
export const api = {
  login: (email: string, password: string) => request<{ access_token: string }>("POST", "/auth/login", { email, password }),
  me: () => request<User>("GET", "/auth/me"),
  projects: () => request<Project[]>("GET", "/projects"),
  createProject: (name: string, description = "") => request<Project>("POST", "/projects", { name, description }),
  repositories: (p?: P) => request<Page<Repository>>("GET", "/repositories", undefined, p),
  repository: (id: string) => request<Repository>("GET", `/repositories/${id}`),
  registerRepository: (b: { project_id: string; full_name: string; ci_provider: string; default_branch: string; criticality: string; internet_facing: boolean }) =>
    request<RepositoryCreated>("POST", "/repositories", b),
  rotateToken: (id: string) => request<RepositoryCreated>("POST", `/repositories/${id}/rotate-token`),
  scans: (p?: P) => request<Page<Scan>>("GET", "/scans", undefined, p),
  scan: (id: string) => request<ScanDetail>("GET", `/scans/${id}`),
  reevaluate: (id: string) => request<unknown>("POST", `/scans/${id}/reevaluate`),
  findings: (p?: P) => request<Page<Finding>>("GET", "/findings", undefined, p),
  finding: (id: string) => request<FindingDetail>("GET", `/findings/${id}`),
  setFindingStatus: (id: string, status: "open" | "acknowledged", note = "") => request<Finding>("PATCH", `/findings/${id}/status`, { status, note }),
  suppress: (id: string, reason: string, expires_at: string) => request<{ id: string }>("POST", `/findings/${id}/suppressions`, { reason, expires_at }),
  revokeSuppression: (id: string, sid: string) => request<void>("DELETE", `/findings/${id}/suppressions/${sid}`),
  policies: () => request<Policy[]>("GET", "/policies"),
  policyVersions: (id: string) => request<PolicyVersion[]>("GET", `/policies/${id}/versions`),
  newPolicyVersion: (id: string, document: PolicyDoc, change_note: string) => request<Policy>("POST", `/policies/${id}/versions`, { document, change_note }),
  createPolicy: (name: string, project_id: string | null, document: PolicyDoc, change_note: string) => request<Policy>("POST", "/policies", { name, project_id, document, change_note }),
  previewPolicy: (id: string, scan_id: string, document?: PolicyDoc) => request<Evaluation>("POST", `/policies/${id}/preview`, { scan_id, document }),
  overview: (window_days = 30) => request<Overview>("GET", "/dashboard/overview", undefined, { window_days }),
  trends: (days = 30) => request<{ points: TrendPoint[] }>("GET", "/dashboard/trends", undefined, { days }),
  integrations: () => request<IntegrationStatus>("GET", "/integrations/status"),
  refreshKev: () => request<{ ok: boolean; error?: string; count: number }>("POST", "/integrations/kev/refresh"),
  audit: (p?: P) => request<{ items: AuditEvent[]; total: number }>("GET", "/audit", undefined, p),
};
