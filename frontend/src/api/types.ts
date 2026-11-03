export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Decision = "PASS" | "WARN" | "FAIL";
export type Role = "admin" | "security_engineer" | "developer";

export interface User { id: string; email: string; full_name: string; role: Role; is_active: boolean }
export interface Project { id: string; name: string; description: string }
export interface Page<T> { items: T[]; total: number; limit: number; offset: number }

export interface LatestScan { id: string; status: string; decision: Decision | null; branch: string; commit_sha: string; created_at: string }
export interface Repository {
  id: string; project_id: string; full_name: string; ci_provider: string; default_branch: string; criticality: string;
  internet_facing: boolean; ingest_token_prefix: string; created_at: string;
  latest_scan?: LatestScan | null; open_findings?: Record<string, number>;
}
export interface RepositoryCreated extends Repository { ingest_token: string }

export interface Scan {
  id: string; repository_id: string; repository: string | null; commit_sha: string; branch: string; base_branch: string | null;
  pr_number: number | null; build_id: string | null; environment: string; status: string; decision: Decision | null;
  created_at: string; started_at: string | null; finished_at: string | null;
}
export interface Execution {
  scanner: string; scan_mode: string; status: string; exit_code: number | null; version: string | null; duration_ms: number | null;
  error: string | null; stderr_tail: string | null; parse_error: string | null; findings_count: number;
}
export interface RuleResult {
  id: string; name: string; effect: string; triggered: boolean; threshold: number | null; count: number | null; explanation: string;
  findings: { finding_id: string; severity: Severity; title: string; scanner: string; location: string }[];
}
export interface Evaluation {
  decision: Decision; summary: string; environment: string; evaluated_at: string; policy: { name: string; version: number };
  rules: RuleResult[]; mandatory_checks: { required: string[]; missing_or_failed: { scanner: string; status: string; reason: string }[] };
  counts: { active_by_severity: Record<string, number>; active_total: number; suppressed: number };
  suppressions_applied: { finding_id: string; title: string; reason: string; expires_at: string }[];
  suppressions_expired: { finding_id: string; expired_at: string }[];
  preview?: boolean; previous_decision?: Decision | null;
}
export interface ScanDetail extends Scan {
  executions: Execution[]; evaluation: Evaluation | null; severity_counts: Record<string, number>; new_counts: Record<string, number>;
}
export interface Finding {
  id: string; repository_id: string; branch: string; scanner: string; scanner_finding_id: string; category: string; title: string;
  severity: Severity; confidence: string | null; vuln_id: string | null; package_name: string | null; installed_version: string | null;
  fixed_version: string | null; file_path: string | null; line: number | null; known_exploited: boolean | null; risk_score: number;
  status: string; effective_status: string; first_seen_at: string; last_seen_at: string;
}
export interface FindingDetail extends Finding {
  description: string; scanner_severity: string | null; cwe: string[]; references: string[]; remediation: string;
  evidence: Record<string, unknown>; resource: string | null; epss: number | null;
  risk_factors: { components?: Record<string, number>; missing?: string[] };
  fingerprint: string; resolved_at: string | null;
  suppression: { id: string; reason: string; expires_at: string; created_by: string } | null;
  history: { at: string; actor: string; action: string; details: Record<string, unknown> }[];
}
export interface Overview {
  window_days: number; repositories: number; scans: { total: number; window: number }; open_findings: Record<string, number>;
  suppressed_findings: number; decisions: Record<Decision, number>; pass_rate: number | null; new_in_window: number;
  resolved_in_window: number;
  recent_scans: { id: string; repository: string; branch: string; commit_sha: string; status: string; decision: Decision | null; created_at: string }[];
  recent_failures: Overview["recent_scans"];
  top_remediation: { id: string; title: string; severity: Severity; risk_score: number; repository: string; package: string | null;
    fixed_version: string | null; file_path: string | null; remediation: string }[];
}
export interface TrendPoint { date: string; scans: number; PASS: number; WARN: number; FAIL: number; new: number; resolved: number; risk: number }
export interface PolicyDoc {
  schema_version: 1; description?: string; default_environment: string;
  branch_environments: { pattern: string; environment: string }[]; environments: Record<string, Record<string, unknown>>;
}
export interface Policy { id: string; name: string; project_id: string | null; is_active: boolean; current_version: number; document: PolicyDoc }
export interface PolicyVersion { version: number; document: PolicyDoc; change_note: string; created_by: string | null; created_at: string }
export interface IntegrationStatus {
  scanners: { scanner: string; last_version: string | null; last_status: string | null; last_run_at: string | null;
    executions_by_status: Record<string, number>; last_error: string | null }[];
  ci_providers: { provider: string; repositories: number; integration: string }[];
  notifications: { id: string; name: string; url: string; enabled: boolean; notify_on: string[]; last_status: string | null; last_error: string | null; last_attempt_at: string | null }[];
  enrichment: { cisa_kev: { loaded: boolean; entries: number; retrieved_at: string | null } };
  config: Record<string, unknown>;
}
export interface AuditEvent { id: string; at: string; actor: string; action: string; target_type: string; target_id: string; details: Record<string, unknown> }
