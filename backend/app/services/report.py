"""Deterministic JSON and Markdown report generation from stored data."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Finding, PolicyEvaluation, Repository, Scan, ScanFinding, ScannerExecution
from app.services.policy import SEV_RANK

MARKER = "<!-- pipelineguard-report -->"


def severity_counts(db: Session, scan_id: str, only_new: bool = False) -> dict[str, int]:
    q = select(ScanFinding.severity).where(ScanFinding.scan_id == scan_id)
    if only_new:
        q = q.where(ScanFinding.new_state == "new")
    out = {s: 0 for s in SEV_RANK}
    for sev in db.scalars(q):
        out[sev] = out.get(sev, 0) + 1
    return out


def build_json_report(db: Session, scan: Scan) -> dict[str, Any]:
    repo = db.get(Repository, scan.repository_id)
    assert repo is not None
    ev = db.scalar(select(PolicyEvaluation).where(PolicyEvaluation.scan_id == scan.id))
    execs = db.scalars(select(ScannerExecution).where(ScannerExecution.scan_id == scan.id).order_by(ScannerExecution.scanner)).all()
    rows = list(db.execute(select(Finding, ScanFinding).join(ScanFinding, ScanFinding.finding_id == Finding.id)
                           .where(ScanFinding.scan_id == scan.id)).all())
    rows.sort(key=lambda r: (SEV_RANK.get(r[1].severity, 9), -r[0].risk_score, r[0].fingerprint))
    limitations: list[str] = []
    for e in execs:
        if e.status != "succeeded":
            limitations.append(f"{e.scanner} did not complete successfully ({e.status}); its results are missing or partial.")
    if not execs:
        limitations.append("No scanner executions were recorded.")
    limitations.append("Risk scores are a transparent heuristic; absent EPSS/KEV data is recorded as unknown, not as safe.")
    return {
        "report_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "repository": {"id": repo.id, "full_name": repo.full_name, "ci_provider": repo.ci_provider},
        "scan": {"id": scan.id, "commit_sha": scan.commit_sha, "branch": scan.branch, "base_branch": scan.base_branch,
                 "pr_number": scan.pr_number, "build_id": scan.build_id, "environment": scan.environment, "status": scan.status,
                 "created_at": scan.created_at.isoformat(), "finished_at": scan.finished_at.isoformat() if scan.finished_at else None},
        "scanner_executions": [{"scanner": e.scanner, "scan_mode": e.scan_mode, "status": e.status, "exit_code": e.exit_code,
                                "version": e.version, "duration_ms": e.duration_ms, "error": e.error,
                                "parse_error": e.parse_error, "findings_count": e.findings_count,
                                "report_sha256": e.report_sha256} for e in execs],
        "policy_decision": ev.result if ev else None,
        "severity_counts": severity_counts(db, scan.id),
        "findings": [{"id": f.id, "fingerprint": f.fingerprint, "scanner": f.scanner, "scanner_finding_id": f.scanner_finding_id,
                      "category": f.category, "title": f.title, "severity": sf.severity, "state_vs_base": sf.new_state,
                      "vuln_id": f.vuln_id, "cwe": f.cwe, "package": f.package_name, "installed_version": f.installed_version,
                      "fixed_version": f.fixed_version, "file_path": f.file_path, "line": sf.line, "resource": f.resource,
                      "known_exploited": f.known_exploited, "risk_score": f.risk_score, "risk_factors": f.risk_factors,
                      "remediation": f.remediation, "references": f.references} for f, sf in rows],
        "limitations": limitations,
    }


def _loc(f: dict[str, Any]) -> str:
    if f["package"]:
        return f"`{f['package']}` {f['installed_version'] or ''}" + (f" → fix: {f['fixed_version']}" if f["fixed_version"] else " (no fix published)")
    if f["file_path"]:
        return f"`{f['file_path']}" + (f":{f['line']}" if f["line"] else "") + "`"
    return f"`{f['resource'] or '-'}`"


def build_markdown(report: dict[str, Any], *, max_items: int = 10) -> str:
    dec = report["policy_decision"] or {}
    decision = dec.get("decision", "UNKNOWN")
    icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}.get(decision, "❔")
    sc, scan, repo = report["severity_counts"], report["scan"], report["repository"]
    url = f"{get_settings().public_base_url.rstrip('/')}/scans/{scan['id']}"
    lines = [MARKER, f"<!-- pipelineguard-commit:{scan['commit_sha']} -->", f"## {icon} PipelineGuard: {decision}", "",
             f"**{repo['full_name']}** · `{scan['branch']}` · `{scan['commit_sha'][:10]}` · environment `{scan['environment']}`", "",
             dec.get("summary", ""), "",
             "| Critical | High | Medium | Low | Info |", "|---|---|---|---|---|",
             f"| {sc.get('critical', 0)} | {sc.get('high', 0)} | {sc.get('medium', 0)} | {sc.get('low', 0)} | {sc.get('info', 0)} |", ""]
    problems = (dec.get("mandatory_checks") or {}).get("missing_or_failed", [])
    if problems:
        lines += ["### Scanner problems", *[f"- **{p['scanner']}**: {p['reason']}" for p in problems], ""]
    trig = [r for r in dec.get("rules", []) if r["triggered"]]
    if trig:
        lines += ["### Rules triggered", *[f"- `{r['id']}` **{r['name']}** ({r['effect']}): {r['explanation']}" for r in trig], ""]
    new = [f for f in report["findings"] if f["state_vs_base"] == "new"]
    if new:
        lines += [f"### Newly introduced findings ({len(new)})"]
        lines += [f"- **{f['severity'].upper()}** {f['title']} — {_loc(f)}" for f in new[:max_items]]
        lines.append("")
    top = [f for f in report["findings"] if f["severity"] in ("critical", "high")][:max_items]
    if top:
        lines += ["### Top blocking-severity findings"]
        for f in top:
            lines.append(f"- **{f['severity'].upper()}** {f['title']} ({f['scanner']}:{f['scanner_finding_id']}) — {_loc(f)}")
            if f["remediation"]:
                lines.append(f"  - Remediation: {f['remediation'][:240]}")
        lines.append("")
    if report["limitations"]:
        lines += ["<details><summary>Limitations</summary>", "", *[f"- {x}" for x in report["limitations"]], "", "</details>", ""]
    lines.append(f"[Full report]({url})")
    return "\n".join(lines)
