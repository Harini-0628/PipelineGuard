"""Scan ingestion: parse -> normalize -> upsert findings -> resolve -> enrich/score -> evaluate policy.

The whole operation runs in one transaction under a per-repository advisory lock, so concurrent submissions
for the same repository are serialized and cannot interleave finding upserts or decisions.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    ExecStatus, Finding, FindingStatus, Repository, Scan, ScanFinding, ScannerExecution, ScanStatus, new_id,
)
from app.schemas import IngestRequest, ScannerSubmission
from app.services import audit, kev, policy_store, risk
from app.services.normalize import NormalizedFinding, ParseError
from app.services.parsers import parse_report


def derive_idempotency_key(req: IngestRequest) -> str:
    h = hashlib.sha256()
    h.update(f"{req.commit_sha}|{req.branch}|{req.build_id or ''}".encode())
    for s in sorted(req.scanners, key=lambda x: x.scanner):
        h.update(f"|{s.scanner}|{s.status}|{_report_hash(s.report)}".encode())
    return "auto:" + h.hexdigest()[:40]


def _report_hash(report: object) -> str:
    if report is None:
        return ""
    return hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _lock_repo(db: Session, repo_id: str) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": f"repo:{repo_id}"})


def get_or_create_scan(db: Session, repo: Repository, *, key: str, commit_sha: str, branch: str, base_branch: str | None,
                       pr_number: int | None, build_id: str | None, status: ScanStatus) -> tuple[Scan, bool]:
    existing = db.scalar(select(Scan).where(Scan.repository_id == repo.id, Scan.idempotency_key == key))
    if existing:
        return existing, False
    scan = Scan(repository_id=repo.id, idempotency_key=key, commit_sha=commit_sha.lower(), branch=branch, base_branch=base_branch,
                pr_number=pr_number, build_id=build_id, status=status.value, started_at=datetime.now(UTC))
    db.add(scan)
    try:
        db.flush()
    except IntegrityError:  # lost a race with a concurrent identical submission
        db.rollback()
        existing = db.scalar(select(Scan).where(Scan.repository_id == repo.id, Scan.idempotency_key == key))
        assert existing is not None
        return existing, False
    return scan, True


def _record_execution(scan: Scan, sub: ScannerSubmission) -> tuple[ScannerExecution, list[NormalizedFinding]]:
    status = ExecStatus(sub.status)
    ex = ScannerExecution(scan_id=scan.id, scanner=sub.scanner, scan_mode=sub.scan_mode, exit_code=sub.exit_code, version=sub.version,
                          started_at=sub.started_at, finished_at=sub.finished_at, error=sub.error, stderr_tail=sub.stderr_tail,
                          report_sha256=_report_hash(sub.report) or None)
    if sub.started_at and sub.finished_at:
        ex.duration_ms = max(0, int((sub.finished_at - sub.started_at).total_seconds() * 1000))
    findings: list[NormalizedFinding] = []
    if status == ExecStatus.SUCCEEDED:
        if sub.report is None:
            status, ex.error = ExecStatus.FAILED, "scanner reported success but no machine-readable report was provided"
        else:
            try:
                parsed = parse_report(sub.scanner, sub.report)
                findings = parsed.findings
                ex.version = ex.version or parsed.tool_version
                if parsed.warnings:
                    ex.stderr_tail = ((ex.stderr_tail or "") + "\n[parser warnings]\n" + "\n".join(parsed.warnings))[-8000:]
                if parsed.incomplete_reason:
                    status, ex.error = ExecStatus.FAILED, parsed.incomplete_reason
            except ParseError as e:
                status, ex.parse_error, ex.error = ExecStatus.FAILED, str(e)[:2000], f"report could not be parsed: {e}"[:2000]
                findings = []
    ex.status = status.value
    ex.findings_count = len(findings)
    if get_settings().store_raw_reports and sub.report is not None:
        ex.raw_report = sub.report
    return ex, findings


def ingest_results(db: Session, repo: Repository, scan: Scan, submissions: list[ScannerSubmission], *, actor: str,
                   ip: str | None = None) -> Scan:
    _lock_repo(db, repo.id)
    db.refresh(scan)
    now = datetime.now(UTC)
    for old in list(scan.executions):
        db.delete(old)
    db.flush()

    _, _, doc = policy_store.effective_policy(db, repo.project_id)
    env = policy_store.resolve_environment_for(doc, scan)

    all_findings: list[tuple[ScannerExecution, NormalizedFinding]] = []
    execs: list[ScannerExecution] = []
    for sub in submissions:
        ex, fs = _record_execution(scan, sub)
        db.add(ex)
        execs.append(ex)
        all_findings.extend((ex, f) for f in fs)
    db.flush()

    base_branch = scan.base_branch or repo.default_branch
    on_base = scan.branch == base_branch
    base_open: set[str] | None = None
    if not on_base:
        had_base_scan = db.scalar(select(Scan.id).where(Scan.repository_id == repo.id, Scan.branch == base_branch,
                                                        Scan.id != scan.id, Scan.status.in_(["completed", "failed"])).limit(1))
        if had_base_scan:
            base_open = set(db.scalars(select(Finding.fingerprint).where(
                Finding.repository_id == repo.id, Finding.branch == base_branch, Finding.status != FindingStatus.RESOLVED.value)))

    fps = [f.fingerprint for _, f in all_findings]
    existing = {f.fingerprint: f for f in db.scalars(select(Finding).where(
        Finding.repository_id == repo.id, Finding.branch == scan.branch, Finding.fingerprint.in_(fps)))} if fps else {}
    intel = kev.lookup(db, {f.vuln_id for _, f in all_findings if f.vuln_id})

    for old_sf in db.scalars(select(ScanFinding).where(ScanFinding.scan_id == scan.id)):
        db.delete(old_sf)
    db.flush()

    seen_by_scanner: dict[str, set[str]] = {}
    for ex, nf in all_findings:
        seen_by_scanner.setdefault(ex.scanner, set()).add(nf.fingerprint)
        kev_flag = intel.get(nf.vuln_id.upper()) if nf.vuln_id else None
        score, factors = risk.score(nf.severity, known_exploited=kev_flag, epss=None, internet_facing=repo.internet_facing,
                                    environment=env, criticality=repo.criticality, fixed_version=nf.fixed_version)
        row = existing.get(nf.fingerprint)
        first_time = row is None
        if row is None:
            row = Finding(id=new_id(), repository_id=repo.id, project_id=repo.project_id, branch=scan.branch, fingerprint=nf.fingerprint,
                          scanner=ex.scanner, scanner_finding_id=nf.scanner_finding_id, category=nf.category, title=nf.title[:500],
                          severity=nf.severity, first_seen_at=now, first_seen_scan_id=scan.id)
            db.add(row)
        elif row.status == FindingStatus.RESOLVED.value:
            row.status, row.resolved_at = FindingStatus.OPEN.value, None  # regression: reopened
            audit.record(db, actor=actor, action="finding.reopened", target_type="finding", target_id=row.id,
                         project_id=repo.project_id, details={"scan_id": scan.id}, ip=ip)
        row.title, row.description, row.severity, row.scanner_severity = nf.title[:500], nf.description, nf.severity, nf.scanner_severity
        row.confidence, row.vuln_id, row.cwe = nf.confidence, nf.vuln_id, nf.cwe
        row.package_name, row.installed_version, row.fixed_version = nf.package_name, nf.installed_version, nf.fixed_version
        row.file_path, row.line, row.resource = nf.file_path, nf.line, nf.resource
        row.references, row.remediation, row.evidence = nf.references, nf.remediation, nf.evidence
        row.known_exploited, row.risk_score, row.risk_factors = kev_flag, score, factors
        row.last_seen_at, row.last_seen_scan_id = now, scan.id
        if on_base:
            state = "new" if first_time else "existing"
        elif base_open is None:
            state = "unknown"
        else:
            state = "existing" if nf.fingerprint in base_open else "new"
        db.add(ScanFinding(scan_id=scan.id, finding_id=row.id, fingerprint=nf.fingerprint, severity=nf.severity, line=nf.line,
                           is_new=state == "new", new_state=state, risk_score=score))
    db.flush()

    # Resolve findings that disappeared, only for scanners that completed successfully in this scan.
    for ex in execs:
        if ex.status != ExecStatus.SUCCEEDED.value:
            continue
        seen = seen_by_scanner.get(ex.scanner, set())
        stale = db.scalars(select(Finding).where(
            Finding.repository_id == repo.id, Finding.branch == scan.branch, Finding.scanner == ex.scanner,
            Finding.status.in_([FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value])))
        for f in stale:
            if f.fingerprint not in seen:
                f.status, f.resolved_at = FindingStatus.RESOLVED.value, now
                audit.record(db, actor="system", action="finding.resolved", target_type="finding", target_id=f.id,
                             project_id=repo.project_id, details={"scan_id": scan.id, "scanner": ex.scanner})

    all_ok = all(e.status == ExecStatus.SUCCEEDED.value for e in execs)
    scan.status = (ScanStatus.COMPLETED if all_ok else ScanStatus.FAILED).value
    scan.finished_at = now
    policy_store.evaluate_and_store(db, scan, repo.project_id)
    audit.record(db, actor=actor, action="scan.ingested", target_type="scan", target_id=scan.id, project_id=repo.project_id,
                 details={"decision": scan.decision, "status": scan.status, "commit": scan.commit_sha, "branch": scan.branch}, ip=ip)
    db.commit()
    return scan
