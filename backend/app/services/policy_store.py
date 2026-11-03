"""Policy persistence helpers: resolution, seeding, and building evaluation inputs from stored data."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    Finding, Policy, PolicyEvaluation, PolicyVersion, Scan, ScanFinding, ScannerExecution, Suppression,
)
from app.services.policy import (
    EvalFinding, EvalInput, EvalSuppression, PolicyDocument, evaluate, load_policy_yaml,
)


def seed_default_policy(db: Session) -> Policy:
    existing = db.scalar(select(Policy).where(Policy.project_id.is_(None), Policy.is_active.is_(True)))
    if existing:
        return existing
    path = Path(get_settings().default_policy_path)
    doc = load_policy_yaml(path.read_text())
    pol = Policy(name="default", project_id=None, is_active=True, current_version=1)
    db.add(pol)
    db.flush()
    db.add(PolicyVersion(policy_id=pol.id, version=1, document=doc.model_dump(mode="json"),
                         change_note="Seeded from policies/default.yaml"))
    db.commit()
    return pol


def effective_policy(db: Session, project_id: str) -> tuple[Policy, PolicyVersion, PolicyDocument]:
    pol = db.scalar(select(Policy).where(Policy.project_id == project_id, Policy.is_active.is_(True))
                    .order_by(Policy.created_at.desc()))
    if pol is None:
        pol = db.scalar(select(Policy).where(Policy.project_id.is_(None), Policy.is_active.is_(True))
                        .order_by(Policy.created_at.desc()))
    if pol is None:
        pol = seed_default_policy(db)
    ver = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == pol.id, PolicyVersion.version == pol.current_version))
    assert ver is not None
    return pol, ver, PolicyDocument.model_validate(ver.document)


def build_eval_input(db: Session, scan: Scan, now: datetime) -> EvalInput:
    rows = db.execute(
        select(Finding, ScanFinding).join(ScanFinding, ScanFinding.finding_id == Finding.id).where(ScanFinding.scan_id == scan.id)
    ).all()
    findings = [EvalFinding(id=f.id, fingerprint=f.fingerprint, severity=sf.severity, category=f.category, title=f.title,
                            scanner=f.scanner, known_exploited=f.known_exploited,
                            location=(f"{f.file_path}:{f.line}" if f.file_path and f.line else (f.file_path or f.resource or "")) +
                                     (f" [{f.package_name} {f.installed_version}]" if f.package_name else ""))
                for f, sf in rows]
    sups = db.scalars(select(Suppression).where(Suppression.repository_id == scan.repository_id)).all()
    execs = db.scalars(select(ScannerExecution).where(ScannerExecution.scan_id == scan.id)).all()
    return EvalInput(
        branch=scan.branch, base_branch=scan.base_branch,
        executions={e.scanner: e.status for e in execs},
        findings=findings,
        suppressions=[EvalSuppression(id=s.id, fingerprint=s.fingerprint, reason=s.reason,
                                      expires_at=s.expires_at.astimezone(UTC), revoked=s.revoked_at is not None) for s in sups],
        evaluated_at=now,
    )


def evaluate_and_store(db: Session, scan: Scan, project_id: str) -> PolicyEvaluation:
    pol, ver, doc = effective_policy(db, project_id)
    now = datetime.now(UTC)
    result = evaluate(doc, build_eval_input(db, scan, now), pol.name, ver.version)
    result["policy"]["id"] = pol.id
    scan.environment = result["environment"]
    scan.decision = result["decision"]
    ev = db.scalar(select(PolicyEvaluation).where(PolicyEvaluation.scan_id == scan.id))
    if ev is None:
        ev = PolicyEvaluation(scan_id=scan.id, policy_id=pol.id, policy_name=pol.name, policy_version=ver.version,
                              decision=result["decision"], result=result, evaluated_at=now)
        db.add(ev)
    else:
        ev.policy_id, ev.policy_name, ev.policy_version = pol.id, pol.name, ver.version
        ev.decision, ev.result, ev.evaluated_at = result["decision"], result, now
    return ev


def resolve_environment_for(doc: PolicyDocument, scan: Scan) -> str:
    from app.services.policy import resolve_environment
    return resolve_environment(doc, scan.branch, scan.base_branch)
