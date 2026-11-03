from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.deps import (
    accessible_project_ids, active_suppression_clause, client_ip, current_user, ensure_repo_access, require_roles,
)
from app.models import AuditEvent, Finding, FindingStatus, Role, ScanFinding, Suppression, User
from app.schemas import FindingDetail, FindingOut, FindingStatusUpdate, Page, SuppressionCreate
from app.services import audit
from app.services.policy import SEV_RANK

router = APIRouter(tags=["findings"])
WRITERS = (Role.ADMIN, Role.SECURITY_ENGINEER)


def _active_sups(db: Session, findings: list[Finding]) -> dict[tuple[str, str], Suppression]:
    if not findings:
        return {}
    now = datetime.now(UTC)
    rows = db.scalars(select(Suppression).where(
        Suppression.repository_id.in_({f.repository_id for f in findings}), Suppression.fingerprint.in_({f.fingerprint for f in findings}),
        Suppression.revoked_at.is_(None), Suppression.expires_at > now)).all()
    return {(s.repository_id, s.fingerprint): s for s in rows}


def _effective(f: Finding, sups: dict[tuple[str, str], Suppression]) -> str:
    if f.status == FindingStatus.RESOLVED.value:
        return f.status
    return FindingStatus.SUPPRESSED.value if (f.repository_id, f.fingerprint) in sups else f.status


def _get_finding(db: Session, user: User, finding_id: str) -> Finding:
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(404, "Finding not found")
    ensure_repo_access(db, user, f.repository_id)
    return f


@router.get("/findings", response_model=Page[FindingOut])
def list_findings(repository_id: str | None = None, scan_id: str | None = None, branch: str | None = None,
                  severity: str | None = None, status: str | None = None, scanner: str | None = None, category: str | None = None,
                  q: str | None = Query(None, max_length=200), sort: str = Query("risk", pattern="^(risk|severity|last_seen|first_seen)$"),
                  limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0), db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    ids = accessible_project_ids(db, user)
    stmt = select(Finding)
    if ids is not None:
        stmt = stmt.where(Finding.project_id.in_(ids))
    if repository_id:
        ensure_repo_access(db, user, repository_id)
        stmt = stmt.where(Finding.repository_id == repository_id)
    if scan_id:
        stmt = stmt.where(Finding.id.in_(select(ScanFinding.finding_id).where(ScanFinding.scan_id == scan_id)))
    for col, val in ((Finding.branch, branch), (Finding.severity, severity), (Finding.scanner, scanner), (Finding.category, category)):
        if val:
            stmt = stmt.where(col == val)
    if status == FindingStatus.SUPPRESSED.value:
        stmt = stmt.where(Finding.status != FindingStatus.RESOLVED.value, active_suppression_clause())
    elif status:
        stmt = stmt.where(Finding.status == status, ~active_suppression_clause()) if status != "resolved" else stmt.where(Finding.status == status)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Finding.title.ilike(like), Finding.file_path.ilike(like), Finding.package_name.ilike(like),
                              Finding.vuln_id.ilike(like), Finding.scanner_finding_id.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    sev_case = case(SEV_RANK, value=Finding.severity, else_=9)
    order = {"risk": [Finding.risk_score.desc(), Finding.id], "severity": [sev_case, Finding.risk_score.desc(), Finding.id],
             "last_seen": [Finding.last_seen_at.desc(), Finding.id], "first_seen": [Finding.first_seen_at.desc(), Finding.id]}[sort]
    rows = db.scalars(stmt.order_by(*order).limit(limit).offset(offset)).all()
    sups = _active_sups(db, list(rows))
    items = []
    for f in rows:
        o = FindingOut.model_validate(f)
        o.effective_status = _effective(f, sups)
        items.append(o)
    return Page[FindingOut](items=items, total=total, limit=limit, offset=offset)


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    f = _get_finding(db, user, finding_id)
    sups = _active_sups(db, [f])
    s = sups.get((f.repository_id, f.fingerprint))
    hist = db.scalars(select(AuditEvent).where(AuditEvent.target_type == "finding", AuditEvent.target_id == f.id)
                      .order_by(AuditEvent.created_at)).all()
    d = FindingDetail.model_validate(f)
    d.effective_status = _effective(f, sups)
    d.suppression = ({"id": s.id, "reason": s.reason, "expires_at": s.expires_at.isoformat(), "created_by": s.created_by} if s else None)
    d.history = [{"at": e.created_at.isoformat(), "actor": e.actor, "action": e.action, "details": e.details} for e in hist]
    return d


@router.patch("/findings/{finding_id}/status", response_model=FindingOut)
def set_status(finding_id: str, body: FindingStatusUpdate, request: Request, db: Session = Depends(get_db),
               user: User = Depends(require_roles(*WRITERS))):
    f = _get_finding(db, user, finding_id)
    if f.status == FindingStatus.RESOLVED.value:
        raise HTTPException(409, "Resolved findings are managed by scans")
    old, f.status = f.status, body.status
    audit.record(db, actor=user.email, action="finding.status_changed", target_type="finding", target_id=f.id, project_id=f.project_id,
                 details={"from": old, "to": body.status, "note": body.note}, ip=client_ip(request))
    db.commit()
    o = FindingOut.model_validate(f)
    o.effective_status = _effective(f, _active_sups(db, [f]))
    return o


@router.post("/findings/{finding_id}/suppressions", status_code=201)
def suppress(finding_id: str, body: SuppressionCreate, request: Request, db: Session = Depends(get_db),
             user: User = Depends(require_roles(*WRITERS))):
    f = _get_finding(db, user, finding_id)
    now = datetime.now(UTC)
    exp = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=UTC)
    if exp <= now:
        raise HTTPException(422, "expires_at must be in the future")
    if exp > now + timedelta(days=get_settings().suppression_max_days):
        raise HTTPException(422, f"suppressions may last at most {get_settings().suppression_max_days} days")
    if f.severity == "critical" and user.role != Role.ADMIN.value:
        raise HTTPException(403, "Only administrators may suppress critical findings")
    s = Suppression(repository_id=f.repository_id, fingerprint=f.fingerprint, reason=body.reason, created_by=user.id, expires_at=exp)
    db.add(s)
    db.flush()
    audit.record(db, actor=user.email, action="finding.suppressed", target_type="finding", target_id=f.id, project_id=f.project_id,
                 details={"suppression_id": s.id, "reason": body.reason, "expires_at": exp.isoformat(), "severity": f.severity},
                 ip=client_ip(request))
    db.commit()
    return {"id": s.id, "finding_id": f.id, "expires_at": exp.isoformat()}


@router.delete("/findings/{finding_id}/suppressions/{suppression_id}", status_code=204)
def revoke(finding_id: str, suppression_id: str, request: Request, db: Session = Depends(get_db),
           user: User = Depends(require_roles(*WRITERS))):
    f = _get_finding(db, user, finding_id)
    s = db.get(Suppression, suppression_id)
    if s is None or s.repository_id != f.repository_id or s.fingerprint != f.fingerprint:
        raise HTTPException(404, "Suppression not found")
    if s.revoked_at is None:
        s.revoked_at, s.revoked_by = datetime.now(UTC), user.id
        audit.record(db, actor=user.email, action="finding.suppression_revoked", target_type="finding", target_id=f.id,
                     project_id=f.project_id, details={"suppression_id": s.id}, ip=client_ip(request))
        db.commit()
