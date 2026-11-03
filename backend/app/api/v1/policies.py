from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import accessible_project_ids, client_ip, current_user, ensure_project_access, ensure_repo_access, require_roles
from app.models import Policy, PolicyVersion, Role, Scan, User
from app.schemas import PolicyCreate, PolicyNewVersion, PolicyOut, PolicyPreviewRequest, PolicyVersionOut
from app.services import audit, policy_store
from app.services.policy import PolicyDocument, evaluate

router = APIRouter(tags=["policies"])
WRITERS = (Role.ADMIN, Role.SECURITY_ENGINEER)


def _validate(doc: dict) -> PolicyDocument:
    try:
        return PolicyDocument.model_validate(doc)
    except ValidationError as e:
        raise HTTPException(422, [{"loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]) from None


def _out(db: Session, p: Policy) -> PolicyOut:
    v = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == p.id, PolicyVersion.version == p.current_version))
    assert v is not None
    return PolicyOut(id=p.id, name=p.name, project_id=p.project_id, is_active=p.is_active, current_version=p.current_version,
                     created_at=p.created_at, document=v.document)


def _access(db: Session, user: User, p: Policy) -> None:
    if p.project_id is None:
        return  # global policies are readable by everyone authenticated; writes are admin-only (checked by callers)
    ensure_project_access(db, user, p.project_id)


def _can_write(user: User, p: Policy) -> None:
    if p.project_id is None and user.role != Role.ADMIN.value:
        raise HTTPException(403, "Only administrators may change global policies")


@router.get("/policies", response_model=list[PolicyOut])
def list_policies(db: Session = Depends(get_db), user: User = Depends(current_user)):
    ids = accessible_project_ids(db, user)
    q = select(Policy).order_by(Policy.created_at)
    if ids is not None:
        q = q.where((Policy.project_id.is_(None)) | (Policy.project_id.in_(ids)))
    return [_out(db, p) for p in db.scalars(q)]


@router.post("/policies", response_model=PolicyOut, status_code=201)
def create_policy(body: PolicyCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles(*WRITERS))):
    doc = _validate(body.document)
    if body.project_id is None and user.role != Role.ADMIN.value:
        raise HTTPException(403, "Only administrators may create global policies")
    if body.project_id:
        ensure_project_access(db, user, body.project_id)
    # a newly created policy becomes the active one for its scope; deactivate the previous one
    for old in db.scalars(select(Policy).where(Policy.project_id == body.project_id if body.project_id else Policy.project_id.is_(None),
                                               Policy.is_active.is_(True))):
        old.is_active = False
    p = Policy(name=body.name, project_id=body.project_id, current_version=1, is_active=True)
    db.add(p)
    db.flush()
    db.add(PolicyVersion(policy_id=p.id, version=1, document=doc.model_dump(mode="json"), change_note=body.change_note, created_by=user.id))
    audit.record(db, actor=user.email, action="policy.created", target_type="policy", target_id=p.id, project_id=p.project_id,
                 details={"name": p.name, "note": body.change_note}, ip=client_ip(request))
    db.commit()
    return _out(db, p)


@router.get("/policies/{policy_id}", response_model=PolicyOut)
def get_policy(policy_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    p = db.get(Policy, policy_id)
    if p is None:
        raise HTTPException(404, "Policy not found")
    _access(db, user, p)
    return _out(db, p)


@router.get("/policies/{policy_id}/versions", response_model=list[PolicyVersionOut])
def versions(policy_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    p = db.get(Policy, policy_id)
    if p is None:
        raise HTTPException(404, "Policy not found")
    _access(db, user, p)
    return db.scalars(select(PolicyVersion).where(PolicyVersion.policy_id == p.id).order_by(PolicyVersion.version.desc())).all()


@router.post("/policies/{policy_id}/versions", response_model=PolicyOut, status_code=201)
def new_version(policy_id: str, body: PolicyNewVersion, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_roles(*WRITERS))):
    p = db.get(Policy, policy_id)
    if p is None:
        raise HTTPException(404, "Policy not found")
    _access(db, user, p)
    _can_write(user, p)
    doc = _validate(body.document)
    last = max(v.version for v in p.versions)
    db.add(PolicyVersion(policy_id=p.id, version=last + 1, document=doc.model_dump(mode="json"), change_note=body.change_note,
                         created_by=user.id))
    p.current_version = last + 1
    audit.record(db, actor=user.email, action="policy.versioned", target_type="policy", target_id=p.id, project_id=p.project_id,
                 details={"from_version": last, "to_version": last + 1, "note": body.change_note}, ip=client_ip(request))
    db.commit()
    return _out(db, p)


@router.post("/policies/{policy_id}/preview")
def preview(policy_id: str, body: PolicyPreviewRequest, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Evaluate a draft (or the current version) against a stored scan WITHOUT persisting or enforcing anything."""
    p = db.get(Policy, policy_id)
    if p is None:
        raise HTTPException(404, "Policy not found")
    _access(db, user, p)
    scan = db.get(Scan, body.scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    ensure_repo_access(db, user, scan.repository_id)
    if body.document is not None:
        doc, version = _validate(body.document), p.current_version + 1
    else:
        v = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == p.id, PolicyVersion.version == p.current_version))
        assert v is not None
        doc, version = PolicyDocument.model_validate(v.document), v.version
    result = evaluate(doc, policy_store.build_eval_input(db, scan, datetime.now(UTC)), p.name, version)
    result["preview"] = True
    result["previous_decision"] = scan.decision
    return result
