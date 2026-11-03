from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import accessible_project_ids, require_roles
from app.models import AuditEvent, Role, User

router = APIRouter(tags=["audit"])


@router.get("/audit")
def list_audit(action: str | None = None, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
               db: Session = Depends(get_db), user: User = Depends(require_roles(Role.ADMIN, Role.SECURITY_ENGINEER))):
    q = select(AuditEvent)
    ids = accessible_project_ids(db, user)
    if ids is not None:  # security engineers see only events for their own projects
        q = q.where(AuditEvent.project_id.in_(ids))
    if action:
        q = q.where(AuditEvent.action.like(f"{action}%"))
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.scalars(q.order_by(AuditEvent.created_at.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "limit": limit, "offset": offset,
            "items": [{"id": e.id, "at": e.created_at.isoformat(), "actor": e.actor, "action": e.action, "target_type": e.target_type,
                       "target_id": e.target_id, "project_id": e.project_id, "details": e.details} for e in rows]}


__all__ = ["router", "or_"]
