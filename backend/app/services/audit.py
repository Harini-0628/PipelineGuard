from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditEvent


def record(db: Session, *, actor: str, action: str, target_type: str = "", target_id: str = "",
           project_id: str | None = None, details: dict[str, Any] | None = None, ip: str | None = None) -> AuditEvent:
    ev = AuditEvent(actor=actor, action=action, target_type=target_type, target_id=target_id, project_id=project_id,
                    details=details or {}, ip=ip)
    db.add(ev)
    return ev
