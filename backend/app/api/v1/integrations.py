from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.deps import client_ip, current_user, ensure_project_access, require_roles
from app.models import IntegrationConfig, Repository, Role, ScannerExecution, User
from app.schemas import IntegrationOut, WebhookCreate
from app.services import audit, kev
from app.services.ssrf import UnsafeURL, validate_outbound_url

router = APIRouter(tags=["integrations"])


def _redact(url: str) -> str:
    """Webhook URLs often embed secrets in the path; show only scheme://host/…"""
    from urllib.parse import urlsplit
    p = urlsplit(url)
    return f"{p.scheme}://{p.hostname}/…" if p.path not in ("", "/") else f"{p.scheme}://{p.hostname}"


def _out(c: IntegrationConfig) -> IntegrationOut:
    o = IntegrationOut.model_validate(c)
    o.url = _redact(c.url)
    return o


@router.get("/integrations/status")
def status(db: Session = Depends(get_db), user: User = Depends(current_user)):
    s = get_settings()
    scanners = []
    for name in ("semgrep", "trivy", "trivy-image"):
        last = db.scalar(select(ScannerExecution).where(ScannerExecution.scanner == name).order_by(ScannerExecution.started_at.desc().nullslast()).limit(1))
        counts = dict(db.execute(select(ScannerExecution.status, func.count()).where(ScannerExecution.scanner == name)
                                 .group_by(ScannerExecution.status)).all())
        scanners.append({"scanner": name, "last_version": last.version if last else None, "last_status": last.status if last else None,
                         "last_run_at": last.started_at.isoformat() if last and last.started_at else None, "executions_by_status": counts,
                         "last_error": last.error if last and last.status != "succeeded" else None})
    providers = dict(db.execute(select(Repository.ci_provider, func.count()).group_by(Repository.ci_provider)).all())
    hooks = db.scalars(select(IntegrationConfig).order_by(IntegrationConfig.created_at)).all()
    return {
        "scanners": scanners,
        "ci_providers": [{"provider": k, "repositories": v, "integration": "github-actions (implemented)" if k == "github" else
                          "gitlab-ci (documented example, not live-tested)" if k == "gitlab" else "generic ingest API"} for k, v in providers.items()],
        "notifications": [_out(h).model_dump(mode="json") for h in hooks],
        "enrichment": {"cisa_kev": kev.status(db)},
        "config": {"environment": s.environment, "cors_origins": s.cors_origin_list, "ingest_rate_per_minute": s.ingest_rate_per_minute,
                   "max_body_bytes": s.max_body_bytes, "jwt_secret_configured": True, "seed_demo_data": s.seed_demo_data,
                   "store_raw_reports": s.store_raw_reports, "public_base_url": s.public_base_url},
    }


@router.post("/integrations/webhooks", response_model=IntegrationOut, status_code=201)
def create_webhook(body: WebhookCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles(Role.ADMIN))):
    try:
        validate_outbound_url(body.url)
    except UnsafeURL as e:
        raise HTTPException(422, f"Unsafe webhook URL: {e}") from None
    if body.project_id:
        ensure_project_access(db, user, body.project_id)
    c = IntegrationConfig(kind="webhook", name=body.name, url=body.url, project_id=body.project_id, notify_on=list(body.notify_on),
                          enabled=body.enabled)
    db.add(c)
    db.flush()
    audit.record(db, actor=user.email, action="integration.created", target_type="integration", target_id=c.id, project_id=c.project_id,
                 details={"name": c.name, "host": _redact(c.url)}, ip=client_ip(request))
    db.commit()
    return _out(c)


@router.delete("/integrations/{integration_id}", status_code=204)
def delete_integration(integration_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles(Role.ADMIN))):
    c = db.get(IntegrationConfig, integration_id)
    if c is None:
        raise HTTPException(404, "Integration not found")
    db.delete(c)
    audit.record(db, actor=user.email, action="integration.deleted", target_type="integration", target_id=integration_id, ip=client_ip(request))
    db.commit()


@router.post("/integrations/kev/refresh")
def refresh_kev(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles(Role.ADMIN))):
    result = kev.refresh(db)
    audit.record(db, actor=user.email, action="integration.kev_refresh", details={k: v for k, v in result.items() if k != "retrieved_at"},
                 ip=client_ip(request))
    db.commit()
    return result
