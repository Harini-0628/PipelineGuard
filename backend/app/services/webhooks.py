"""Outbound webhook notifications with SSRF protection. Delivery never follows redirects."""
from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import IntegrationConfig, Repository, Scan
from app.services.ssrf import UnsafeURL, validate_outbound_url


def deliver(db: Session, cfg: IntegrationConfig, payload: dict[str, Any], *, client: httpx.Client | None = None) -> None:
    cfg.last_attempt_at = datetime.now(UTC)
    own = client is None
    try:
        validate_outbound_url(cfg.url)  # re-validate at send time (config may predate a DNS change)
        client = client or httpx.Client(timeout=10, follow_redirects=False)
        r = client.post(cfg.url, json=payload, headers={"User-Agent": "PipelineGuard-Webhook/1"})
        cfg.last_status = "ok" if r.status_code < 300 else f"http_{r.status_code}"
        cfg.last_error = None if r.status_code < 300 else f"receiver returned HTTP {r.status_code}"
    except (UnsafeURL, httpx.HTTPError, socket.gaierror) as e:
        cfg.last_status, cfg.last_error = "error", f"{type(e).__name__}: {str(e)[:300]}"
    finally:
        if own and client is not None:
            client.close()
    db.commit()


def notify_scan(db: Session, scan: Scan, repo: Repository) -> None:
    from app.config import get_settings
    cfgs = db.scalars(select(IntegrationConfig).where(
        IntegrationConfig.kind == "webhook", IntegrationConfig.enabled.is_(True),
        (IntegrationConfig.project_id == repo.project_id) | (IntegrationConfig.project_id.is_(None)))).all()
    payload = {"event": "scan.completed", "repository": repo.full_name, "branch": scan.branch, "commit": scan.commit_sha,
               "decision": scan.decision, "scan_id": scan.id, "url": f"{get_settings().public_base_url.rstrip('/')}/scans/{scan.id}"}
    for cfg in cfgs:
        if scan.decision in (cfg.notify_on or []):
            deliver(db, cfg, payload)
