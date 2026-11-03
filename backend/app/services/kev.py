"""Optional CISA KEV enrichment with a database cache. Failure is non-fatal and never changes
existing data: an unreachable feed yields 'unknown', not 'not exploited'."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import VulnIntel

SOURCE = "kev"


def refresh(db: Session, *, client: httpx.Client | None = None) -> dict[str, Any]:
    url = get_settings().kev_feed_url
    own = client is None
    client = client or httpx.Client(timeout=20, follow_redirects=False)
    try:
        resp = client.get(url)
        resp.raise_for_status()
        payload = resp.json()
        vulns = payload["vulnerabilities"]
        if not isinstance(vulns, list):
            raise ValueError("unexpected KEV schema")
    except (httpx.HTTPError, KeyError, ValueError) as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}", "count": 0}
    finally:
        if own:
            client.close()
    now = datetime.now(UTC)
    db.execute(delete(VulnIntel).where(VulnIntel.source == SOURCE))
    for v in vulns:
        cve = str(v.get("cveID", "")).upper()
        if cve:
            db.add(VulnIntel(cve_id=cve, source=SOURCE, retrieved_at=now,
                             data={"dateAdded": v.get("dateAdded"), "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse"),
                                   "catalogVersion": payload.get("catalogVersion")}))
    db.commit()
    return {"ok": True, "count": len(vulns), "retrieved_at": now.isoformat()}


def lookup(db: Session, cve_ids: set[str]) -> dict[str, bool | None]:
    """True = listed in KEV. False = feed is loaded and CVE not listed. None = feed never loaded (unknown)."""
    cves = {c.upper() for c in cve_ids if c.upper().startswith("CVE-")}
    if not cves:
        return {}
    loaded = (db.scalar(select(func.count()).select_from(VulnIntel).where(VulnIntel.source == SOURCE)) or 0) > 0
    if not loaded:
        return {c: None for c in cves}
    listed = set(db.scalars(select(VulnIntel.cve_id).where(VulnIntel.source == SOURCE, VulnIntel.cve_id.in_(cves))))
    return {c: (c in listed) for c in cves}


def status(db: Session) -> dict[str, Any]:
    n = db.scalar(select(func.count()).select_from(VulnIntel).where(VulnIntel.source == SOURCE)) or 0
    last = db.scalar(select(func.max(VulnIntel.retrieved_at)).where(VulnIntel.source == SOURCE))
    return {"loaded": n > 0, "entries": n, "retrieved_at": last.isoformat() if last else None}
