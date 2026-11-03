"""Transparent baseline risk score (0-100). This is a heuristic, NOT machine learning, and it is
independent of the scanner severity and of the policy decision (policy never reads this score).

score = severity_base + exploitability + exposure + asset_importance + fix_availability, capped at 100
  severity_base : critical 50, high 38, medium 24, low 10, info 2
  exploitability: +30 if listed in CISA KEV; else +round(EPSS*20,1) if EPSS known; else +0 (recorded as missing)
  exposure      : +8 internet-facing repository, +4 production environment (cumulative)
  asset         : criticality low 0, medium 3, high 6, critical 10
  fix           : +4 when a fixed version exists (cheap to remediate => prioritize)
Missing intelligence adds 0 and is listed under `missing`; it is never read as "safe".
"""
from __future__ import annotations

from typing import Any

SEVERITY_BASE = {"critical": 50, "high": 38, "medium": 24, "low": 10, "info": 2}
ASSET = {"low": 0, "medium": 3, "high": 6, "critical": 10}
WEIGHTS = {"severity": SEVERITY_BASE, "kev": 30, "epss_max": 20, "internet_facing": 8, "production": 4, "asset": ASSET, "fix": 4}


def score(severity: str, *, known_exploited: bool | None, epss: float | None, internet_facing: bool,
          environment: str, criticality: str, fixed_version: str | None) -> tuple[float, dict[str, Any]]:
    parts: dict[str, float] = {"severity": float(SEVERITY_BASE.get(severity, 2))}
    missing: list[str] = []
    if known_exploited is True:
        parts["exploitability_kev"] = 30.0
    elif epss is not None:
        parts["exploitability_epss"] = round(max(0.0, min(1.0, epss)) * 20, 1)
    if known_exploited is None:
        missing.append("kev")
    if epss is None:
        missing.append("epss")
    parts["exposure"] = (8.0 if internet_facing else 0.0) + (4.0 if environment == "production" else 0.0)
    parts["asset_importance"] = float(ASSET.get(criticality, 3))
    parts["fix_available"] = 4.0 if fixed_version else 0.0
    total = round(min(100.0, sum(parts.values())), 1)
    return total, {"components": parts, "missing": missing, "formula": "see app/services/risk.py", "capped_at": 100}
