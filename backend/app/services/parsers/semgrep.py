"""Parse Semgrep `--json` output."""
from __future__ import annotations

import json
import re
from typing import Any

from app.services.normalize import NormalizedFinding, ParsedReport, ParseError, assign_fingerprints

_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low", "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_CWE_RE = re.compile(r"CWE-\d+")


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def parse(raw: Any) -> ParsedReport:
    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ParseError(f"semgrep report is not valid JSON: {e}") from e
    if not isinstance(raw, dict) or not isinstance(raw.get("results"), list):
        raise ParseError("semgrep report missing 'results' list")
    findings: list[NormalizedFinding] = []
    for i, r in enumerate(raw["results"]):
        try:
            extra = r.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            cwes = sorted({m for c in _as_list(meta.get("cwe")) for m in _CWE_RE.findall(str(c))})
            sev_raw = str(extra.get("severity", "INFO")).upper()
            refs = [str(x) for x in _as_list(meta.get("references"))]
            lines = extra.get("lines")
            snippet = lines if isinstance(lines, str) and lines != "requires login" else None
            findings.append(NormalizedFinding(
                scanner="semgrep",
                scanner_finding_id=str(r["check_id"]),
                category="sast",
                title=str(r["check_id"]).rsplit(".", 1)[-1].replace("-", " "),
                description=str(extra.get("message", "")),
                severity=_SEV.get(sev_raw, "medium"),
                scanner_severity=sev_raw,
                confidence=str(meta["confidence"]).lower() if meta.get("confidence") else None,
                cwe=cwes,
                file_path=str(r["path"]),
                line=int(r["start"]["line"]),
                references=refs,
                remediation=str(extra.get("fix") or extra.get("message", "")),
                evidence={"start": r.get("start"), "end": r.get("end"), "snippet": snippet,
                          "semgrep_fingerprint": extra.get("fingerprint")},
            ))
        except (KeyError, TypeError, ValueError) as e:
            raise ParseError(f"semgrep result #{i} malformed: {e!r}") from e
    errors = [e for e in raw.get("errors", []) if isinstance(e, dict)]
    fatal = [e for e in errors if str(e.get("level", "")).lower() == "error"]
    warnings = [f"{e.get('type', 'error')}: {str(e.get('message', ''))[:200]}" for e in errors]
    incomplete = None
    if fatal:
        incomplete = f"semgrep reported {len(fatal)} error-level problem(s); results may be incomplete"
    return ParsedReport(assign_fingerprints(findings), str(raw.get("version") or "") or None, warnings, incomplete)
