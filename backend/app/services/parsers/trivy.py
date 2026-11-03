"""Parse Trivy `--format json` output (fs, image, config, secret scanners)."""
from __future__ import annotations

import json
from typing import Any

from app.services.normalize import NormalizedFinding, ParsedReport, ParseError, assign_fingerprints

_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}


def _sev(v: Any) -> str:
    return _SEV.get(str(v).upper(), "info")


def _refs(v: dict[str, Any]) -> list[str]:
    out = [str(x) for x in (v.get("References") or [])]
    primary = v.get("PrimaryURL")
    if primary and primary not in out:
        out.insert(0, str(primary))
    return out


def parse(raw: Any) -> ParsedReport:
    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ParseError(f"trivy report is not valid JSON: {e}") from e
    if not isinstance(raw, dict) or "SchemaVersion" not in raw:
        raise ParseError("trivy report missing 'SchemaVersion'; not a Trivy JSON report")
    results = raw.get("Results")
    if results is None:
        results = []  # Trivy omits Results when nothing was found
    if not isinstance(results, list):
        raise ParseError("trivy 'Results' must be a list")
    is_image = raw.get("ArtifactType") == "container_image"
    findings: list[NormalizedFinding] = []
    for res in results:
        try:
            target = str(res.get("Target", ""))
            klass = str(res.get("Class", ""))
            for v in res.get("Vulnerabilities") or []:
                container = is_image or klass == "os-pkgs" and is_image
                fixed = v.get("FixedVersion")
                vid = str(v["VulnerabilityID"])
                findings.append(NormalizedFinding(
                    scanner="trivy", scanner_finding_id=vid,
                    category="container" if container else "dependency",
                    title=str(v.get("Title") or f"{vid} in {v.get('PkgName')}"),
                    description=str(v.get("Description", "")),
                    severity=_sev(v.get("Severity")), scanner_severity=str(v.get("Severity", "")),
                    vuln_id=vid, cwe=[str(c) for c in (v.get("CweIDs") or [])],
                    package_name=str(v["PkgName"]), installed_version=str(v.get("InstalledVersion", "")) or None,
                    fixed_version=str(fixed) if fixed else None, resource=target,
                    file_path=None if container else target,
                    references=_refs(v),
                    remediation=(f"Upgrade {v['PkgName']} to {fixed}" if fixed else
                                 f"No fixed version published for {v['PkgName']}; consider mitigation or an alternative package"),
                    evidence={"status": v.get("Status"), "pkg_path": v.get("PkgPath"), "layer": v.get("Layer"),
                              "cvss": v.get("CVSS"), "data_source": v.get("DataSource"),
                              "published": v.get("PublishedDate")},
                ))
            for m in res.get("Misconfigurations") or []:
                if str(m.get("Status", "FAIL")).upper() != "FAIL":
                    continue
                cause = m.get("CauseMetadata") or {}
                findings.append(NormalizedFinding(
                    scanner="trivy", scanner_finding_id=str(m["ID"]),
                    category="misconfig", title=str(m.get("Title", m["ID"])),
                    description=str(m.get("Message") or m.get("Description", "")),
                    severity=_sev(m.get("Severity")), scanner_severity=str(m.get("Severity", "")),
                    file_path=target, line=cause.get("StartLine") or None,
                    resource=str(cause.get("Resource") or target) or None,
                    references=_refs(m), remediation=str(m.get("Resolution", "")),
                    evidence={"type": m.get("Type"), "namespace": m.get("Namespace"), "provider": cause.get("Provider"),
                              "service": cause.get("Service"), "start_line": cause.get("StartLine"),
                              "end_line": cause.get("EndLine")},
                ))
            for s in res.get("Secrets") or []:
                findings.append(NormalizedFinding(
                    scanner="trivy", scanner_finding_id=str(s["RuleID"]),
                    category="secret", title=str(s.get("Title", s["RuleID"])),
                    description=f"Possible {s.get('Category', 'secret')} committed to {target}",
                    severity=_sev(s.get("Severity")), scanner_severity=str(s.get("Severity", "")),
                    file_path=target, line=s.get("StartLine") or None,
                    remediation="Revoke and rotate the credential, remove it from history, and load it from a secret manager.",
                    # Never persist the matched secret value itself.
                    evidence={"category": s.get("Category"), "start_line": s.get("StartLine"), "end_line": s.get("EndLine")},
                ))
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise ParseError(f"trivy result malformed: {e!r}") from e
    version = (raw.get("Trivy") or {}).get("Version") if isinstance(raw.get("Trivy"), dict) else None
    return ParsedReport(assign_fingerprints(findings), version)
