"""Common finding schema produced by scanner parsers, plus stable fingerprinting."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")


class ParseError(Exception):
    """Raised when a scanner report is malformed or not the expected format."""


@dataclass
class NormalizedFinding:
    scanner: str
    scanner_finding_id: str
    category: str  # sast | dependency | container | misconfig | secret
    title: str
    severity: str
    description: str = ""
    scanner_severity: str | None = None
    confidence: str | None = None
    vuln_id: str | None = None
    cwe: list[str] = field(default_factory=list)
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    file_path: str | None = None
    line: int | None = None
    resource: str | None = None  # lockfile/image/target the finding was reported against
    references: list[str] = field(default_factory=list)
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""


@dataclass
class ParsedReport:
    findings: list[NormalizedFinding]
    tool_version: str | None = None
    warnings: list[str] = field(default_factory=list)
    incomplete_reason: str | None = None  # set => execution must not count as a clean success


def _h(*parts: object) -> str:
    return hashlib.sha256("\x1f".join("" if p is None else str(p) for p in parts).encode()).hexdigest()


def _identity_key(f: NormalizedFinding) -> tuple[str, ...]:
    """Identity excluding the occurrence index. Line numbers are deliberately NOT used for
    SAST/secret findings so that unrelated edits above a finding do not make it look new."""
    if f.category == "dependency" or (f.category == "container" and f.package_name):
        return (f.scanner, f.category, f.vuln_id or f.scanner_finding_id, f.resource or "", f.package_name or "", f.installed_version or "")
    if f.category == "misconfig":
        return (f.scanner, f.category, f.scanner_finding_id, f.resource or "", f.file_path or "")
    return (f.scanner, f.category, f.scanner_finding_id, f.file_path or "")


def assign_fingerprints(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Assign stable fingerprints. Findings sharing an identity key (e.g. two hits of the same rule in one
    file) are disambiguated by their order of appearance by line, not by the line number itself."""
    groups: dict[tuple[str, ...], list[NormalizedFinding]] = defaultdict(list)
    for f in findings:
        groups[_identity_key(f)].append(f)
    for key, items in groups.items():
        items.sort(key=lambda x: (x.line or 0, x.title))
        for idx, f in enumerate(items):
            f.fingerprint = _h(*key, idx)
    return findings
