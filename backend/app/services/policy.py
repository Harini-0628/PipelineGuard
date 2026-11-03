"""Deterministic, explainable policy engine.

`evaluate()` is a pure function: identical inputs (including `evaluated_at`, which only affects suppression
expiry and the reported timestamp) always yield an identical result. It performs no I/O.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
KNOWN_SCANNERS = {"semgrep", "trivy", "trivy-image"}


class EnvPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mandatory_scanners: list[str] = Field(default_factory=lambda: ["semgrep", "trivy"])
    max_critical: int = Field(default=0, ge=0)
    max_high: int = Field(default=0, ge=0)
    warn_medium_above: int = Field(default=0, ge=0)
    fail_on_known_exploited: bool = True
    fail_on_secrets: bool = True

    @field_validator("mandatory_scanners")
    @classmethod
    def _scanners(cls, v: list[str]) -> list[str]:
        unknown = set(v) - KNOWN_SCANNERS
        if unknown:
            raise ValueError(f"unknown scanner(s): {sorted(unknown)}")
        return sorted(set(v))


class BranchMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pattern: str = Field(min_length=1, max_length=200)
    environment: str


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    description: str = ""
    default_environment: str = "production"
    branch_environments: list[BranchMapping] = Field(default_factory=list)
    environments: dict[str, EnvPolicy]

    @model_validator(mode="after")
    def _refs(self) -> PolicyDocument:
        if not self.environments:
            raise ValueError("at least one environment must be defined")
        names = set(self.environments)
        if self.default_environment not in names:
            raise ValueError(f"default_environment '{self.default_environment}' is not defined")
        for m in self.branch_environments:
            if m.environment not in names:
                raise ValueError(f"branch mapping '{m.pattern}' references undefined environment '{m.environment}'")
        return self


def load_policy_yaml(text: str) -> PolicyDocument:
    return PolicyDocument.model_validate(yaml.safe_load(text))


def resolve_environment(doc: PolicyDocument, branch: str, base_branch: str | None = None) -> str:
    target = base_branch or branch
    for m in doc.branch_environments:
        if fnmatch.fnmatchcase(target, m.pattern):
            return m.environment
    return doc.default_environment


@dataclass(frozen=True)
class EvalFinding:
    id: str
    fingerprint: str
    severity: str
    category: str
    title: str
    scanner: str
    known_exploited: bool | None = None
    location: str = ""


@dataclass(frozen=True)
class EvalSuppression:
    id: str
    fingerprint: str
    reason: str
    expires_at: datetime
    revoked: bool = False


@dataclass
class EvalInput:
    branch: str
    base_branch: str | None
    executions: dict[str, str]  # scanner -> execution status
    findings: list[EvalFinding]
    suppressions: list[EvalSuppression] = field(default_factory=list)
    evaluated_at: datetime | None = None


def _ref(f: EvalFinding) -> dict[str, Any]:
    return {"finding_id": f.id, "fingerprint": f.fingerprint, "severity": f.severity, "title": f.title,
            "scanner": f.scanner, "category": f.category, "location": f.location}


def _sorted(fs: list[EvalFinding]) -> list[EvalFinding]:
    return sorted(fs, key=lambda f: (SEV_RANK.get(f.severity, 9), f.fingerprint, f.id))


def evaluate(doc: PolicyDocument, inp: EvalInput, policy_name: str, policy_version: int) -> dict[str, Any]:
    assert inp.evaluated_at is not None, "evaluated_at must be supplied by the caller"
    now = inp.evaluated_at
    env_name = resolve_environment(doc, inp.branch, inp.base_branch)
    env = doc.environments[env_name]

    by_fp = {s.fingerprint: s for s in sorted(inp.suppressions, key=lambda s: (s.fingerprint, s.id)) if not s.revoked}
    active: list[EvalFinding] = []
    applied: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    for f in _sorted(inp.findings):
        s = by_fp.get(f.fingerprint)
        if s is not None and s.expires_at > now:
            applied.append({"finding_id": f.id, "fingerprint": f.fingerprint, "severity": f.severity, "title": f.title,
                            "suppression_id": s.id, "reason": s.reason, "expires_at": s.expires_at.isoformat()})
        else:
            if s is not None:
                expired.append({"finding_id": f.id, "fingerprint": f.fingerprint, "suppression_id": s.id,
                                "expired_at": s.expires_at.isoformat()})
            active.append(f)

    rules: list[dict[str, Any]] = []

    def add(rid: str, name: str, effect: str, triggered: bool, explanation: str, fs: list[EvalFinding] | None = None,
            threshold: int | None = None, count: int | None = None, extra: dict[str, Any] | None = None) -> None:
        rules.append({"id": rid, "name": name, "effect": effect, "triggered": triggered, "threshold": threshold,
                      "count": count, "explanation": explanation, "findings": [_ref(f) for f in _sorted(fs or [])],
                      **(extra or {})})

    # PG-001: mandatory scanners must have run successfully. Missing results are NEVER treated as clean.
    problems: list[dict[str, str]] = []
    for sc in env.mandatory_scanners:
        st = inp.executions.get(sc)
        if st is None:
            problems.append({"scanner": sc, "status": "not_run", "reason": f"{sc} results were not submitted"})
        elif st != "succeeded":
            problems.append({"scanner": sc, "status": st, "reason": f"{sc} execution ended with status '{st}'"})
    add("PG-001", "Mandatory scanners completed", "FAIL", bool(problems),
        ("Mandatory scanner check failed: " + "; ".join(p["reason"] for p in problems) + ". Missing results are not treated as a clean scan.")
        if problems else f"All mandatory scanners succeeded ({', '.join(env.mandatory_scanners) or 'none required'}).",
        extra={"problems": problems})

    def of(sev: str) -> list[EvalFinding]:
        return [f for f in active if f.severity == sev]

    crit, high, med, low = of("critical"), of("high"), of("medium"), of("low")
    add("PG-002", "Critical findings", "FAIL", len(crit) > env.max_critical,
        f"{len(crit)} active critical finding(s); policy allows at most {env.max_critical}.", crit, env.max_critical, len(crit))
    add("PG-003", "High findings", "FAIL", len(high) > env.max_high,
        f"{len(high)} active high finding(s); policy allows at most {env.max_high}.", high, env.max_high, len(high))
    kev = [f for f in active if f.known_exploited is True]
    add("PG-004", "Known exploited vulnerabilities", "FAIL", env.fail_on_known_exploited and bool(kev),
        (f"{len(kev)} finding(s) are flagged as known exploited." if kev else "No active finding is flagged as known exploited. "
         "Absence of a flag means 'not known', not 'safe'.") if env.fail_on_known_exploited else "Rule disabled for this environment.",
        kev if env.fail_on_known_exploited else [], None, len(kev))
    secrets = [f for f in active if f.category == "secret"]
    add("PG-005", "Committed secrets", "FAIL", env.fail_on_secrets and bool(secrets),
        (f"{len(secrets)} possible secret(s) detected." if secrets else "No secrets detected by the scanners that ran.")
        if env.fail_on_secrets else "Rule disabled for this environment.", secrets if env.fail_on_secrets else [], None, len(secrets))
    add("PG-006", "Medium findings", "WARN", len(med) > env.warn_medium_above,
        f"{len(med)} active medium finding(s); warning threshold is {env.warn_medium_above}.", med, env.warn_medium_above, len(med))
    optional_failed = [{"scanner": sc, "status": st} for sc, st in sorted(inp.executions.items())
                       if sc not in env.mandatory_scanners and st != "succeeded"]
    add("PG-007", "Optional scanners completed", "WARN", bool(optional_failed),
        ("Optional scanner(s) did not succeed: " + ", ".join(f"{p['scanner']} ({p['status']})" for p in optional_failed))
        if optional_failed else "No optional scanner failures.", extra={"problems": optional_failed})
    add("PG-008", "Low and informational findings", "NONE", False,
        f"{len(low)} low finding(s) are allowed and reported.", low, None, len(low))

    if any(r["triggered"] and r["effect"] == "FAIL" for r in rules):
        decision = "FAIL"
    elif any(r["triggered"] and r["effect"] == "WARN" for r in rules):
        decision = "WARN"
    else:
        decision = "PASS"

    triggered = [r for r in rules if r["triggered"]]
    counts = {s: len([f for f in active if f.severity == s]) for s in SEV_RANK}
    summary = (f"{decision}: " + ("; ".join(f"{r['id']} {r['name']}" for r in triggered) if triggered else "no rules triggered")
               + f" (environment: {env_name}, policy: {policy_name} v{policy_version})")
    return {
        "decision": decision,
        "policy": {"name": policy_name, "version": policy_version},
        "environment": env_name,
        "evaluated_at": now.isoformat(),
        "summary": summary,
        "rules": rules,
        "mandatory_checks": {"required": env.mandatory_scanners, "missing_or_failed": problems},
        "counts": {"active_by_severity": counts, "active_total": len(active), "suppressed": len(applied)},
        "suppressions_applied": applied,
        "suppressions_expired": expired,
    }
