from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.services import risk
from app.services.policy import (
    EvalFinding, EvalInput, EvalSuppression, PolicyDocument, evaluate, load_policy_yaml, resolve_environment,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
DOC = load_policy_yaml((Path(__file__).resolve().parents[2] / "policies" / "default.yaml").read_text())
OK = {"semgrep": "succeeded", "trivy": "succeeded"}


def f(i, sev, **kw):
    return EvalFinding(id=f"id{i}", fingerprint=f"fp{i}", severity=sev, category=kw.pop("category", "dependency"), title=f"t{i}",
                       scanner="trivy", **kw)


def run(findings, execs=OK, branch="main", base=None, sups=(), doc=DOC):
    return evaluate(doc, EvalInput(branch=branch, base_branch=base, executions=dict(execs), findings=list(findings),
                                   suppressions=list(sups), evaluated_at=NOW), "default", 1)


def rule(res, rid):
    return next(r for r in res["rules"] if r["id"] == rid)


def test_clean_scan_passes():
    r = run([])
    assert r["decision"] == "PASS" and not [x for x in r["rules"] if x["triggered"]]


def test_critical_fails_and_names_the_finding():
    r = run([f(1, "critical")])
    assert r["decision"] == "FAIL" and rule(r, "PG-002")["findings"][0]["finding_id"] == "id1"
    assert "critical" in rule(r, "PG-002")["explanation"]


def test_high_threshold_by_environment():
    highs = [f(i, "high") for i in range(3)]
    assert run(highs, branch="main")["decision"] == "FAIL"          # production: 0 allowed
    assert run(highs, branch="release/1.0")["decision"] == "PASS"   # staging: 3 allowed (mediums 0)
    assert run(highs + [f(9, "high")], branch="release/1.0")["decision"] == "FAIL"


def test_medium_warns_and_low_allowed():
    assert run([f(1, "medium")])["decision"] == "WARN"
    r = run([f(1, "low"), f(2, "info")])
    assert r["decision"] == "PASS" and rule(r, "PG-008")["count"] == 1


def test_missing_mandatory_scanner_fails_even_with_zero_findings():
    r = run([], execs={"semgrep": "succeeded"})
    assert r["decision"] == "FAIL" and r["mandatory_checks"]["missing_or_failed"][0]["status"] == "not_run"
    assert "not treated as a clean scan" in rule(r, "PG-001")["explanation"]


@pytest.mark.parametrize("status", ["failed", "timeout", "missing", "skipped"])
def test_failed_mandatory_scanner_fails(status):
    r = run([], execs={"semgrep": "succeeded", "trivy": status})
    assert r["decision"] == "FAIL" and status in rule(r, "PG-001")["explanation"]


def test_optional_scanner_failure_warns():
    r = run([], execs={**OK, "trivy-image": "failed"})
    assert r["decision"] == "WARN" and rule(r, "PG-007")["triggered"]


def test_known_exploited_fails_even_when_medium():
    r = run([f(1, "medium", known_exploited=True)], branch="feature/x")
    assert r["decision"] == "FAIL" and rule(r, "PG-004")["triggered"]


def test_unknown_exploitability_is_not_treated_as_safe_or_unsafe():
    r = run([f(1, "low", known_exploited=None)])
    assert r["decision"] == "PASS" and "not known" in rule(r, "PG-004")["explanation"]


def test_secret_fails_regardless_of_severity():
    r = run([f(1, "low", category="secret")], branch="feature/x")
    assert r["decision"] == "FAIL" and rule(r, "PG-005")["triggered"]


def test_suppression_excludes_finding_and_is_reported():
    s = EvalSuppression(id="s1", fingerprint="fp1", reason="accepted risk, ticket SEC-1", expires_at=NOW + timedelta(days=5))
    r = run([f(1, "critical")], sups=[s])
    assert r["decision"] == "PASS" and r["suppressions_applied"][0]["reason"].startswith("accepted")


def test_expired_suppression_does_not_apply():
    s = EvalSuppression(id="s1", fingerprint="fp1", reason="expired exception", expires_at=NOW - timedelta(seconds=1))
    r = run([f(1, "critical")], sups=[s])
    assert r["decision"] == "FAIL" and r["suppressions_expired"][0]["suppression_id"] == "s1"


def test_revoked_suppression_does_not_apply_and_is_scoped_to_fingerprint():
    s = EvalSuppression(id="s1", fingerprint="fp1", reason="x" * 12, expires_at=NOW + timedelta(days=5), revoked=True)
    assert run([f(1, "critical")], sups=[s])["decision"] == "FAIL"
    s2 = EvalSuppression(id="s2", fingerprint="fp1", reason="x" * 12, expires_at=NOW + timedelta(days=5))
    assert run([f(1, "critical"), f(2, "critical")], sups=[s2])["decision"] == "FAIL"  # fp2 still blocks


def test_decision_is_deterministic_regardless_of_input_order():
    fs = [f(1, "high"), f(2, "critical"), f(3, "medium")]
    a, b = run(fs), run(list(reversed(fs)))
    assert a == b and a["policy"] == {"name": "default", "version": 1}


def test_environment_resolution_uses_pr_target_branch():
    assert resolve_environment(DOC, "feature/x") == "development"
    assert resolve_environment(DOC, "feature/x", "main") == "production"
    assert resolve_environment(DOC, "release/2.0") == "staging"
    strict = DOC.model_copy(update={"branch_environments": []})
    assert resolve_environment(strict, "anything") == "production"  # unmapped => default (strict)


def test_result_contains_required_decision_fields():
    r = run([f(1, "critical")])
    for k in ("decision", "policy", "evaluated_at", "rules", "mandatory_checks", "suppressions_applied", "summary", "environment"):
        assert k in r


@pytest.mark.parametrize("bad", [
    {"environments": {}}, {"environments": {"a": {"max_high": -1}}}, {"environments": {"a": {"bogus": 1}}},
    {"environments": {"a": {}}, "default_environment": "zzz"},
    {"environments": {"a": {}}, "default_environment": "a", "branch_environments": [{"pattern": "*", "environment": "nope"}]},
    {"environments": {"a": {"mandatory_scanners": ["nmap"]}}, "default_environment": "a"},
])
def test_invalid_policy_documents_rejected(bad):
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(bad)


def test_risk_score_is_separate_documented_and_never_treats_missing_as_safe():
    s, fx = risk.score("high", known_exploited=None, epss=None, internet_facing=False, environment="development",
                       criticality="medium", fixed_version=None)
    assert s == 41.0 and fx["missing"] == ["kev", "epss"]
    s2, _ = risk.score("high", known_exploited=True, epss=None, internet_facing=True, environment="production",
                       criticality="critical", fixed_version="1.2")
    assert s2 == 38 + 30 + 8 + 4 + 10 + 4
    s3, _ = risk.score("critical", known_exploited=True, epss=None, internet_facing=True, environment="production",
                       criticality="critical", fixed_version="1")
    assert s3 == 100.0  # capped
    assert risk.score("low", known_exploited=False, epss=0.5, internet_facing=False, environment="development",
                      criticality="low", fixed_version=None)[0] == 20.0
