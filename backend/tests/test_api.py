from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select

from app.db import session_factory
from app.models import AuditEvent, IntegrationConfig, Role
from app.services import kev, webhooks
from tests.conftest import ingest_body, make_user, submission

V = "/api/v1"


def vulnerable(commit="a" * 40, branch="main", **kw):
    return ingest_body([submission("semgrep", "semgrep_real.json"), submission("trivy", "trivy_vulns_synthetic.json")], commit, branch, **kw)


def clean(commit="b" * 40, branch="main", **kw):
    return ingest_body([submission("semgrep", "semgrep_clean.json"), submission("trivy", "trivy_clean.json")], commit, branch, **kw)


# ---------- health / security headers / errors
def test_health_ready_and_headers(client):
    assert client.get(f"{V}/health").json() == {"status": "ok"}
    r = client.get(f"{V}/ready")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert "x-request-id" in r.headers and r.headers["cache-control"] == "no-store"


def test_validation_errors_do_not_echo_input(client):
    r = client.post(f"{V}/auth/login", json={"email": "a", "password": "SuperSecretValue!", "extra": 1})
    assert r.status_code == 422 and "SuperSecretValue" not in r.text and r.json()["error"] == "validation_error"


def test_openapi_documented(client):
    spec = client.get(f"{V}/openapi.json").json()
    for p in ("/api/v1/ingest", "/api/v1/policies/{policy_id}/preview", "/api/v1/findings", "/api/v1/dashboard/overview"):
        assert p in spec["paths"]


def test_oversized_body_rejected(client, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "max_body_bytes", 2048)
    # the middleware captured the limit at app creation; assert the Content-Length path using a fresh app instance
    from fastapi.testclient import TestClient

    from app.main import create_app
    with TestClient(create_app()) as c2:
        r = c2.post(f"{V}/auth/login", content=b"x" * 5000, headers={"content-type": "application/json"})
        assert r.status_code == 413


# ---------- authn / authz
def test_login_and_me(client, admin):
    assert client.get(f"{V}/auth/me", headers=admin).json()["role"] == "admin"


def test_bad_login_and_lockout(client, admin):
    for _ in range(5):
        assert client.post(f"{V}/auth/login", json={"email": "admin@example.com", "password": "wrong-password-1"}).status_code == 401
    assert client.post(f"{V}/auth/login", json={"email": "admin@example.com", "password": "Admin-Password-123"}).status_code == 429


def test_endpoints_require_auth(client):
    for path in ("/auth/me", "/repositories", "/scans", "/findings", "/policies", "/dashboard/overview", "/audit", "/users"):
        assert client.get(V + path).status_code == 401, path
    assert client.get(f"{V}/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_tampered_and_expired_jwt_rejected(client, admin):
    import jwt as pyjwt

    from app.config import get_settings
    tok = admin["Authorization"].split()[1]
    assert client.get(f"{V}/auth/me", headers={"Authorization": f"Bearer {tok[:-3]}abc"}).status_code == 401
    expired = pyjwt.encode({"sub": "x", "exp": datetime.now(UTC) - timedelta(minutes=1), "typ": "access"}, get_settings().jwt_secret, algorithm="HS256")
    assert client.get(f"{V}/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401
    none_alg = pyjwt.encode({"sub": "x", "exp": datetime.now(UTC) + timedelta(hours=1)}, key="", algorithm="none")
    assert client.get(f"{V}/auth/me", headers={"Authorization": f"Bearer {none_alg}"}).status_code == 401


def test_repo_token_cannot_be_used_as_user_token_and_vice_versa(client, world):
    assert client.get(f"{V}/scans", headers=world["token"]).status_code == 401
    assert client.post(f"{V}/ingest", json=clean(), headers=world["admin"]).status_code == 401


def test_invalid_ingest_token_rejected(client, world):
    r = client.post(f"{V}/ingest", json=clean(), headers={"Authorization": "Bearer pgt_" + "x" * 40})
    assert r.status_code == 401


def test_role_enforcement(client, world):
    assert client.post(f"{V}/projects", json={"name": "X1"}, headers=world["se"]).status_code == 403
    assert client.post(f"{V}/users", json={"email": "n@example.com", "password": "Another-Pass-123"}, headers=world["se"]).status_code == 403
    assert client.get(f"{V}/users", headers=world["dev"]).status_code == 403
    assert client.get(f"{V}/audit", headers=world["dev"]).status_code == 403
    assert client.post(f"{V}/repositories", json={"project_id": world["project"]["id"], "full_name": "a/b"}, headers=world["dev"]).status_code == 403


def test_weak_password_rejected(client, admin):
    r = client.post(f"{V}/users", json={"email": "w@example.com", "password": "short"}, headers=admin)
    assert r.status_code == 422


def test_admin_cannot_demote_self(client, admin):
    me = client.get(f"{V}/auth/me", headers=admin).json()
    assert client.patch(f"{V}/users/{me['id']}", json={"role": "developer"}, headers=admin).status_code == 409


def test_cross_project_access_denied(client, api, world, admin):
    # another project + repo + member, with their own data
    p2 = client.post(f"{V}/projects", json={"name": "Internal tools"}, headers=admin).json()
    r2 = client.post(f"{V}/repositories", json={"project_id": p2["id"], "full_name": "acme/tools"}, headers=admin).json()
    tok2 = {"Authorization": f"Bearer {r2['ingest_token']}"}
    scan2 = client.post(f"{V}/ingest", json=vulnerable(), headers=tok2).json()
    other = make_user("other@example.com", Role.SECURITY_ENGINEER)
    client.post(f"{V}/projects/{p2['id']}/members", json={"user_id": other.id}, headers=admin)
    other_h = api.login("other@example.com", "Admin-Password-123")
    fid = client.get(f"{V}/findings", params={"repository_id": r2["id"]}, headers=other_h).json()["items"][0]["id"]

    # world['se'] belongs only to Payments
    se = world["se"]
    assert client.get(f"{V}/scans/{scan2['scan_id']}", headers=se).status_code == 404
    assert client.get(f"{V}/scans/{scan2['scan_id']}/report.json", headers=se).status_code == 404
    assert client.get(f"{V}/repositories/{r2['id']}", headers=se).status_code == 404
    assert client.get(f"{V}/findings/{fid}", headers=se).status_code == 404
    assert client.patch(f"{V}/findings/{fid}/status", json={"status": "acknowledged"}, headers=se).status_code == 404
    assert client.post(f"{V}/findings/{fid}/suppressions", json={"reason": "not allowed here", "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat()}, headers=se).status_code == 404
    assert client.get(f"{V}/findings", params={"repository_id": r2["id"]}, headers=se).status_code == 404
    assert client.get(f"{V}/findings", headers=se).json()["total"] == 0
    assert client.get(f"{V}/scans", headers=se).json()["total"] == 0
    assert [r["id"] for r in client.get(f"{V}/repositories", headers=se).json()["items"]] == [world["repo"]["id"]]
    assert client.post(f"{V}/repositories", json={"project_id": p2["id"], "full_name": "evil/repo"}, headers=se).status_code == 404
    # repo token of project 1 cannot touch project 2's scan
    assert client.post(f"{V}/scans/{scan2['scan_id']}/report", json={"scanners": [submission("semgrep", "semgrep_clean.json")]}, headers=world["token"]).status_code == 404
    assert client.get(f"{V}/ci/scans/{scan2['scan_id']}/report.md", headers=world["token"]).status_code == 404
    ov = client.get(f"{V}/dashboard/overview", headers=se).json()
    assert ov["repositories"] == 1 and ov["scans"]["total"] == 0
    assert client.get(f"{V}/audit", headers=se).json()["total"] >= 0
    for e in client.get(f"{V}/audit", headers=se).json()["items"]:
        assert e["project_id"] in (world["project"]["id"],)


# ---------- ingestion + policy
def test_vulnerable_scan_fails_with_explanation(client, world):
    r = client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["decision"] == "FAIL" and body["exit_code"] == 1 and body["status"] == "completed" and not body["idempotent_replay"]
    d = client.get(f"{V}/scans/{body['scan_id']}", headers=world["dev"]).json()
    assert d["severity_counts"]["critical"] == 1 and d["severity_counts"]["high"] == 4
    rules = {x["id"]: x for x in d["evaluation"]["rules"]}
    assert rules["PG-002"]["triggered"] and rules["PG-003"]["triggered"]
    assert rules["PG-002"]["findings"][0]["title"].startswith("Arbitrary code execution")
    assert d["evaluation"]["policy"]["name"] == "default" and d["environment"] == "production"
    assert {e["scanner"]: e["status"] for e in d["executions"]} == {"semgrep": "succeeded", "trivy": "succeeded"}


def test_clean_scan_passes(client, world):
    r = client.post(f"{V}/ingest", json=clean(), headers=world["token"]).json()
    assert r["decision"] == "PASS" and r["exit_code"] == 0


def test_scanner_failure_is_never_a_clean_pass(client, world):
    body = ingest_body([submission("semgrep", "semgrep_clean.json"), submission("trivy", None, status="failed", exit_code=2, error="boom")])
    r = client.post(f"{V}/ingest", json=body, headers=world["token"]).json()
    assert r["decision"] == "FAIL" and r["status"] == "failed"
    d = client.get(f"{V}/scans/{r['scan_id']}", headers=world["dev"]).json()
    assert d["evaluation"]["mandatory_checks"]["missing_or_failed"][0]["scanner"] == "trivy"


def test_missing_scanner_results_fail(client, world):
    r = client.post(f"{V}/ingest", json=ingest_body([submission("semgrep", "semgrep_clean.json")]), headers=world["token"]).json()
    assert r["decision"] == "FAIL"


def test_success_claim_without_report_is_failed(client, world):
    body = ingest_body([submission("semgrep", "semgrep_clean.json"), {"scanner": "trivy", "status": "succeeded"}])
    r = client.post(f"{V}/ingest", json=body, headers=world["token"]).json()
    assert r["decision"] == "FAIL"


def test_malformed_report_is_failed_not_clean(client, world):
    body = ingest_body([submission("semgrep", "semgrep_clean.json"), {"scanner": "trivy", "status": "succeeded", "report": {"nonsense": True}}])
    r = client.post(f"{V}/ingest", json=body, headers=world["token"]).json()
    d = client.get(f"{V}/scans/{r['scan_id']}", headers=world["dev"]).json()
    assert r["decision"] == "FAIL"
    assert next(e for e in d["executions"] if e["scanner"] == "trivy")["parse_error"]


def test_ingest_is_idempotent(client, world):
    first = client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    second = client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    assert first.status_code == 201 and second.status_code == 200
    assert second.json()["idempotent_replay"] is True and second.json()["scan_id"] == first.json()["scan_id"]
    assert client.get(f"{V}/scans", headers=world["admin"]).json()["total"] == 1
    assert client.get(f"{V}/findings", headers=world["admin"]).json()["total"] == 9


def test_explicit_idempotency_key(client, world):
    a = client.post(f"{V}/ingest", json=vulnerable(idempotency_key="build-1234-attempt-1"), headers=world["token"]).json()
    b = client.post(f"{V}/ingest", json=clean(idempotency_key="build-1234-attempt-1"), headers=world["token"]).json()
    assert a["scan_id"] == b["scan_id"] and b["decision"] == "FAIL"  # replay returns the original decision


def test_concurrent_identical_submissions_do_not_corrupt_state(client, world):
    results: list[tuple[int, dict]] = []

    def go():
        r = client.post(f"{V}/ingest", json=vulnerable(idempotency_key="concurrent-key-1"), headers=world["token"])
        results.append((r.status_code, r.json()))

    ts = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert all(code in (200, 201) for code, _ in results), results
    assert len({b["scan_id"] for _, b in results}) == 1 and {b["decision"] for _, b in results} == {"FAIL"}
    assert client.get(f"{V}/scans", headers=world["admin"]).json()["total"] == 1
    assert client.get(f"{V}/findings", headers=world["admin"]).json()["total"] == 9


def test_two_phase_scan_lifecycle_and_cancel(client, world):
    s = client.post(f"{V}/scans", json={"commit_sha": "c" * 40, "branch": "main", "idempotency_key": "run-0001-xyz"}, headers=world["token"])
    assert s.status_code == 201 and s.json()["status"] == "running"
    sid = s.json()["id"]
    r = client.post(f"{V}/scans/{sid}/report", json={"scanners": clean()["scanners"]}, headers=world["token"])
    assert r.status_code == 200 and r.json()["decision"] == "PASS"
    assert client.post(f"{V}/scans/{sid}/cancel", headers=world["token"]).status_code == 409
    s2 = client.post(f"{V}/scans", json={"commit_sha": "d" * 40, "branch": "main", "idempotency_key": "run-0002-xyz"}, headers=world["token"]).json()
    assert client.post(f"{V}/scans/{s2['id']}/cancel", headers=world["token"]).json()["status"] == "cancelled"
    assert client.post(f"{V}/scans/{s2['id']}/report", json={"scanners": clean()["scanners"]}, headers=world["token"]).status_code == 409


def test_strict_schema_rejects_unknown_fields_and_bad_values(client, world):
    for bad in ({**clean(), "surprise": 1}, {**clean(), "commit_sha": "not-hex!"}, {**clean(), "scanners": []},
                ingest_body([submission("nmap", "trivy_clean.json")])):
        assert client.post(f"{V}/ingest", json=bad, headers=world["token"]).status_code == 422
    dup = ingest_body([submission("semgrep", "semgrep_clean.json"), submission("semgrep", "semgrep_clean.json")])
    assert client.post(f"{V}/ingest", json=dup, headers=world["token"]).status_code == 422


def test_ingest_rate_limited(client, world, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "ingest_rate_per_minute", 3)
    codes = [client.post(f"{V}/ingest", json=clean(idempotency_key=f"rate-limit-{i}"), headers=world["token"]).status_code for i in range(5)]
    assert codes[:3] == [201, 201, 201] and codes[3:] == [429, 429]


# ---------- findings lifecycle
def _first_finding(client, world, **params):
    items = client.get(f"{V}/findings", params={"limit": 200, **params}, headers=world["admin"]).json()["items"]
    return items


def test_finding_resolution_and_reopen(client, world):
    client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    assert client.get(f"{V}/findings", params={"status": "open"}, headers=world["admin"]).json()["total"] == 9
    client.post(f"{V}/ingest", json=clean(), headers=world["token"])
    assert client.get(f"{V}/findings", params={"status": "open"}, headers=world["admin"]).json()["total"] == 0
    assert client.get(f"{V}/findings", params={"status": "resolved"}, headers=world["admin"]).json()["total"] == 9
    client.post(f"{V}/ingest", json=vulnerable(commit="e" * 40), headers=world["token"])
    items = client.get(f"{V}/findings", params={"status": "open"}, headers=world["admin"]).json()
    assert items["total"] == 9
    one = items["items"][0]
    assert any(h["action"] == "finding.reopened" for h in client.get(f"{V}/findings/{one['id']}", headers=world["admin"]).json()["history"])


def test_failed_scanner_does_not_resolve_its_findings(client, world):
    client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    body = ingest_body([submission("semgrep", "semgrep_real.json"), submission("trivy", None, status="timeout")], commit="f" * 40)
    client.post(f"{V}/ingest", json=body, headers=world["token"])
    deps = client.get(f"{V}/findings", params={"scanner": "trivy", "status": "open"}, headers=world["admin"]).json()
    assert deps["total"] == 4  # unchanged: a timed-out scanner proves nothing


def test_acknowledge_and_audit_trail(client, world):
    client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    f = _first_finding(client, world)[0]
    assert client.patch(f"{V}/findings/{f['id']}/status", json={"status": "acknowledged"}, headers=world["dev"]).status_code == 403
    r = client.patch(f"{V}/findings/{f['id']}/status", json={"status": "acknowledged", "note": "triaged"}, headers=world["se"])
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    d = client.get(f"{V}/findings/{f['id']}", headers=world["dev"]).json()
    assert d["history"][-1]["action"] == "finding.status_changed" and d["history"][-1]["actor"] == "se@example.com"
    assert d["risk_factors"]["components"]["severity"] > 0 and d["evidence"] is not None


def test_suppression_flow_changes_decision_and_expiry_is_enforced(client, world):
    body = ingest_body([submission("semgrep", "semgrep_clean.json"), submission("trivy", "trivy_vulns_synthetic.json")])
    sid = client.post(f"{V}/ingest", json=body, headers=world["token"]).json()["scan_id"]
    items = _first_finding(client, world)
    crit = next(i for i in items if i["severity"] == "critical")
    exp = (datetime.now(UTC) + timedelta(days=7)).isoformat()
    # engineers cannot suppress criticals; admins can; developers cannot suppress at all
    assert client.post(f"{V}/findings/{crit['id']}/suppressions", json={"reason": "accepted until upgrade", "expires_at": exp}, headers=world["se"]).status_code == 403
    assert client.post(f"{V}/findings/{crit['id']}/suppressions", json={"reason": "accepted until upgrade", "expires_at": exp}, headers=world["dev"]).status_code == 403
    for bad in ({"reason": "short", "expires_at": exp}, {"reason": "valid reason text", "expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat()},
                {"reason": "valid reason text", "expires_at": (datetime.now(UTC) + timedelta(days=999)).isoformat()}):
        assert client.post(f"{V}/findings/{crit['id']}/suppressions", json=bad, headers=world["admin"]).status_code == 422
    ok = client.post(f"{V}/findings/{crit['id']}/suppressions", json={"reason": "accepted until upgrade", "expires_at": exp}, headers=world["admin"])
    assert ok.status_code == 201
    assert client.get(f"{V}/findings/{crit['id']}", headers=world["dev"]).json()["effective_status"] == "suppressed"
    # re-evaluate: critical suppressed, but 1 high (django) still violates production's max_high=0
    r = client.post(f"{V}/scans/{sid}/reevaluate", headers=world["se"]).json()
    ev = client.get(f"{V}/scans/{sid}", headers=world["dev"]).json()["evaluation"]
    assert ev["suppressions_applied"][0]["reason"] == "accepted until upgrade" and ev["counts"]["suppressed"] == 1
    assert not next(x for x in ev["rules"] if x["id"] == "PG-002")["triggered"] and r["decision"] == "FAIL"
    # force expiry directly in the DB: the next evaluation must NOT honour it
    from app.models import Suppression
    with session_factory()() as db:
        s = db.scalars(select(Suppression)).one()
        s.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    client.post(f"{V}/scans/{sid}/reevaluate", headers=world["se"])
    ev = client.get(f"{V}/scans/{sid}", headers=world["dev"]).json()["evaluation"]
    assert next(x for x in ev["rules"] if x["id"] == "PG-002")["triggered"] and ev["suppressions_expired"]
    assert client.get(f"{V}/findings/{crit['id']}", headers=world["dev"]).json()["effective_status"] == "open"
    with session_factory()() as db:
        assert "finding.suppressed" in {e.action for e in db.scalars(select(AuditEvent))}


def test_revoke_suppression(client, world):
    client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    f = next(i for i in _first_finding(client, world) if i["severity"] == "medium")
    sup = client.post(f"{V}/findings/{f['id']}/suppressions", json={"reason": "temporary exception", "expires_at": (datetime.now(UTC) + timedelta(days=3)).isoformat()}, headers=world["se"]).json()
    assert client.delete(f"{V}/findings/{f['id']}/suppressions/{sup['id']}", headers=world["se"]).status_code == 204
    assert client.get(f"{V}/findings/{f['id']}", headers=world["se"]).json()["effective_status"] == "open"


def test_findings_filters_search_sort_pagination(client, world):
    client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    g = lambda **p: client.get(f"{V}/findings", params=p, headers=world["dev"]).json()  # noqa: E731
    assert g(severity="critical")["total"] == 1 and g(scanner="semgrep")["total"] == 5 and g(category="dependency")["total"] == 4
    assert g(q="flask")["total"] == 2 and g(q="CVE-2099-0002")["total"] == 1
    page = g(limit=3, offset=0, sort="severity")
    assert len(page["items"]) == 3 and page["total"] == 9 and page["items"][0]["severity"] == "critical"
    assert client.get(f"{V}/findings", params={"limit": 9999}, headers=world["dev"]).status_code == 422
    assert client.get(f"{V}/findings", params={"q": "x'; DROP TABLE findings;--"}, headers=world["dev"]).status_code == 200
    assert g()["total"] == 9


def test_new_vs_existing_vs_base_comparison(client, world):
    client.post(f"{V}/ingest", json=clean(commit="1" * 40), headers=world["token"])  # base branch has a scan with no findings
    pr = client.post(f"{V}/ingest", json=vulnerable(commit="2" * 40, branch="feature/x", base_branch="main", pr_number=7), headers=world["token"]).json()
    d = client.get(f"{V}/scans/{pr['scan_id']}", headers=world["dev"]).json()
    assert d["new_counts"]["critical"] == 1 and d["environment"] == "production" and d["pr_number"] == 7
    md = client.get(f"{V}/ci/scans/{pr['scan_id']}/report.md", headers=world["token"]).text
    assert "Newly introduced findings" in md and "pipelineguard-commit:" + "2" * 40 in md and md.startswith("<!-- pipelineguard-report -->")


# ---------- policies
def test_policy_versioning_preview_and_authorization(client, world):
    sid = client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"]).json()["scan_id"]
    pols = client.get(f"{V}/policies", headers=world["se"]).json()
    base = pols[0]
    assert base["project_id"] is None and base["current_version"] == 1
    # engineers cannot alter global policies
    assert client.post(f"{V}/policies/{base['id']}/versions", json={"document": base["document"]}, headers=world["se"]).status_code == 403
    assert client.post(f"{V}/policies/{base['id']}/versions", json={"document": base["document"]}, headers=world["dev"]).status_code == 403
    # a project-scoped policy created by the engineer: relaxed dev thresholds
    relaxed = {**base["document"]}
    relaxed["environments"] = {k: {**v, "max_critical": 5, "max_high": 50, "warn_medium_above": 50} for k, v in base["document"]["environments"].items()}
    relaxed["environments"]["production"]["fail_on_secrets"] = True
    created = client.post(f"{V}/policies", json={"name": "payments-relaxed", "project_id": world["project"]["id"], "document": relaxed, "change_note": "pilot"}, headers=world["se"])
    assert created.status_code == 201
    pid = created.json()["id"]
    # preview does not enforce: stored decision stays FAIL while preview says PASS
    pv = client.post(f"{V}/policies/{pid}/preview", json={"scan_id": sid}, headers=world["se"]).json()
    assert pv["decision"] == "PASS" and pv["preview"] is True and pv["previous_decision"] == "FAIL"
    assert client.get(f"{V}/scans/{sid}", headers=world["se"]).json()["decision"] == "FAIL"
    # draft preview with a stricter document, and versioning
    strict = client.post(f"{V}/policies/{pid}/preview", json={"scan_id": sid, "document": base["document"]}, headers=world["se"]).json()
    assert strict["decision"] == "FAIL" and strict["rules"][1]["triggered"]
    v2 = client.post(f"{V}/policies/{pid}/versions", json={"document": base["document"], "change_note": "tighten"}, headers=world["se"])
    assert v2.status_code == 201 and v2.json()["current_version"] == 2
    versions = client.get(f"{V}/policies/{pid}/versions", headers=world["dev"]).json()
    assert [v["version"] for v in versions] == [2, 1]
    # new scan uses the project policy (version 2 = strict) and records it
    r = client.post(f"{V}/ingest", json=vulnerable(commit="9" * 40), headers=world["token"]).json()
    ev = client.get(f"{V}/scans/{r['scan_id']}", headers=world["dev"]).json()["evaluation"]
    assert ev["policy"]["name"] == "payments-relaxed" and ev["policy"]["version"] == 2
    assert client.post(f"{V}/policies/{pid}/versions", json={"document": {"environments": {}}}, headers=world["se"]).status_code == 422
    with session_factory()() as db:
        acts = [e.action for e in db.scalars(select(AuditEvent).order_by(AuditEvent.created_at))]
    assert "policy.created" in acts and "policy.versioned" in acts


def test_policy_tampering_blocked_for_other_projects(client, api, world, admin):
    p2 = client.post(f"{V}/projects", json={"name": "Other"}, headers=admin).json()
    doc = client.get(f"{V}/policies", headers=admin).json()[0]["document"]
    pol = client.post(f"{V}/policies", json={"name": "other-policy", "project_id": p2["id"], "document": doc}, headers=admin).json()
    assert client.post(f"{V}/policies/{pol['id']}/versions", json={"document": doc}, headers=world["se"]).status_code == 404
    assert client.post(f"{V}/policies", json={"name": "xx", "project_id": p2["id"], "document": doc}, headers=world["se"]).status_code == 404
    assert pol["id"] not in [p["id"] for p in client.get(f"{V}/policies", headers=world["se"]).json()]


# ---------- reports / dashboard / audit
def test_reports_json_and_markdown(client, world):
    sid = client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"]).json()["scan_id"]
    r = client.get(f"{V}/scans/{sid}/report.json", headers=world["dev"])
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    rep = r.json()
    assert rep["policy_decision"]["decision"] == "FAIL" and len(rep["findings"]) == 9 and rep["repository"]["full_name"] == "acme/payments-api"
    assert rep["scanner_executions"][0]["report_sha256"] and rep["limitations"]
    md = client.get(f"{V}/scans/{sid}/report.md", headers=world["dev"]).text
    assert "PipelineGuard: FAIL" in md and "PG-002" in md and f"http://testserver/scans/{sid}" in md


def test_dashboard_reflects_real_stored_results(client, world):
    client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    client.post(f"{V}/ingest", json=clean(), headers=world["token"])
    client.post(f"{V}/ingest", json=vulnerable(commit="3" * 40), headers=world["token"])
    ov = client.get(f"{V}/dashboard/overview", headers=world["dev"]).json()
    assert ov["repositories"] == 1 and ov["scans"]["total"] == 3 and ov["decisions"] == {"PASS": 1, "WARN": 0, "FAIL": 2}
    assert ov["open_findings"]["critical"] == 1 and ov["open_findings"]["high"] == 4 and ov["pass_rate"] == 33.3
    assert ov["top_remediation"][0]["severity"] == "critical" and len(ov["recent_failures"]) == 2
    tr = client.get(f"{V}/dashboard/trends", headers=world["dev"]).json()["points"]
    assert tr and tr[-1]["scans"] == 3 and tr[-1]["risk"] > 0 and tr[-1]["new"] == 9 and tr[-1]["resolved"] == 0  # reopened by the 3rd scan, so not counted as resolved
    repos = client.get(f"{V}/repositories", headers=world["dev"]).json()["items"]
    assert repos[0]["latest_scan"]["decision"] == "FAIL" and repos[0]["open_findings"]["critical"] == 1


def test_empty_dashboard(client, admin):
    ov = client.get(f"{V}/dashboard/overview", headers=admin).json()
    assert ov["repositories"] == 0 and ov["pass_rate"] is None


def test_audit_events_and_role_change(client, world):
    me = client.get(f"{V}/auth/me", headers=world["dev"]).json()
    assert client.patch(f"{V}/users/{me['id']}", json={"role": "security_engineer"}, headers=world["admin"]).status_code == 200
    events = client.get(f"{V}/audit", params={"action": "user."}, headers=world["admin"]).json()["items"]
    changed = next(e for e in events if e["action"] == "user.updated")
    assert changed["details"]["role"] == {"from": "developer", "to": "security_engineer"} and changed["actor"] == "admin@example.com"
    acts = {e["action"] for e in client.get(f"{V}/audit", params={"limit": 200}, headers=world["admin"]).json()["items"]}
    assert {"repository.registered", "project.created", "auth.login", "user.updated"} <= acts


def test_token_rotation_invalidates_old_token(client, world):
    rot = client.post(f"{V}/repositories/{world['repo']['id']}/rotate-token", headers=world["se"]).json()
    assert client.post(f"{V}/ingest", json=clean(), headers=world["token"]).status_code == 401
    assert client.post(f"{V}/ingest", json=clean(), headers={"Authorization": f"Bearer {rot['ingest_token']}"}).status_code == 201


def test_secrets_not_exposed_in_responses(client, world):
    assert "ingest_token_hash" not in client.get(f"{V}/repositories/{world['repo']['id']}", headers=world["admin"]).text
    listing = client.get(f"{V}/repositories", headers=world["admin"]).text
    assert world["repo"]["ingest_token"] not in listing and "password" not in client.get(f"{V}/users", headers=world["admin"]).text
    st = client.get(f"{V}/integrations/status", headers=world["dev"]).text
    assert "jwt_secret\": \"" not in st and "test-secret" not in st


# ---------- integrations
def test_webhook_ssrf_blocked_and_audited(client, world):
    for url in ("https://127.0.0.1/hook", "http://example.com/x", "https://169.254.169.254/latest", "https://localhost/x"):
        assert client.post(f"{V}/integrations/webhooks", json={"name": "bad hook", "url": url}, headers=world["admin"]).status_code == 422
    assert client.post(f"{V}/integrations/webhooks", json={"name": "hook", "url": "https://93.184.216.34/h"}, headers=world["se"]).status_code == 403


def test_webhook_delivery_records_health_and_never_follows_redirects(client, world):
    created = client.post(f"{V}/integrations/webhooks", json={"name": "chat", "url": "https://93.184.216.34/secret/path", "notify_on": ["FAIL"]}, headers=world["admin"])
    assert created.status_code == 201 and "secret/path" not in created.text
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(302, headers={"location": "https://169.254.169.254/"}) if len(seen) == 1 else httpx.Response(200)

    with session_factory()() as db:
        cfg = db.scalars(select(IntegrationConfig)).one()
        webhooks.deliver(db, cfg, {"event": "t"}, client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False))
        assert cfg.last_status == "http_302" and len(seen) == 1
        webhooks.deliver(db, cfg, {"event": "t"}, client=httpx.Client(transport=httpx.MockTransport(handler)))
        assert cfg.last_status == "ok"
    status = client.get(f"{V}/integrations/status", headers=world["dev"]).json()
    assert status["notifications"][0]["last_status"] == "ok" and "secret/path" not in str(status)


def test_integration_status_reports_real_scanner_data(client, world):
    client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    st = client.get(f"{V}/integrations/status", headers=world["dev"]).json()
    sg = next(s for s in st["scanners"] if s["scanner"] == "semgrep")
    assert sg["last_version"] == "1.182.1" and sg["executions_by_status"] == {"succeeded": 1}
    assert st["ci_providers"][0]["provider"] == "github" and st["enrichment"]["cisa_kev"]["loaded"] is False


def test_kev_enrichment_flags_findings_and_failure_is_graceful(client, world):
    ok = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"catalogVersion": "t", "vulnerabilities": [{"cveID": "CVE-2099-0003", "dateAdded": "2026-01-01"}]})))
    with session_factory()() as db:
        assert kev.refresh(db, client=ok)["ok"] is True
        assert kev.lookup(db, {"CVE-2099-0003", "CVE-2099-0004"}) == {"CVE-2099-0003": True, "CVE-2099-0004": False}
    r = client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"]).json()
    items = _first_finding(client, world)
    flask = next(i for i in items if i["vuln_id"] == "CVE-2099-0003")
    assert flask["known_exploited"] is True and flask["severity"] == "medium"
    assert next(i for i in items if i["vuln_id"] == "CVE-2099-0004")["known_exploited"] is False
    ev = client.get(f"{V}/scans/{r['scan_id']}", headers=world["dev"]).json()["evaluation"]
    assert next(x for x in ev["rules"] if x["id"] == "PG-004")["triggered"]
    bad = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    with session_factory()() as db:
        res = kev.refresh(db, client=bad)
        assert res["ok"] is False and kev.status(db)["loaded"] is True  # cache untouched on failure


def test_kev_unknown_when_feed_never_loaded(client, world):
    client.post(f"{V}/ingest", json=vulnerable(), headers=world["token"])
    assert all(i["known_exploited"] is None for i in _first_finding(client, world) if i["vuln_id"])
