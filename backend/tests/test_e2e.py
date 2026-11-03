"""End-to-end: register repository -> real-format scan report -> normalize/store -> policy -> CI exit code -> dashboard."""
from tests.conftest import ingest_body, submission

V = "/api/v1"


def test_end_to_end_blocked_then_fixed_pipeline(client, world):
    # 1. repository was registered by the `world` fixture (admin created project + repo, got a one-time token)
    assert world["repo"]["ingest_token"].startswith("pgt_")
    # 2. a vulnerable build: real Semgrep output + Trivy-format dependency report
    bad = client.post(f"{V}/ingest", json=ingest_body([submission("semgrep", "semgrep_real.json"), submission("trivy", "trivy_vulns_synthetic.json")],
                                                       branch="main", build_id="run-1"), headers=world["token"]).json()
    assert bad["decision"] == "FAIL" and bad["exit_code"] == 1  # 3. CI must fail
    ov = client.get(f"{V}/dashboard/overview", headers=world["dev"]).json()
    assert ov["open_findings"]["critical"] == 1 and ov["decisions"]["FAIL"] == 1  # 4. dashboard shows stored results
    # 5. the fix lands: clean scans -> PASS, exit code 0, findings resolved
    good = client.post(f"{V}/ingest", json=ingest_body([submission("semgrep", "semgrep_clean.json"), submission("trivy", "trivy_clean.json")],
                                                        commit="b" * 40, build_id="run-2"), headers=world["token"]).json()
    assert good["decision"] == "PASS" and good["exit_code"] == 0
    ov = client.get(f"{V}/dashboard/overview", headers=world["dev"]).json()
    assert sum(ov["open_findings"].values()) == 0 and ov["resolved_in_window"] == 9 and ov["decisions"] == {"PASS": 1, "WARN": 0, "FAIL": 1}
    # 6. scanner outage on a later build is a FAIL, never a silent pass
    out = client.post(f"{V}/ingest", json=ingest_body([submission("semgrep", None, status="missing", error="semgrep: command not found"),
                                                        submission("trivy", "trivy_clean.json")], commit="c" * 40), headers=world["token"]).json()
    assert out["decision"] == "FAIL" and out["status"] == "failed"
