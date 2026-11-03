import copy

import pytest

from app.services.normalize import ParseError
from app.services.parsers import parse_report
from tests.conftest import load


def test_semgrep_real_output_is_normalized():
    r = parse_report("semgrep", load("semgrep_real.json"))
    assert len(r.findings) == 5 and r.tool_version
    sev = sorted(f.severity for f in r.findings)
    assert sev == ["high", "high", "high", "medium", "medium"]
    f = next(x for x in r.findings if x.scanner_finding_id.endswith("subprocess-shell-true"))
    assert f.category == "sast" and f.file_path == "app.py" and f.line == 10
    assert "CWE-78" in f.cwe and f.confidence == "high" and f.scanner_severity == "ERROR"
    assert len({x.fingerprint for x in r.findings}) == 5


def test_trivy_real_config_output():
    r = parse_report("trivy", load("trivy_config_secret_real.json"))
    ids = {f.scanner_finding_id: f for f in r.findings}
    assert set(ids) == {"DS-0001", "DS-0002", "DS-0005", "DS-0026", "DS-0029"}
    assert ids["DS-0002"].severity == "high" and ids["DS-0002"].category == "misconfig"
    assert ids["DS-0002"].file_path == "Dockerfile" and ids["DS-0002"].remediation


def test_trivy_dependency_vulns_and_fix_versions():
    r = parse_report("trivy", load("trivy_vulns_synthetic.json"))
    by = {f.vuln_id: f for f in r.findings}
    assert by["CVE-2099-0001"].severity == "critical" and by["CVE-2099-0001"].fixed_version == "5.4"
    assert by["CVE-2099-0004"].fixed_version is None and "No fixed version" in by["CVE-2099-0004"].remediation
    assert all(f.category == "dependency" for f in r.findings)


def test_trivy_image_is_container_category():
    r = parse_report("trivy-image", load("trivy_image_synthetic.json"))
    assert [f.category for f in r.findings] == ["container"]


def test_trivy_secret_never_stores_match_value():
    r = parse_report("trivy", load("trivy_secret_synthetic.json"))
    f = r.findings[0]
    assert f.category == "secret" and "Match" not in str(f.evidence) and "REDACTED" not in str(f.evidence)


def test_clean_reports_yield_no_findings():
    assert parse_report("trivy", load("trivy_clean.json")).findings == []
    assert parse_report("semgrep", load("semgrep_clean.json")).findings == []


@pytest.mark.parametrize("scanner,raw", [("semgrep", "{not json"), ("trivy", "[]"), ("semgrep", {"foo": 1}), ("trivy", {"Results": []}),
                                         ("semgrep", {"results": [{"check_id": "x"}]}), ("nope", {})])
def test_malformed_reports_raise(scanner, raw):
    with pytest.raises(ParseError):
        parse_report(scanner, raw)


def test_malformed_fixture_file():
    with pytest.raises(ParseError):
        parse_report("semgrep", (load.__globals__["FIXTURES"] / "malformed.json").read_text())


def test_semgrep_error_level_marks_report_incomplete():
    raw = copy.deepcopy(load("semgrep_clean.json"))
    raw["errors"] = [{"level": "error", "type": "RuleParseError", "message": "bad rule"}]
    r = parse_report("semgrep", raw)
    assert r.incomplete_reason and r.warnings


def test_fingerprint_stable_when_lines_shift():
    a = parse_report("semgrep", load("semgrep_real.json"))
    shifted = copy.deepcopy(load("semgrep_real.json"))
    for res in shifted["results"]:
        res["start"]["line"] += 40
    b = parse_report("semgrep", shifted)
    assert {f.fingerprint for f in a.findings} == {f.fingerprint for f in b.findings}


def test_same_rule_twice_in_one_file_not_merged():
    raw = copy.deepcopy(load("semgrep_real.json"))
    dup = copy.deepcopy(raw["results"][0])
    dup["start"]["line"] = 99
    raw["results"].append(dup)
    r = parse_report("semgrep", raw)
    assert len(r.findings) == 6 and len({f.fingerprint for f in r.findings}) == 6


def test_unrelated_findings_with_similar_titles_not_merged():
    raw = copy.deepcopy(load("trivy_vulns_synthetic.json"))
    raw["Results"][0]["Vulnerabilities"][2]["Title"] = raw["Results"][0]["Vulnerabilities"][3]["Title"]
    r = parse_report("trivy", raw)
    assert len({f.fingerprint for f in r.findings}) == 4
