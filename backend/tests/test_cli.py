"""CI client tests: a live uvicorn server + fake scanner executables that emit the committed fixtures.
These verify exit-code behaviour end to end without needing Semgrep/Trivy installed."""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import stat
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from tests.conftest import FIXTURES, ROOT

spec = importlib.util.spec_from_file_location("pg_cli", ROOT.parent / "cli" / "pipelineguard.py")
cli = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(cli)  # type: ignore[union-attr]

FAKE = '''#!/usr/bin/env python3
import os, sys, time, json
a = sys.argv[1:]
if "--version" in a:
    print("fake 1.0"); sys.exit(0)
name = os.path.splitext(os.path.basename(sys.argv[0]))[0]
mode = os.environ.get("FAKE_%s_MODE" % name.upper(), "ok")
if os.environ.get("FAKE_ENV_DUMP"):
    open(os.environ["FAKE_ENV_DUMP"], "w").write(json.dumps({"token_visible": "PIPELINEGUARD_TOKEN" in os.environ, "argv": a}))
if mode == "sleep":
    time.sleep(30)
if mode == "crash":
    sys.stderr.write("segfault-ish\\n"); sys.exit(2)
out = a[a.index("-o") + 1] if "-o" in a else a[a.index("--output") + 1]
fx = os.environ["FAKE_%s_FIXTURE" % name.upper()]
open(out, "w").write("{broken" if mode == "garbage" else open(fx).read())
'''


@pytest.fixture
def server():
    from app.main import create_app
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    t.join(5)


@pytest.fixture
def fakebin(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    for n in ("semgrep", "trivy"):
        if sys.platform == "win32":
            py_script = d / f"{n}.py"
            py_script.write_text(FAKE, encoding="utf-8")
            cmd = d / f"{n}.cmd"
            cmd.write_text(f'@"{sys.executable}" "{py_script}" %*\n', encoding="utf-8")
        else:
            p = d / n
            p.write_text(FAKE)
            p.chmod(p.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{d}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_SEMGREP_FIXTURE", str(FIXTURES / "semgrep_clean.json"))
    monkeypatch.setenv("FAKE_TRIVY_FIXTURE", str(FIXTURES / "trivy_clean.json"))
    return d


@pytest.fixture
def env(monkeypatch, world, server):
    monkeypatch.setenv("PIPELINEGUARD_URL", server)
    monkeypatch.setenv("PIPELINEGUARD_TOKEN", world["repo"]["ingest_token"])
    for k in ("GITHUB_ACTIONS", "GITLAB_CI"):
        monkeypatch.delenv(k, raising=False)
    return world


def run(tmp_path, *extra):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return cli.main(["scan", "--path", str(work), "--output-dir", str(tmp_path / "out"), "--commit-sha", "a" * 40, "--branch", "main",
                     "--semgrep-config", "x", "--idempotency-key", f"k-{time.time_ns()}", *extra])


def decision(tmp_path):
    return json.loads((tmp_path / "out" / "decision.json").read_text())


def test_clean_scan_exits_zero(env, fakebin, tmp_path):
    assert run(tmp_path) == 0 and decision(tmp_path)["decision"] == "PASS"
    assert "PipelineGuard: PASS" in (tmp_path / "out" / "summary.md").read_text()


def test_vulnerable_scan_exits_one(env, fakebin, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_SEMGREP_FIXTURE", str(FIXTURES / "semgrep_real.json"))
    monkeypatch.setenv("FAKE_TRIVY_FIXTURE", str(FIXTURES / "trivy_vulns_synthetic.json"))
    assert run(tmp_path) == 1
    assert decision(tmp_path)["decision"] == "FAIL" and decision(tmp_path)["exit_code"] == 1


def test_warn_exit_policy_is_configurable(env, fakebin, tmp_path, monkeypatch):
    medium_only = tmp_path / "medium.json"
    data = json.loads((FIXTURES / "trivy_vulns_synthetic.json").read_text())
    data["Results"][0]["Vulnerabilities"] = [v for v in data["Results"][0]["Vulnerabilities"] if v["Severity"] == "MEDIUM"]
    medium_only.write_text(json.dumps(data))
    monkeypatch.setenv("FAKE_TRIVY_FIXTURE", str(medium_only))
    assert run(tmp_path) == 0 and decision(tmp_path)["decision"] == "WARN"
    assert run(tmp_path, "--warn-as-failure") == 1


def test_missing_scanner_binary_fails_not_passes(env, fakebin, tmp_path):
    for f in fakebin.glob("trivy*"):
        f.unlink()
    assert run(tmp_path) == 1
    d = decision(tmp_path)
    assert d["decision"] == "FAIL" and d["status"] == "failed"


@pytest.mark.parametrize("mode,extra", [("crash", []), ("garbage", []), ("sleep", ["--timeout", "1"])])
def test_scanner_failures_are_preserved_and_fail(env, fakebin, tmp_path, monkeypatch, mode, extra):
    monkeypatch.setenv("FAKE_SEMGREP_MODE", mode)
    assert run(tmp_path, *extra) == 1
    assert decision(tmp_path)["decision"] == "FAIL"
    scan = json.loads(json.dumps(decision(tmp_path)))
    assert "mandatory" in scan["summary"].lower() or "PG-001" in scan["summary"]


def test_skipping_a_mandatory_scanner_fails(env, fakebin, tmp_path):
    assert run(tmp_path, "--skip", "trivy") == 1 and decision(tmp_path)["decision"] == "FAIL"


def test_unreachable_server_fails_closed(env, fakebin, tmp_path, monkeypatch):
    monkeypatch.setenv("PIPELINEGUARD_URL", "http://127.0.0.1:1")
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    assert run(tmp_path) == 2


def test_wrong_token_fails_closed(env, fakebin, tmp_path, monkeypatch):
    monkeypatch.setenv("PIPELINEGUARD_TOKEN", "pgt_" + "z" * 40)
    assert run(tmp_path) == 2


def test_configuration_errors(env, fakebin, tmp_path, monkeypatch):
    monkeypatch.delenv("PIPELINEGUARD_TOKEN")
    assert run(tmp_path) == 3
    monkeypatch.setenv("PIPELINEGUARD_TOKEN", "pgt_x")
    monkeypatch.setenv("PIPELINEGUARD_URL", "http://example.com")
    assert run(tmp_path) == 3
    with pytest.raises(ValueError):
        cli.validate_server_url("ftp://x", False)


def test_ci_secrets_are_not_passed_to_scanners(env, fakebin, tmp_path, monkeypatch):
    dump = tmp_path / "env.json"
    monkeypatch.setenv("FAKE_ENV_DUMP", str(dump))
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_secret")
    run(tmp_path)
    info = json.loads(dump.read_text())
    assert info["token_visible"] is False and "shell" not in " ".join(info["argv"])


def test_github_metadata_detection(monkeypatch, tmp_path):
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps({"pull_request": {"number": 42, "head": {"sha": "f" * 40}}}))
    for k, v in {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_PATH": str(ev), "GITHUB_HEAD_REF": "feature/x", "GITHUB_BASE_REF": "main",
                 "GITHUB_RUN_ID": "99", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": "merge-sha"}.items():
        monkeypatch.setenv(k, v)
    args = cli.parser().parse_args(["scan"])
    assert cli.ci_metadata(args) == {"commit_sha": "f" * 40, "branch": "feature/x", "base_branch": "main", "pr_number": 42, "build_id": "99-2"}


def test_pr_comment_is_updated_not_duplicated(monkeypatch):
    calls = []
    existing = [{"id": 7, "body": cli.MARKER + "\nold"}, {"id": 8, "body": "unrelated"}]

    def fake_http(method, url, token=None, body=None, timeout=60, headers=None):
        calls.append((method, url, body))
        return 200, json.dumps(existing if method == "GET" else {})

    monkeypatch.setattr(cli, "http", fake_http)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/payments-api")
    cli.upsert_pr_comment(cli.MARKER + "\nnew", 5)
    assert [c[0] for c in calls] == ["GET", "PATCH"] and calls[1][1].endswith("/issues/comments/7")
    calls.clear()
    existing[0]["body"] = cli.MARKER + "\nnew"
    cli.upsert_pr_comment(cli.MARKER + "\nnew", 5)
    assert [c[0] for c in calls] == ["GET"]  # identical => no write
    calls.clear()
    existing.clear()
    cli.upsert_pr_comment(cli.MARKER + "\nfresh", 5)
    assert [c[0] for c in calls] == ["GET", "POST"]


def test_pr_comment_failure_is_nonfatal(monkeypatch):
    def boom(*a, **k):
        raise cli.HttpError(403, "Resource not accessible by integration")

    monkeypatch.setattr(cli, "http", boom)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "a/b")
    cli.upsert_pr_comment("x", 1)  # must not raise


_ = Path
