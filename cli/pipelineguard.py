#!/usr/bin/env python3
"""PipelineGuard CI client (standard library only, Python 3.9+).

Runs Semgrep and Trivy with safe subprocess handling (no shell), uploads the original machine-readable
reports to PipelineGuard, prints the server-side policy decision and exits accordingly.

Exit codes:  0 = PASS (or WARN without --warn-as-failure)   1 = policy FAIL (or WARN with --warn-as-failure)
             2 = operational error (server unreachable, bad response, upload rejected) -> pipeline FAILS CLOSED
             3 = invalid configuration/arguments
Scanner execution problems (missing binary, timeout, malformed output) are reported to the server verbatim and the
server records them as failed executions: they can never turn into a PASS.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXIT_PASS, EXIT_FAIL, EXIT_ERROR, EXIT_CONFIG = 0, 1, 2, 3
MARKER = "<!-- pipelineguard-report -->"
SECRET_ENV = ("PIPELINEGUARD_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "CI_JOB_TOKEN")


def now() -> datetime:
    return datetime.now(timezone.utc)


def log(msg: str) -> None:
    print(f"[pipelineguard] {msg}", flush=True)


# --------------------------------------------------------------------------- scanners
def _scanner_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV}  # never hand CI secrets to scanners
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    return env


def tool_version(exe: str) -> str | None:
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30, env=_scanner_env(), check=False)
        text = (out.stdout or out.stderr).strip().splitlines()
        return text[0].replace("Version:", "").strip()[:64] if text else None
    except (OSError, subprocess.SubprocessError):
        return None


def run_scanner(name: str, argv: list[str], out_file: Path, timeout: int, ok_codes: tuple[int, ...], mode: str) -> dict[str, Any]:
    """Run one scanner and return a submission dict. Never raises; failures are encoded in `status`."""
    sub: dict[str, Any] = {"scanner": name, "status": "failed", "scan_mode": mode, "exit_code": None, "version": None,
                           "started_at": now().isoformat(), "report": None, "error": None, "stderr_tail": None}
    exe = shutil.which(argv[0])
    if exe is None:
        sub.update(status="missing", error=f"{argv[0]}: executable not found on PATH", finished_at=now().isoformat())
        return sub
    argv = [exe, *argv[1:]]
    sub["version"] = tool_version(exe)
    log(f"running {name}: {' '.join(argv)}")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=_scanner_env(), check=False)  # no shell
    except subprocess.TimeoutExpired as e:
        sub.update(status="timeout", error=f"{name} exceeded {timeout}s timeout", finished_at=now().isoformat(),
                   stderr_tail=((e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""))[-4000:])
        return sub
    except OSError as e:
        sub.update(status="failed", error=f"could not execute {name}: {e}", finished_at=now().isoformat())
        return sub
    sub["finished_at"] = now().isoformat()
    sub["exit_code"] = proc.returncode
    sub["stderr_tail"] = (proc.stderr or "")[-4000:] or None
    if proc.returncode not in ok_codes:
        sub["error"] = f"{name} exited with code {proc.returncode}"
        return sub
    try:
        sub["report"] = json.loads(out_file.read_text(encoding="utf-8"))
        sub["status"] = "succeeded"
    except (OSError, ValueError) as e:
        sub["error"] = f"{name} produced no valid JSON report at {out_file}: {e}"
    return sub


def build_scans(args: argparse.Namespace, outdir: Path) -> list[dict[str, Any]]:
    subs: list[dict[str, Any]] = []
    if "semgrep" not in args.skip:
        cfgs = [x for c in args.semgrep_config for x in ("--config", c)]
        excl = [x for e in args.exclude for x in ("--exclude", e)]
        subs.append(run_scanner("semgrep", ["semgrep", "scan", *cfgs, *excl, "--json", "--metrics=off", "--disable-version-check", "--quiet",
                                            "-o", str(outdir / "semgrep.json"), args.path],
                                outdir / "semgrep.json", args.timeout, (0, 1), "sast"))
    if "trivy" not in args.skip:
        argv = ["trivy", "fs", "--scanners", args.trivy_scanners, "--format", "json", "--output", str(outdir / "trivy-fs.json"), "--quiet"]
        if args.trivy_offline:
            argv.append("--skip-db-update")
        argv += [x for e in args.exclude for x in ("--skip-dirs", e)]
        subs.append(run_scanner("trivy", [*argv, args.path], outdir / "trivy-fs.json", args.timeout, (0,), "fs:" + args.trivy_scanners))
    if args.trivy_image:
        argv = ["trivy", "image", "--format", "json", "--output", str(outdir / "trivy-image.json"), "--quiet"]
        if args.trivy_offline:
            argv.append("--skip-db-update")
        subs.append(run_scanner("trivy-image", [*argv, args.trivy_image], outdir / "trivy-image.json", args.timeout, (0,), "image"))
    return subs


# --------------------------------------------------------------------------- CI metadata
def ci_metadata(args: argparse.Namespace) -> dict[str, Any]:
    e = os.environ
    meta: dict[str, Any] = {}
    if e.get("GITHUB_ACTIONS") == "true":
        event: dict[str, Any] = {}
        try:
            event = json.loads(Path(e["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8")) if e.get("GITHUB_EVENT_PATH") else {}
        except (OSError, ValueError):
            pass
        pr = event.get("pull_request") or {}
        meta["commit_sha"] = (pr.get("head") or {}).get("sha") or e.get("GITHUB_SHA")
        meta["branch"] = e.get("GITHUB_HEAD_REF") or e.get("GITHUB_REF_NAME")
        if e.get("GITHUB_BASE_REF"):
            meta["base_branch"] = e["GITHUB_BASE_REF"]
        if pr.get("number"):
            meta["pr_number"] = int(pr["number"])
        meta["build_id"] = f"{e.get('GITHUB_RUN_ID', '')}-{e.get('GITHUB_RUN_ATTEMPT', '1')}"
    elif e.get("GITLAB_CI") == "true":
        meta["commit_sha"] = e.get("CI_COMMIT_SHA")
        meta["branch"] = e.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME") or e.get("CI_COMMIT_REF_NAME")
        if e.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"):
            meta["base_branch"] = e["CI_MERGE_REQUEST_TARGET_BRANCH_NAME"]
        if e.get("CI_MERGE_REQUEST_IID"):
            meta["pr_number"] = int(e["CI_MERGE_REQUEST_IID"])
        meta["build_id"] = e.get("CI_PIPELINE_ID")
    for k in ("commit_sha", "branch", "base_branch", "pr_number", "build_id"):
        v = getattr(args, k, None)
        if v not in (None, ""):
            meta[k] = v
    if not meta.get("commit_sha") or not meta.get("branch"):
        try:  # local runs: fall back to git
            meta.setdefault("commit_sha", subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, cwd=args.path).stdout.strip())
            meta.setdefault("branch", subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, check=True, cwd=args.path).stdout.strip())
        except (OSError, subprocess.SubprocessError):
            pass
    return {k: v for k, v in meta.items() if v not in (None, "")}


# --------------------------------------------------------------------------- HTTP
class HttpError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status = status


def http(method: str, url: str, token: str | None = None, body: Any = None, timeout: int = 60, headers: dict[str, str] | None = None) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)  # noqa: S310 (scheme validated by caller)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "pipelineguard-cli/1")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        raise HttpError(e.code, e.read().decode(errors="replace")) from None


def validate_server_url(url: str, allow_insecure: bool) -> str:
    p = urllib.parse.urlsplit(url)
    if p.scheme == "https" or (p.scheme == "http" and (allow_insecure or p.hostname in ("localhost", "127.0.0.1", "::1"))):
        return url.rstrip("/")
    raise ValueError("PIPELINEGUARD_URL must use https (http is only accepted for localhost or with --allow-insecure-http)")


def upload(server: str, token: str, payload: dict[str, Any], retries: int = 3) -> dict[str, Any]:
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            _, text = http("POST", f"{server}/api/v1/ingest", token, payload, timeout=120)
            return json.loads(text)
        except HttpError as e:
            if e.status < 500 and e.status != 429:
                raise  # client errors are not retried
            last = e
        except (urllib.error.URLError, OSError, ValueError) as e:
            last = e
        log(f"upload attempt {attempt}/{retries} failed: {last}")
        time.sleep(min(2 ** attempt, 10))  # safe: idempotency key makes retries harmless
    raise RuntimeError(f"upload failed after {retries} attempts: {last}")


# --------------------------------------------------------------------------- pull-request comment
def upsert_pr_comment(markdown: str, pr_number: int) -> None:
    token, repo = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        log("PR comment skipped: GITHUB_TOKEN/GITHUB_REPOSITORY not set")
        return
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    gh = {"X-GitHub-Api-Version": "2022-11-28", "Accept": "application/vnd.github+json"}
    try:
        existing = None
        for page in range(1, 6):
            _, text = http("GET", f"{api}/repos/{repo}/issues/{pr_number}/comments?per_page=100&page={page}", token, headers=gh)
            items = json.loads(text)
            existing = next((c for c in items if MARKER in (c.get("body") or "")), None)
            if existing or len(items) < 100:
                break
        if existing and existing.get("body") == markdown:
            log("PR comment already up to date")
        elif existing:
            http("PATCH", f"{api}/repos/{repo}/issues/comments/{existing['id']}", token, {"body": markdown}, headers=gh)
            log("updated existing PR comment")
        else:
            http("POST", f"{api}/repos/{repo}/issues/{pr_number}/comments", token, {"body": markdown}, headers=gh)
            log("posted PR comment")
    except (HttpError, urllib.error.URLError, OSError, ValueError) as e:
        log(f"PR comment failed (non-fatal; fork PRs have read-only tokens): {e}")


# --------------------------------------------------------------------------- main
def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pipelineguard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["scan"])
    p.add_argument("--path", default=".", help="directory to scan (default: .)")
    p.add_argument("--semgrep-config", action="append", default=None, help="Semgrep config/ruleset (repeatable). Default: scanner-config/semgrep-rules.yml if present, else p/ci")
    p.add_argument("--trivy-scanners", default="vuln,misconfig,secret")
    p.add_argument("--trivy-offline", action="store_true", help="pass --skip-db-update to Trivy (DB must already be cached)")
    p.add_argument("--trivy-image", help="also scan this container image (submitted as scanner 'trivy-image', optional by default)")
    p.add_argument("--exclude", action="append", default=[], help="path/glob to exclude from scanning (repeatable)")
    p.add_argument("--skip", action="append", default=[], choices=["semgrep", "trivy"], help="do not run this scanner (server policy will FAIL if it is mandatory)")
    p.add_argument("--timeout", type=int, default=900, help="per-scanner timeout seconds")
    p.add_argument("--url", default=os.environ.get("PIPELINEGUARD_URL"))
    p.add_argument("--allow-insecure-http", action="store_true")
    p.add_argument("--warn-as-failure", action="store_true", help="exit 1 on WARN as well")
    p.add_argument("--pr-comment", action="store_true", help="create/update a pull-request comment (needs GITHUB_TOKEN with pull-requests: write)")
    p.add_argument("--output-dir", default="pipelineguard-output")
    for k in ("commit_sha", "branch", "base_branch", "build_id", "idempotency_key"):
        p.add_argument("--" + k.replace("_", "-"), dest=k)
    p.add_argument("--pr-number", type=int, dest="pr_number")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    token = os.environ.get("PIPELINEGUARD_TOKEN", "")
    try:
        if not args.url or not token:
            raise ValueError("PIPELINEGUARD_URL and PIPELINEGUARD_TOKEN must be set")
        server = validate_server_url(args.url, args.allow_insecure_http)
    except ValueError as e:
        log(f"configuration error: {e}")
        return EXIT_CONFIG
    if not Path(args.path).is_dir():
        log(f"configuration error: --path {args.path} is not a directory")
        return EXIT_CONFIG
    if args.semgrep_config is None:
        default_rules = Path(args.path) / "scanner-config" / "semgrep-rules.yml"
        args.semgrep_config = [str(default_rules)] if default_rules.is_file() else ["p/ci"]
    meta = ci_metadata(args)
    if "commit_sha" not in meta or "branch" not in meta:
        log("configuration error: could not determine commit SHA/branch; pass --commit-sha and --branch")
        return EXIT_CONFIG
    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    submissions = build_scans(args, outdir)
    key = args.idempotency_key or (f"ci-{meta['build_id']}-{meta['commit_sha'][:12]}" if meta.get("build_id") else None)
    payload: dict[str, Any] = {**meta, "scanners": submissions}
    if key and len(key) >= 8:
        payload["idempotency_key"] = "".join(c if (c.isalnum() or c in "._:-") else "-" for c in key)[:128]
    for s in submissions:
        log(f"{s['scanner']}: {s['status']}" + (f" ({s['error']})" if s.get("error") else ""))

    try:
        result = upload(server, token, payload)
    except HttpError as e:
        log(f"server rejected the report ({e}). Failing closed.")
        return EXIT_ERROR
    except RuntimeError as e:
        log(f"{e}. Failing closed: an unverifiable scan is not a passing scan.")
        return EXIT_ERROR
    (outdir / "decision.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    markdown = ""
    try:
        _, markdown = http("GET", f"{server}/api/v1/ci/scans/{result['scan_id']}/report.md", token)
        (outdir / "summary.md").write_text(markdown, encoding="utf-8")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
                fh.write(markdown + "\n")
    except (HttpError, urllib.error.URLError, OSError) as e:
        log(f"could not fetch summary (non-fatal): {e}")
    if args.pr_comment and markdown and meta.get("pr_number"):
        upsert_pr_comment(markdown, int(meta["pr_number"]))

    decision = result.get("decision")
    log(f"DECISION: {decision} - {result.get('summary', '')}")
    log(f"report: {result.get('report_url')}")
    if decision == "FAIL":
        return EXIT_FAIL
    if decision == "WARN":
        return EXIT_FAIL if args.warn_as_failure else EXIT_PASS
    if decision == "PASS":
        return EXIT_PASS
    log(f"unexpected decision {decision!r}; failing closed")
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
