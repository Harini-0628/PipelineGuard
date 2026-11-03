#!/usr/bin/env bash
# Runs the REAL scanners against the bundled vulnerable sample and a clean sample, against a running PipelineGuard.
# Requires: semgrep and trivy on PATH, PIPELINEGUARD_URL and PIPELINEGUARD_TOKEN set (see README "Run your first scans").
# Trivy runs offline (misconfig+secret) so no vulnerability DB download is needed; drop --trivy-offline/--trivy-scanners
# arguments to also scan dependencies (needs network access to Trivy's DB mirror).
set -uo pipefail
cd "$(dirname "$0")/.."
common=(--semgrep-config scanner-config/semgrep-rules.yml --trivy-scanners misconfig,secret --trivy-offline --branch main)
clean="$(mktemp -d)"; cp tests-data/clean-app/* "$clean"/
echo "=== 1) deliberately vulnerable app (expect FAIL, exit 1) ==="
python3 cli/pipelineguard.py scan --path tests-data/vulnerable-app "${common[@]}" --commit-sha 1111111111111111111111111111111111111111 --output-dir pipelineguard-output/blocked; echo "exit code: $?"
echo; echo "=== 2) clean app (expect PASS, exit 0) ==="
python3 cli/pipelineguard.py scan --path "$clean" "${common[@]}" --commit-sha 2222222222222222222222222222222222222222 --output-dir pipelineguard-output/clean; echo "exit code: $?"
