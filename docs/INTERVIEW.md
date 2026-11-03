# Explaining PipelineGuard in an interview

Everything below describes what is **actually implemented**; where something is only partly verified I say so — saying that out loud is a strength.

## 30-second pitch
"PipelineGuard is a self-hosted security gate for CI/CD. Pipelines run Semgrep and Trivy and ship the raw reports to my FastAPI service. It normalizes findings into one schema, evaluates a versioned, deterministic policy, and returns PASS/WARN/FAIL with the exact rules and findings behind it. The CLI turns that into the job's exit code. Everything is stored in PostgreSQL with an audit trail, and a React dashboard shows posture, trends and remediation. The design principle is *fail closed*: a missing or broken scan can never look like a clean one."

## Architecture in one breath
CI job (scanners + stdlib-only CLI) → `POST /ingest` (per-repo token, idempotency key) → parsers → fingerprinted findings upserted per (repo, branch) under an advisory lock → policy engine (pure function) → decision stored + returned → CLI exit code, job summary, PR comment, optional webhook → dashboard reads the same data.

## Threat model highlights (see docs/SECURITY.md)
Assets: decisions' integrity, findings data, tokens. Untrusted: repo content and scanner output. Key controls: scoped hashed tokens, RBAC + project boundary (404s not 403s), strict schemas, no shell, SSRF guard, no secrets in responses/logs, fail-closed CLI. Honest residual risk: a compromised CI job can lie about *its own* repo's scan; mitigate with runner isolation and branch protection.

## Policy engine talking points
* Pure `evaluate(doc, input, name, version) -> dict`; time is injected → reproducible; order-independent (sorted).
* Rules `PG-001…008` with explicit effects. Mandatory-scanner rule first: *absence of evidence is not evidence of absence*.
* Environments via branch patterns; PRs use the target branch; unmapped ⇒ strictest.
* Suppressions: per-fingerprint, expiring, audited, admin-only for criticals; expiry enforced at evaluation time, `suppressed` is derived so it can't go stale.
* Preview endpoint evaluates a draft against a stored scan without persisting — safe policy change management.
* Risk score is separate (documented formula, missing data adds 0 and is listed as unknown) and **never** feeds the decision. Not ML, and I say so.

## Scanner integrations
Semgrep JSON (`results[]`, CWE metadata, error-level problems ⇒ incomplete ⇒ failed) and Trivy JSON (vulns, misconfigs, secrets, image vs fs). Fingerprints: SAST excludes line numbers (uses order of occurrence within rule+file) so unrelated edits don't cause "new" findings; dependency identity = CVE + lockfile + package + version. Tested with *real* Semgrep and Trivy output. Candidly: Trivy's vulnerability DB couldn't be downloaded in my build sandbox, so dependency/image parsing is tested with schema-faithful synthetic fixtures — first thing I'd do next is run it on a real repo.

## Failure handling you can demo
1. Remove Semgrep from PATH → scanner `missing` → `PG-001` → FAIL, exit 1.
2. Kill the server → CLI retries with the same idempotency key, then exits 2.
3. Garbage report → execution marked failed with `parse_error`, decision FAIL.
4. Timed-out scanner → doesn't resolve its old findings (it proved nothing).
5. Same request twice/6 concurrently → one scan, same decision (unique constraint + advisory lock).

## Trade-offs I'd defend
Server-side parsing (one source of truth) vs. client-side evaluation (works offline) — chose server, CLI fails closed. In-memory rate limiter (simple, per-worker) vs. Redis (extra infra) — documented limitation. JWT in sessionStorage vs. cookies — avoids CSRF, accepts XSS exposure, mitigated by strict CSP. JSON policy editor vs. rich form UI — faster to ship, validated server-side with Pydantic. Python policy engine first; OPA deliberately **not** claimed.

## Honest verification statement
118 backend tests on real PostgreSQL (91 % coverage), lint/type-checks clean, frontend build + 6 tests, real Semgrep/Trivy runs through a live server giving FAIL/exit 1, PASS/exit 0 and missing-scanner FAIL. **Not run:** Docker images/Compose/Caddy, GitHub Actions on GitHub, GitLab, PR comments and webhooks against real services, live KEV feed.

## Likely questions
*How do you stop someone ingesting a fake PASS?* Token per repo, server computes the decision from findings (the client never sends a decision), mandatory scanners must be present; residual: a compromised runner. *Why per-branch findings?* Independent lifecycle and clean "new vs base" comparison. *What breaks at scale?* Raw reports in Postgres, per-finding loop in ingest (could batch/COPY), in-memory limiter — I'd add object storage, bulk upserts and Redis. *How would you add a scanner?* Add a parser returning `ParsedReport`, register it in `PARSERS`, add the name to `ScannerName`/`KNOWN_SCANNERS`, add fixtures and a CLI runner.
