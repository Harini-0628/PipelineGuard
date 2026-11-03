# Security model and threat model (as implemented)

PipelineGuard is security-sensitive: it decides what ships and stores vulnerability data. This document states the assets, trust boundaries, controls that exist **in code**, and what is *not* covered. It does not claim the system is "secure" or "compliant".

## Assets
Vulnerability/finding data (a map of weaknesses), policy decisions (integrity matters: a forged PASS ships vulnerable code), repository ingest tokens, user credentials/JWT secret, audit log, raw scanner reports (may contain file paths and snippets).

## Trust boundaries and actors
| Actor | Trust | Interface |
|---|---|---|
| Developer/engineer/admin (human) | Authenticated, role-limited | Dashboard → `/api/v1` with JWT |
| CI job holding a repo ingest token | Trusted for **one repository** only | `/ingest`, `/scans*`, `/ci/scans/*` |
| Repository content being scanned | **Untrusted** | Only ever touched by scanners in CI, never by the API |
| Scanner output (JSON) | Untrusted input | Parsed with strict validation; malformed ⇒ failed execution |
| Webhook receivers | External | Outbound only, SSRF-guarded |

## Threats and controls (STRIDE-oriented)
| Threat | Control | Verified by |
|---|---|---|
| Forged/replayed ingest | Per-repo bearer token (SHA-256 at rest, constant-time compare), rate limit, idempotency key unique per repo; replays return the original decision | `test_invalid_ingest_token_rejected`, idempotency/concurrency tests |
| Scanner failure masquerading as clean | `PG-001`; success-without-report and unparseable reports downgraded to failed; resolved-marking only for scanners that *succeeded* | `test_scanner_failure_is_never_a_clean_pass`, `test_failed_scanner_does_not_resolve_its_findings` |
| Policy tampering / privilege escalation | RBAC; global policies admin-only; project policy needs membership; versions immutable; every change audited | `test_policy_tampering_blocked_for_other_projects`, role tests |
| Cross-project data access (IDOR) | Every read/write resolves the repo→project and checks membership; non-members get 404 (no existence leak) | `test_cross_project_access_denied` |
| Suppression abuse | Reason ≥10 chars, mandatory expiry ≤ max, critical needs admin, expired/revoked never apply, audited | suppression tests |
| Credential attacks | argon2 hashing, password-strength rule, per-IP+email lockout (per process), generic error + dummy hash on unknown user, JWT `exp`/`typ` enforced, `alg=none` rejected | auth tests |
| Injection | SQLAlchemy parameterized queries only; strict Pydantic models (`extra=forbid`); no shell anywhere (`subprocess` argv lists) | filter-injection test, code review |
| SSRF via webhooks | https only, no credentials/odd ports, deny private/loopback/link-local/metadata ranges (after DNS resolution), no redirects, re-validated at send time | `test_ssrf.py`, webhook tests |
| Information disclosure | Secrets never returned (only "configured"); webhook URLs redacted; validation errors never echo input; generic 500s with request id; Trivy secret *match values are never stored* | `test_secrets_not_exposed_in_responses`, `test_trivy_secret_never_stores_match_value` |
| DoS | Body size limit (413), ingest rate limit (429), gunicorn limits, pagination caps | tests for 413/429 |
| CSRF/XSS | Bearer tokens (no ambient cookies) ⇒ no CSRF; React escaping; strict CSP in nginx; no `dangerouslySetInnerHTML`; external links `rel=noopener noreferrer` | design/review |
| Supply chain | Pinned Python deps, npm lockfile, Actions pinned to commit SHAs, CI `pip-audit`/`npm audit` | audits run at build time |
| CI token leakage | CLI strips `PIPELINEGUARD_TOKEN`/`GITHUB_TOKEN` from the scanner environment; composite action passes inputs via env, not shell interpolation | `test_ci_secrets_are_not_passed_to_scanners` |
| Production misconfiguration | App refuses to start in production with a weak JWT secret, demo seed, or private webhook targets | manual check recorded in README |

## Execution model for untrusted repositories
Scanning untrusted code (fork PRs, third-party repos) must happen on **ephemeral, isolated runners** with no access to secrets other than the ingest token (and prefer no secrets at all for fork PRs: use `pull_request`, never `pull_request_target` with checkout of PR code). Semgrep and Trivy read files; they do not run project code, but parsers have had vulnerabilities — keep them updated and sandboxed. PipelineGuard's API/containers never mount the Docker socket and run no privileged containers.

## Not covered / residual risk
Per-worker (not global) rate limits; `sessionStorage` token; no MFA/SSO; no token revocation list; DNS-rebinding window for webhooks (no IP pinning); a compromised CI job with a valid ingest token can submit false-clean reports for *its own repository* (mitigate with protected branches, required checks, and runner isolation — the server cannot verify that a scanner really ran); no encryption at rest beyond what your disk/DB provides; the bundled Semgrep ruleset is illustrative. Dependency data is only as good as Trivy's DB freshness.
