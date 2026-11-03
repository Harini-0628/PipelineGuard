# PipelineGuard

A self-hosted **DevSecOps CI/CD security gate**. CI jobs run Semgrep (SAST) and Trivy (dependencies, misconfiguration, secrets, container images) and send the *original* reports to PipelineGuard. PipelineGuard parses and normalizes the findings, evaluates a versioned policy, returns a deterministic **PASS / WARN / FAIL** with an explanation, stores everything in PostgreSQL, and shows it in a dashboard.

> Honesty note: this README separates what was **executed and verified** from what is **implemented but not exercised** in the build environment. See [Implementation status](#implementation-status) and [Known limitations](#known-limitations). Nothing here claims PipelineGuard is "completely secure" or "compliant" with anything.

## Contents
1. [Problem and goals](#problem-and-goals) · 2. [Architecture](#architecture) · 3. [Stack and design decisions](#stack-and-design-decisions) · 4. [Implementation status](#implementation-status) · 5. [Quick start on Windows/WSL Ubuntu](#quick-start-windowswsl-ubuntu) · 6. [Run your first scans](#run-your-first-scans) · 7. [CI/CD integration](#cicd-integration) · 8. [Policy](#policy) · 9. [API](#api) · 10. [Configuration reference](#configuration-reference) · 11. [Testing](#testing) · 12. [Docker deployment](#docker-deployment) · 13. [Production checklist](#production-checklist) · 14. [Troubleshooting](#troubleshooting) · 15. [Known limitations and roadmap](#known-limitations)

Further docs: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) · [docs/SECURITY.md](docs/SECURITY.md) (threat model) · [docs/INTERVIEW.md](docs/INTERVIEW.md).

## Problem and goals
Teams need one place that answers: *what vulnerabilities are in this build, how bad are they, does the build satisfy our policy, what evidence supports that, and how do we fix it?* PipelineGuard keeps that decision **centralized, explainable, auditable and deterministic**, and treats missing or failed scans as failures instead of silent passes.

## Architecture
```mermaid
flowchart LR
  Dev[Push / PR] --> CI[GitHub Actions job]
  CI -->|runs, no shell| S1[Semgrep]
  CI -->|runs, no shell| S2[Trivy]
  S1 --> CLI[cli/pipelineguard.py]
  S2 --> CLI
  CLI -->|"POST /api/v1/ingest<br/>Bearer repo token + idempotency key"| API[FastAPI]
  subgraph PipelineGuard
    API --> N[Parsers + normalization + fingerprints]
    N --> DB[(PostgreSQL)]
    N --> P[Policy engine<br/>pure, deterministic]
    P --> R[Risk scoring<br/>heuristic, separate]
    P --> DB
    API --> W[Webhook notifier<br/>SSRF-guarded]
  end
  API -->|"decision + exit_code"| CLI
  CLI -->|exit 0 / 1| CI
  CLI -->|upsert comment| PR[GitHub PR comment]
  UI[React dashboard] -->|JWT| API
```
**Boundary:** scanners execute in *your CI runners*, never in the API process. The API only parses JSON and never executes repository code. For untrusted repositories use ephemeral, isolated runners (see [docs/SECURITY.md](docs/SECURITY.md)).

Layers: CI/CD integration (`cli/`, `.github/actions/pipelineguard`) → scanner execution (CLI) → parsing/normalization/dedup (`backend/app/services/parsers`, `normalize.py`) → policy engine (`services/policy.py`) → risk prioritization (`services/risk.py`) → reports (`services/report.py`) and notifications (`services/webhooks.py`) → FastAPI (`backend/app/api/v1`) → PostgreSQL (`models.py`, `alembic/`) → React dashboard (`frontend/`).

## Stack and design decisions
Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, PostgreSQL 16, psycopg 3, argon2 password hashing, PyJWT · React 19 + TypeScript + Vite + Tailwind 4 + Recharts + React Router · Semgrep, Trivy, GitHub Actions, Docker Compose, Caddy (HTTPS), gunicorn+uvicorn workers. All Python dependencies are pinned in `backend/requirements*.txt`; the frontend is locked by `package-lock.json`.

| Decision | Why |
|---|---|
| Server-side parsing; CLI uploads **raw** scanner reports | One normalization/policy implementation, reproducible evidence (report SHA-256 and raw report are stored). |
| Pure-function policy engine | Same findings + same policy version + same `evaluated_at` ⇒ identical result; trivially unit-testable. OPA/Rego is **not** implemented (not claimed). |
| Scanner failure ≠ clean | Missing/failed/timeout/unparseable mandatory scanners trigger `PG-001` (FAIL). A success claim without a report is downgraded to failed. |
| Fail closed in CI | Server unreachable / token rejected ⇒ CLI exits 2 (pipeline fails). |
| Findings keyed by `(repository, branch, fingerprint)` | Independent lifecycle per branch; line numbers are excluded from SAST fingerprints so unrelated edits don't create "new" findings. |
| `suppressed` is a *derived* status | Computed from active (unrevoked, unexpired) suppressions at evaluation time; expiry can never be bypassed by stale state. |
| Risk score separate from policy | Heuristic ordering aid only; the policy never reads it. Formula documented in `services/risk.py`. |
| Per-repository ingest tokens (SHA-256 at rest) | CI credentials are scoped to one repository and rotatable; humans use short-lived JWTs. |
| Postgres advisory lock per repository during ingest | Concurrent submissions are serialized; idempotency enforced by a unique constraint. |

## Implementation status
Legend: ✅ implemented **and verified here** · 🟡 implemented, verified only with mocks/static checks · ⛔ not implemented.

| Area | Status | Evidence / note |
|---|---|---|
| Backend API, auth (JWT, argon2), RBAC (admin / security_engineer / developer), project boundaries | ✅ | 118 automated tests against PostgreSQL 16 |
| Alembic migrations from empty database | ✅ | Run by the test session on a fresh schema |
| Semgrep integration (real tool) | ✅ | Semgrep 1.182.1 run through the CLI against a live server |
| Trivy misconfiguration + secret scanning (real tool) | ✅ | Trivy 0.76.1, offline mode, real output parsed |
| Trivy **dependency/image vulnerability** parsing | 🟡 | The sandbox could not download Trivy's vulnerability DB, so these parsers are tested with **synthetic fixtures that follow Trivy's JSON schema** (`trivy_vulns_synthetic.json`, `trivy_image_synthetic.json`, CVE ids `CVE-2099-*`). Run it once against a real project to confirm. |
| Policy engine, suppressions + expiry, environments, versioning, preview | ✅ | Unit + API tests |
| Idempotent + concurrent ingestion | ✅ | 6-thread race test, replay test |
| CLI exit behaviour (PASS→0, FAIL→1, WARN configurable, outage→2, missing/crashed/timed-out scanner→FAIL) | ✅ | Live server + fake scanner executables, and real scanners manually |
| Reports (JSON download, Markdown) | ✅ | |
| Dashboard (7 pages) | ✅ | Walked through in headless Chromium against the live API with real scan data; lint/typecheck/build/6 unit tests pass. A React key warning found during the walk-through was fixed afterwards and **not re-run in the browser**. |
| Production server (gunicorn + uvicorn workers), safety guards for weak secrets / demo mode | ✅ | Started locally; `/ready` OK, no `Server` header; production refuses weak secret |
| Dependency audits | ✅ | `pip-audit` and `npm audit --omit=dev`: 0 known vulnerabilities (at build time) |
| GitHub Actions composite action + workflows | 🟡 | YAML parses; actions pinned to commit SHAs; **never executed on GitHub** |
| PR comment upsert (no duplicates) | 🟡 | Unit-tested with mocked HTTP; not run against the GitHub API |
| Webhook notifications + SSRF guard | 🟡 | Guard unit-tested; delivery tested with a mock transport only |
| CISA KEV enrichment | 🟡 | Mock-feed tests; live feed not reachable from the sandbox. Unknown ≠ safe is enforced. |
| Docker images, Compose, Caddy HTTPS | 🟡 | **No Docker in the build sandbox**: Dockerfiles/compose were written and YAML-validated but never built or started. CI includes a `docker-build` job that will. |
| GitLab CI | 🟡 | Documented example only (`examples/gitlab-ci/`), not run. The CLI reads GitLab's `CI_*` variables. |
| OPA/Rego, EPSS, Syft SBOM, OWASP Dependency-Check, scan-queue workers | ⛔ | Optional in the spec; not built, not claimed. |

## Quick start on Windows/WSL Ubuntu
Work **inside the WSL filesystem** (e.g. `~/pipelineguard`), not under `/mnt/c`, for speed and correct file permissions.

```bash
unzip pipelineguard.zip -d ~ && cd ~/pipelineguard
code .                                   # VS Code with the WSL extension
```
### Prerequisites
Python 3.12+, Node 20+ (22 recommended), `make`, and PostgreSQL 16 — via **either** Docker Desktop (WSL integration on) **or** native packages. Optional for real scans: Semgrep and Trivy.

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip make curl git
# Node 22: https://nodejs.org (or nvm). Docker: Docker Desktop -> Settings -> Resources -> WSL integration.
```
### 1. Database (pick one)
```bash
# A) Docker
make db-up                               # PostgreSQL 16 on 127.0.0.1:5432 (+ pipelineguard_test DB)
# B) native
sudo apt install -y postgresql && sudo service postgresql start
sudo -u postgres psql -c "CREATE USER pipelineguard WITH PASSWORD 'pipelineguard' CREATEDB;"
sudo -u postgres psql -c "CREATE DATABASE pipelineguard OWNER pipelineguard;"
sudo -u postgres psql -c "CREATE DATABASE pipelineguard_test OWNER pipelineguard;"
```
(`pipelineguard/pipelineguard` is a **development-only** credential for a local DB. Never reuse it anywhere reachable.)
### 2. Install, configure, migrate, run
```bash
make setup                               # venv + backend deps + npm ci
cp backend/.env.example backend/.env
sed -i "s/^PG_JWT_SECRET=.*/PG_JWT_SECRET=$(openssl rand -hex 32)/" backend/.env
sed -i "s/^PG_BOOTSTRAP_ADMIN_PASSWORD=.*/PG_BOOTSTRAP_ADMIN_PASSWORD=Change-Me-Please-123/" backend/.env   # choose your own
make migrate
make run-backend                         # terminal 1 -> http://127.0.0.1:8000/api/v1/docs
make run-frontend                        # terminal 2 -> http://localhost:5173
```
Sign in with the bootstrap admin, **create a project, register a repository**, and copy the ingest token (shown once).

> The bootstrap admin is only created when the users table is empty. Remove `PG_BOOTSTRAP_ADMIN_PASSWORD` afterwards. More users: `cd backend && ../.venv/bin/python -m app.manage create-user --email you@example.com --role security_engineer`, or `POST /api/v1/users` as an admin.

## Run your first scans
Install the scanners (pinned versions were used for verification):
```bash
.venv/bin/pip install semgrep==1.182.1                      # then: export PATH="$PWD/.venv/bin:$PATH"
# Trivy 0.76.1: https://trivy.dev/latest/getting-started/installation/  (single static binary)
```
```bash
export PIPELINEGUARD_URL=http://127.0.0.1:8000              # http is accepted for localhost only
export PIPELINEGUARD_TOKEN=pgt_...                          # the token you copied
make demo
```
`scripts/demo.sh` scans `tests-data/vulnerable-app` (deliberately insecure; **never deploy it**) and `tests-data/clean-app`:
* vulnerable app → **FAIL**, CLI exit code **1** · clean app → **PASS**, exit **0**.
* Remove `semgrep` from `PATH` and re-run → **FAIL** (`PG-001`, scanner `missing`), exit 1: a scanner outage is never a pass.

The demo uses `--trivy-scanners misconfig,secret --trivy-offline` so no vulnerability DB download is needed. For dependency scanning run the CLI without those flags (Trivy then downloads its DB; needs outbound access to Trivy's database mirrors).

Real captured output: [`docs/examples/blocked-scan-summary.md`](docs/examples/blocked-scan-summary.md), [`blocked-scan-decision.json`](docs/examples/blocked-scan-decision.json), [`clean-scan-summary.md`](docs/examples/clean-scan-summary.md). Excerpt of the decision (abridged):
```json
{ "decision": "FAIL", "exit_code": 1,
  "summary": "FAIL: PG-003 High findings; PG-006 Medium findings (environment: production, policy: default v1)" }
```
Optional demo dataset in the dashboard: `PG_SEED_DEMO_DATA=true` (development only; refused in production; creates a clearly named "DEMO (sample data)" project through the normal ingest path).

## CI/CD integration
**GitHub Actions** (primary). Copy [`examples/github-actions/pipelineguard.yml`](examples/github-actions/pipelineguard.yml), add repository secrets `PIPELINEGUARD_URL` and `PIPELINEGUARD_TOKEN`, and reference the composite action (`.github/actions/pipelineguard`) at a **commit SHA you have reviewed**. It: checks out, installs pinned Semgrep + Trivy, runs both without a shell, uploads the raw reports, evaluates the policy server-side, writes a job summary, upserts one PR comment (identified by a hidden marker, so no duplicates), uploads `pipelineguard-output/` as an artifact, and exits non-zero on FAIL. Permissions are least-privilege (`contents: read`, plus `pull-requests: write` only for the comment). PR comments are skipped gracefully for fork PRs (read-only token).

Exit policy: `0` PASS · `0` WARN (set `warn-as-failure: "true"` to make it `1`) · `1` FAIL · `2` operational error (fail closed) · `3` configuration error. Scanner execution errors are forwarded verbatim and recorded; they are never masked.

**Ingest contract** (any CI): `POST /api/v1/ingest` with `Authorization: Bearer pgt_…` and a JSON body `{commit_sha, branch, base_branch?, pr_number?, build_id?, idempotency_key?, scanners:[{scanner, status, exit_code, version, started_at, finished_at, error, stderr_tail, report}]}`. Responses: `201` created, `200` idempotent replay (same key ⇒ same scan and decision), `401`, `422`, `413`, `429`. Two-phase flow also exists (`POST /scans`, `POST /scans/{id}/report`, `POST /scans/{id}/cancel`). **GitLab:** see the documented, not-live-tested example.

## Policy
Default: [`policies/default.yaml`](policies/default.yaml) (seeded as the global policy on first start). Branch → environment via first matching pattern (for PRs the **target** branch decides; unmapped ⇒ `default_environment`, which defaults to the strictest). Rules:

| Rule | Effect | Meaning |
|---|---|---|
| PG-001 | FAIL | A mandatory scanner is missing, failed, timed out, or its report was unparseable |
| PG-002 / PG-003 | FAIL | Active critical / high findings exceed `max_critical` / `max_high` |
| PG-004 | FAIL | Any active finding flagged as known-exploited (CISA KEV; **unknown is not safe and not unsafe**) |
| PG-005 | FAIL | Any possible committed secret (any severity) |
| PG-006 | WARN | Active medium findings exceed `warn_medium_above` |
| PG-007 | WARN | An optional scanner (e.g. `trivy-image`) did not succeed |
| PG-008 | none | Low/info findings are allowed and reported |

Every decision records policy name/version, environment, timestamp, each rule with its threshold, count, explanation and the exact responsible findings, mandatory-check problems, and applied/expired suppressions. Suppressions are per finding fingerprint, require a reason (≥10 chars) and an expiry (≤ `PG_SUPPRESSION_MAX_DAYS`), only admins may suppress *critical* findings, expired/revoked ones never apply, and all actions are audited. Edit policies in **Policies** (JSON editor): preview against any stored scan *without enforcing*, then save as a new immutable version. Project-specific policies override the global one; global policies are admin-only.

## API
Interactive OpenAPI: `/api/v1/docs` (spec at `/api/v1/openapi.json`). Groups: health (`/health`, `/ready`), auth/users, projects/repositories, scans (`/ingest`, `/scans`, `/scans/{id}/report.json|.md`), findings (filter/search/sort/paginate, status, suppressions), policies (versions, preview), `/dashboard/overview|trends`, `/integrations/*`, `/audit`. Errors are `{error, detail, request_id}`; validation errors never echo submitted values.

## Configuration reference
All settings are environment variables prefixed `PG_` (see `.env.example`). Docker Compose additionally reads `POSTGRES_PASSWORD`, `PIPELINEGUARD_DOMAIN`, `ACME_EMAIL`.

| Variable | Default | Notes |
|---|---|---|
| `PG_ENVIRONMENT` | `production` | `development` / `test` relax only the secret-length check; the image sets `production` |
| `PG_DATABASE_URL` | local dev URL | `postgresql+psycopg://user:pass@host:5432/db` |
| `PG_JWT_SECRET` | *(required)* | ≥32 chars in production; app refuses to start otherwise |
| `PG_JWT_TTL_MINUTES` | 60 | Access-token lifetime |
| `PG_CORS_ORIGINS` | empty | Comma-separated explicit origins; `*` is ignored. Empty = same-origin only |
| `PG_PUBLIC_BASE_URL` | `http://localhost:8000` | Used in report/PR links |
| `PG_MAX_BODY_BYTES` | 26214400 | Request size limit (413) |
| `PG_INGEST_RATE_PER_MINUTE` | 60 | Per token+IP, per worker process |
| `PG_LOGIN_MAX_ATTEMPTS` / `PG_LOGIN_LOCKOUT_SECONDS` | 5 / 300 | Per IP+email, per worker process |
| `PG_SUPPRESSION_MAX_DAYS` | 180 | Maximum suppression lifetime |
| `PG_STORE_RAW_REPORTS` | true | Keep raw scanner JSON in the DB (evidence; grows storage) |
| `PG_BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` | empty | One-time first admin (only if no users exist) |
| `PG_SEED_DEMO_DATA` | false | Rejected in production |
| `PG_ALLOW_PRIVATE_WEBHOOK_TARGETS` | false | Rejected in production |
| `PG_KEV_FEED_URL` | CISA feed | Used by the admin "refresh KEV" action |
| `PG_RUN_MIGRATIONS` | true | Container entrypoint runs `alembic upgrade head` |

## Testing
```bash
make test-backend      # 118 tests; needs PostgreSQL and the pipelineguard_test DB (PG_TEST_DATABASE_URL overrides the URL)
make test-frontend     # vitest
make lint              # ruff + eslint
make typecheck         # mypy + tsc
make build             # production frontend build
cd backend && ../.venv/bin/alembic upgrade head   # migrations
```
**Results recorded at packaging time** (sandbox: Ubuntu 24, Python 3.12.3, Node 22, PostgreSQL 16 from apt): backend `118 passed`, 91 % line coverage of `app/`; `ruff` and `mypy` clean (39 source files); frontend `eslint` clean, `tsc` clean, `6 passed`, `vite build` OK; `pip-audit` / `npm audit --omit=dev` found nothing. Test groups: parser/fingerprint unit tests, policy/suppression/risk/SSRF unit tests, API integration (authn/authz, cross-project access, idempotency, concurrency, lifecycle, policy tampering, reports, dashboard, audit), end-to-end vertical slice, and CLI exit-code tests against a live server. Fixtures: `backend/tests/fixtures/` — `semgrep_real.json` and `trivy_config_secret_real.json` are **real tool output**; `*_synthetic.json` are hand-written to Trivy's schema; `malformed.json`/`trivy_clean.json`/`semgrep_clean.json` cover bad/clean inputs. No dangerous payloads are executed anywhere.

## Docker deployment
```bash
cp .env.example .env                       # fill every placeholder (openssl rand -hex 32)
docker compose up -d --build               # db + backend + web (web on 127.0.0.1:8080)
docker compose ps && curl -fsS http://127.0.0.1:8080/api/v1/ready
# Public HTTPS (needs DNS + ports 80/443):
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```
Containers: non-root, `cap_drop: ALL`, `no-new-privileges`, read-only root FS for the API, DB unpublished, memory limits, health checks. **A successful `docker compose up` is not a hardened internet deployment** — complete the checklist below and read [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (VM, firewall, backups, rollback). *These files have not been built in the authoring environment (no Docker there); expect to fix small environment issues on first run and please report them.*

## Production checklist
- [ ] Domain with DNS A/AAAA → host; ports 80/443 open, everything else closed (`ufw`); Postgres never exposed.
- [ ] Random `PG_JWT_SECRET` and `POSTGRES_PASSWORD`; `.env` mode 600, outside git; remove `PG_BOOTSTRAP_ADMIN_PASSWORD` after first login.
- [ ] `PG_PUBLIC_BASE_URL=https://…`; `PG_CORS_ORIGINS` empty unless you host the UI elsewhere.
- [ ] Backups scheduled (`scripts/backup.sh`) and a restore rehearsal done (`scripts/restore.sh`).
- [ ] CI uses ephemeral/isolated runners for untrusted code; the composite action is pinned to a reviewed SHA.
- [ ] Rate limiting/WAF at the proxy for strict global limits (in-app limiter is per worker).
- [ ] Log shipping + alerting on `/ready`, 5xx, auth failures; retention policy for reports/audit (suggested: audit ≥ 1 year, raw reports 90 days — no automatic pruning exists yet).
- [ ] Update plan for base images and pinned dependencies (CI runs `pip-audit`/`npm audit`).

## Troubleshooting
| Symptom | Fix |
|---|---|
| `PG_JWT_SECRET must be set…` at start | Set a ≥32-char secret (production) / ≥16 (development). |
| `connection refused` on 5432 | Start Postgres (`sudo service postgresql start` in WSL, or `make db-up`). In WSL, services do not auto-start after a restart. |
| Tests: `password authentication failed` | Create the `pipelineguard` role/DBs as in step 1, or set `PG_TEST_DATABASE_URL`. |
| CLI exit 2 "upload failed" | Wrong `PIPELINEGUARD_URL`, server down, or token rotated; the pipeline fails closed on purpose. |
| CLI exit 3 | `PIPELINEGUARD_URL`/`TOKEN` missing, `http://` to a non-localhost host, or commit/branch undetectable (pass `--commit-sha --branch`). |
| Decision FAIL with `PG-001` | A mandatory scanner is missing/failed — open the scan's *Scanner executions* panel for the exact error. |
| Trivy "failed to download vulnerability DB" | Runner has no access to Trivy's DB mirror; allow egress or pre-cache the DB (`--trivy-offline` then requires a cached DB). |
| Semgrep rule ids look like `scanner-config.pg.python…` | Semgrep prefixes ids with the config's relative path. Always run from the same working directory/config path so fingerprints stay stable. |
| Blank dashboard after login in dev | Backend must run on :8000 (Vite proxies `/api`). |
| Windows line endings break `*.sh` | `git config core.autocrlf input` and re-checkout, or `dos2unix scripts/*.sh backend/entrypoint.sh`. |

## Known limitations
* Rate limiting and login lockout are **per worker process** (in memory); use a proxy for global limits. Restarting resets them.
* Access token is kept in `sessionStorage` (XSS exposure vs. cookie CSRF trade-off); there are no refresh tokens or token revocation list (rotate `PG_JWT_SECRET` to invalidate all sessions).
* Webhook delivery re-validates the URL and never follows redirects but **does not pin the resolved IP** (DNS-rebinding window). Webhooks and user management are API/CLI-only (the UI lists and displays them).
* The default Semgrep ruleset is a **small illustrative set** (6 rules) so scans work offline; use real rulesets (e.g. `p/ci`) in practice.
* Findings are matched by fingerprint; renamed files appear as a resolved + a new finding.
* Raw reports are stored in PostgreSQL (can be large); no automatic retention pruning.
* Not implemented: OPA/Rego, EPSS, SBOM/Syft, OWASP Dependency-Check, queued server-side scan workers, GitLab merge-request notes, SSO/MFA, multi-tenancy beyond project membership.
* Environment-specific verification gaps are listed in [Implementation status](#implementation-status).

**Roadmap (priority):** 1) build and smoke-test Docker images in CI and fix findings; 2) run on GitHub against a real repo (SHA-pinned action, PR comments); 3) EPSS/KEV scheduled refresh; 4) UI for users/webhooks/suppression review queue; 5) SBOM (Syft) + OPA policy backend; 6) shared rate limiter + token revocation; 7) retention jobs; 8) GitLab MR notes.
