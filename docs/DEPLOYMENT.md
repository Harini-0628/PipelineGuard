# Deployment guide (Linux VM + Docker Compose)

> The Dockerfiles and Compose files were **not built in the authoring environment** (no Docker available there). CI's `docker-build` job builds both images and validates the compose files; treat your first deployment as the first real test.

## 0. What you must provide
| Item | Notes |
|---|---|
| A Linux VM (Ubuntu 24.04, 2 vCPU / 4 GB is enough to start) | Any provider; no paid PipelineGuard dependency exists. |
| A domain name | A/AAAA record → VM public IP **before** first start (Let's Encrypt validates over port 80/443). |
| An email for ACME | `ACME_EMAIL` (certificate expiry notices). |
| Secrets | `POSTGRES_PASSWORD`, `PG_JWT_SECRET` (`openssl rand -hex 32`), first admin password. |
| GitHub | Per protected repo: Actions secrets `PIPELINEGUARD_URL`, `PIPELINEGUARD_TOKEN`; workflow permissions as in the example. No GitHub App or PAT is required (the built-in `GITHUB_TOKEN` posts PR comments). |
| Optional | An outbound HTTPS webhook receiver (Slack/Teams/etc.) for notifications; outbound access to `cisa.gov` for KEV refresh. |

## 1. Prepare the host
```bash
sudo apt update && sudo apt -y upgrade
sudo apt install -y ufw ca-certificates curl git
# Docker Engine + compose plugin: https://docs.docker.com/engine/install/ubuntu/
sudo ufw default deny incoming && sudo ufw default allow outgoing
sudo ufw allow OpenSSH && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable
```
Never publish 5432. (Docker bypasses ufw for *published* ports; this stack publishes only 80/443 via Caddy and `127.0.0.1:8080`.)

## 2. Configure and start
```bash
git clone <your repo> pipelineguard && cd pipelineguard      # or scp the ZIP contents
cp .env.example .env && chmod 600 .env && $EDITOR .env        # every placeholder, domain, ACME email
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```
The backend entrypoint runs `alembic upgrade head` on start (single replica). For multiple replicas run migrations once as a job: `docker compose run --rm -e PG_RUN_MIGRATIONS=true backend alembic upgrade head` and set `PG_RUN_MIGRATIONS=false` for the replicas.

## 3. Verify
```bash
docker compose ps                                  # all healthy
curl -fsS https://$PIPELINEGUARD_DOMAIN/api/v1/ready
curl -sI https://$PIPELINEGUARD_DOMAIN | grep -i -E 'strict-transport|content-security|x-frame'
docker compose logs backend --tail 50              # JSON lines; look for the bootstrap admin message once
```
Sign in, register a repository, copy its token into the repo's Actions secrets, push a branch. Then **remove `PG_BOOTSTRAP_ADMIN_PASSWORD` from `.env`** and `docker compose up -d`.

## 4. Backups and restore
```bash
./scripts/backup.sh /var/backups/pipelineguard          # pg_dump | gzip, mode 600
# cron (daily 02:15):  15 2 * * *  cd /opt/pipelineguard && ./scripts/backup.sh /var/backups/pipelineguard
./scripts/restore.sh /var/backups/pipelineguard/<file>.sql.gz   # DESTRUCTIVE, asks for confirmation
```
Copy backups off-host and encrypt them (they contain findings, audit logs, raw reports and password hashes). **Rehearse a restore** into a scratch VM before relying on it. Also back up `.env` separately (secret manager or an encrypted vault).

## 5. Upgrade and rollback
1. `./scripts/backup.sh` · 2. `git pull` (or deploy the new tree) · 3. `docker compose ... up -d --build` (migrations run on start).
Rollback: images are rebuilt from source, so check out the previous revision and rebuild. **Migrations are forward-only in practice**; if a release changed the schema, roll back by restoring the pre-upgrade backup (`restore.sh`) *and* the previous code. Tag releases so this is a one-liner.

## 6. Secrets, rotation, hardening notes
* Rotate `PG_JWT_SECRET` → all sessions invalid (intended emergency lever). Rotate repo ingest tokens in the UI (old one dies immediately).
* Keep `.env` out of git and shell history; consider Docker/Compose secrets or a secret manager for larger setups.
* Keep Postgres on the internal network only; the API container has a read-only root FS, no capabilities and a non-root user.
* Put a WAF / global rate limiter at the edge if the instance is internet-facing (the in-app limiter is per worker).
* Monitor: `/api/v1/ready`, container restarts, 5xx rate, auth-failure audit events (`auth.login_failed`).
* Retention: no automatic pruning exists. Suggested: keep audit ≥ 1 year; prune raw reports after 90 days (e.g. `UPDATE scanner_executions SET raw_report = NULL WHERE …`), keeping hashes and findings.

## 7. Remaining operational requirements
This is a **starting point**, not a hardened SaaS: add centralized logging, alerting, OS patching, image scanning of your own images (PipelineGuard's `trivy-image` scanner can scan them), TLS/HSTS review, and a threat-model review for your environment (see SECURITY.md).
