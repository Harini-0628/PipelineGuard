#!/usr/bin/env bash
# Restore a backup into the running stack (DESTRUCTIVE: replaces the public schema). Usage: ./scripts/restore.sh backups/file.sql.gz
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 backup.sql.gz" >&2; exit 2; }
read -r -p "This replaces ALL current data. Type 'restore' to continue: " ok; [ "$ok" = "restore" ] || exit 1
docker compose stop backend
docker compose exec -T db psql -U pipelineguard -d pipelineguard -v ON_ERROR_STOP=1 -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
gunzip -c "$1" | docker compose exec -T db psql -U pipelineguard -d pipelineguard -v ON_ERROR_STOP=1
docker compose start backend
echo "restore complete"
