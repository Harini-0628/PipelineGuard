#!/usr/bin/env bash
# Logical backup of the PipelineGuard database. Usage: ./scripts/backup.sh [output-dir]
set -euo pipefail
out="${1:-backups}"; mkdir -p "$out"
file="$out/pipelineguard-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
docker compose exec -T db pg_dump -U pipelineguard --no-owner pipelineguard | gzip > "$file"
chmod 600 "$file"
echo "wrote $file"
