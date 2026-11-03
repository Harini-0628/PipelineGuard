#!/bin/sh
set -eu
# Apply migrations, then start the production server. With several replicas run migrations as a separate one-off job instead.
if [ "${PG_RUN_MIGRATIONS:-true}" = "true" ]; then
  alembic upgrade head
fi
exec gunicorn -c gunicorn.conf.py app.main:app
