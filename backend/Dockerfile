# Build context: repository root (needed for policies/). docker build -f backend/Dockerfile .
FROM python:3.12-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY backend/requirements.txt .
RUN pip wheel --wheel-dir /wheels -r requirements.txt

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PG_ENVIRONMENT=production PG_DEFAULT_POLICY_PATH=/app/policies/default.yaml
RUN useradd --system --uid 10001 --create-home --home-dir /home/pg pg
WORKDIR /app
COPY --from=builder /wheels /wheels
COPY backend/requirements.txt .
RUN pip install --no-index --find-links=/wheels -r requirements.txt && rm -rf /wheels
COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini backend/gunicorn.conf.py backend/entrypoint.sh ./
COPY policies ./policies
RUN chown -R pg:pg /app
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/ready', timeout=4).status == 200 else 1)"
ENTRYPOINT ["./entrypoint.sh"]
