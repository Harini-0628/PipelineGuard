# Developer commands (run from the repository root, inside WSL/Linux/macOS).
PY ?= python3
VENV := .venv
BIN := $(VENV)/bin

.PHONY: help setup db-up db-down migrate run-backend run-frontend test test-backend test-frontend lint typecheck build up down logs backup demo zip

help:            ## show targets
	@grep -E '^[a-z-]+:.*##' Makefile | sed 's/:.*##/ -/'

setup:           ## create venv, install backend + frontend dependencies
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -r backend/requirements-dev.txt
	cd frontend && npm ci

db-up:           ## start only PostgreSQL in Docker (published on localhost:5432 for development)
	docker run -d --name pipelineguard-dev-db -e POSTGRES_USER=pipelineguard -e POSTGRES_PASSWORD=pipelineguard \
	  -e POSTGRES_DB=pipelineguard -p 127.0.0.1:5432:5432 postgres:16-alpine
	docker exec pipelineguard-dev-db sh -c 'until pg_isready -U pipelineguard; do sleep 1; done'
	docker exec pipelineguard-dev-db psql -U pipelineguard -c 'CREATE DATABASE pipelineguard_test;'

db-down:         ## stop and remove the dev database container
	-docker rm -f pipelineguard-dev-db

migrate:         ## apply database migrations (uses backend/.env or PG_* variables)
	cd backend && ../$(BIN)/alembic upgrade head

run-backend:     ## dev API server with reload (NEVER use reload in production)
	cd backend && ../$(BIN)/uvicorn app.main:app --reload --port 8000

run-frontend:    ## Vite dev server on :5173 (proxies /api to :8000)
	cd frontend && npm run dev

test-backend:    ## backend tests (needs PostgreSQL; see README)
	cd backend && ../$(BIN)/pytest -q
test-frontend:
	cd frontend && npm test
test: test-backend test-frontend

lint:
	cd backend && ../$(BIN)/ruff check app tests
	cd frontend && npm run lint
typecheck:
	cd backend && ../$(BIN)/mypy app
	cd frontend && npm run typecheck

build:           ## production frontend build
	cd frontend && npm run build

up:              ## docker compose up (needs .env)
	docker compose up -d --build
down:
	docker compose down
logs:
	docker compose logs -f --tail=100
backup:
	./scripts/backup.sh
demo:            ## real scanners against the sample apps (see scripts/demo.sh)
	./scripts/demo.sh
