from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("PG_ENVIRONMENT", "test")
os.environ.setdefault("PG_JWT_SECRET", "test-secret-test-secret-test-secret-123456")
os.environ["PG_DATABASE_URL"] = os.environ.get(
    "PG_TEST_DATABASE_URL", "postgresql+psycopg://pipelineguard:pipelineguard@localhost:5432/pipelineguard_test")
os.environ["PG_ENVIRONMENT"] = "test"
os.environ.setdefault("PG_DEFAULT_POLICY_PATH", str(Path(__file__).resolve().parents[2] / "policies" / "default.yaml"))
os.environ["PG_PUBLIC_BASE_URL"] = "http://testserver"
os.environ["PG_BOOTSTRAP_ADMIN_EMAIL"] = ""
os.environ["PG_BOOTSTRAP_ADMIN_PASSWORD"] = ""

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db import get_engine, reset_engine, session_factory  # noqa: E402
from app.models import Role  # noqa: E402
from app.bootstrap import create_user  # noqa: E402
from app.security import ingest_limiter, login_throttle  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]
ADMIN_PW = "Admin-Password-123"


def load(name: str):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture(scope="session", autouse=True)
def _migrated():
    reset_engine()
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    eng = get_engine()
    with eng.begin() as c:
        c.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    command.upgrade(cfg, "head")
    yield


@pytest.fixture(autouse=True)
def _clean_db(_migrated):
    ingest_limiter.reset()
    login_throttle.reset()
    with get_engine().begin() as c:
        names = [r[0] for r in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'alembic_version'"))]
        c.execute(text("TRUNCATE " + ", ".join(names) + " RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture
def client():
    from app.main import app
    with TestClient(app) as c:  # runs lifespan -> seeds default policy
        yield c


class Api:
    """Small helper wrapping the test client with auth."""

    def __init__(self, client: TestClient):
        self.c = client

    def login(self, email: str, password: str) -> dict[str, str]:
        r = self.c.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}


def make_user(email: str, role: Role, password: str = ADMIN_PW):
    with session_factory()() as db:
        return create_user(db, email, password, role)


@pytest.fixture
def api(client):
    return Api(client)


@pytest.fixture
def admin(api):
    make_user("admin@example.com", Role.ADMIN)
    return api.login("admin@example.com", ADMIN_PW)


@pytest.fixture
def world(client, api, admin):
    """A project with one repository and its ingest token, plus an engineer and a developer who are members."""
    r = client.post("/api/v1/projects", json={"name": "Payments"}, headers=admin)
    assert r.status_code == 201, r.text
    project = r.json()
    r = client.post("/api/v1/repositories", json={"project_id": project["id"], "full_name": "acme/payments-api"}, headers=admin)
    assert r.status_code == 201, r.text
    repo = r.json()
    se = make_user("se@example.com", Role.SECURITY_ENGINEER)
    dev = make_user("dev@example.com", Role.DEVELOPER)
    for u in (se, dev):
        assert client.post(f"/api/v1/projects/{project['id']}/members", json={"user_id": u.id}, headers=admin).status_code == 204
    return {"project": project, "repo": repo, "token": {"Authorization": f"Bearer {repo['ingest_token']}"}, "admin": admin,
            "se": api.login("se@example.com", ADMIN_PW), "dev": api.login("dev@example.com", ADMIN_PW)}


def submission(scanner: str, fixture: str | None, status: str = "succeeded", **kw):
    return {"scanner": scanner, "status": status, "report": load(fixture) if fixture else None, **kw}


def ingest_body(scanners, commit="a" * 40, branch="main", **kw):
    return {"commit_sha": commit, "branch": branch, "scanners": scanners, **kw}
