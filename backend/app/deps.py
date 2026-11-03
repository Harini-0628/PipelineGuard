"""FastAPI dependencies: authentication, RBAC, project boundaries, repository ingest tokens."""
from __future__ import annotations

from datetime import UTC, datetime

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import Finding, Project, ProjectMember, Repository, Role, Suppression, User
from app.security import TOKEN_PREFIX, decode_access_token, hash_token, ingest_limiter, tokens_equal

bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    unauth = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    if creds is None or creds.credentials.startswith(TOKEN_PREFIX):
        raise unauth
    try:
        payload = decode_access_token(creds.credentials)
    except jwt.PyJWTError:
        raise unauth from None
    user = db.get(User, payload["sub"])
    if user is None or not user.is_active:
        raise unauth
    return user


def require_roles(*roles: Role):
    allowed = {r.value for r in roles}

    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role for this operation")
        return user

    return dep


def accessible_project_ids(db: Session, user: User) -> set[str] | None:
    """None means unrestricted (administrator)."""
    if user.role == Role.ADMIN.value:
        return None
    return set(db.scalars(select(ProjectMember.project_id).where(ProjectMember.user_id == user.id)))


def ensure_project_access(db: Session, user: User, project_id: str) -> Project:
    project = db.get(Project, project_id)
    ids = accessible_project_ids(db, user)
    if project is None or (ids is not None and project_id not in ids):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")  # do not reveal existence
    return project


def ensure_repo_access(db: Session, user: User, repo_id: str) -> Repository:
    repo = db.get(Repository, repo_id)
    ids = accessible_project_ids(db, user)
    if repo is None or (ids is not None and repo.project_id not in ids):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found")
    return repo


def repo_from_token(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer),
                    db: Session = Depends(get_db)) -> Repository:
    unauth = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing repository token", headers={"WWW-Authenticate": "Bearer"})
    if creds is None or not creds.credentials.startswith(TOKEN_PREFIX):
        raise unauth
    digest = hash_token(creds.credentials)
    s = get_settings()
    if not ingest_limiter.allow(f"{client_ip(request)}:{digest[:12]}", s.ingest_rate_per_minute):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded", headers={"Retry-After": "60"})
    repo = db.scalar(select(Repository).where(Repository.ingest_token_hash == digest))
    if repo is None or not tokens_equal(repo.ingest_token_hash, digest):
        raise unauth
    return repo


def active_suppression_clause(now: datetime | None = None):
    """Correlated EXISTS: an unrevoked, unexpired suppression exists for the finding's repo+fingerprint."""
    now = now or datetime.now(UTC)
    return exists().where(Suppression.repository_id == Finding.repository_id, Suppression.fingerprint == Finding.fingerprint,
                          Suppression.revoked_at.is_(None), Suppression.expires_at > now)
