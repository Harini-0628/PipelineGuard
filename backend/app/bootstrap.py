"""Startup initialisation: default policy, optional bootstrap admin. Demo data is opt-in and never in production."""
from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Role, User
from app.security import hash_password, validate_password_strength
from app.services.policy_store import seed_default_policy

log = logging.getLogger("pipelineguard.bootstrap")


def create_user(db: Session, email: str, password: str, role: Role, full_name: str = "") -> User:
    validate_password_strength(password)
    user = User(email=email.strip().lower(), full_name=full_name, password_hash=hash_password(password), role=role.value)
    db.add(user)
    db.commit()
    return user


def bootstrap(db: Session) -> None:
    s = get_settings()
    seed_default_policy(db)
    if s.bootstrap_admin_email and s.bootstrap_admin_password:
        if (db.scalar(select(func.count()).select_from(User)) or 0) == 0:
            create_user(db, s.bootstrap_admin_email, s.bootstrap_admin_password, Role.ADMIN, "Bootstrap Administrator")
            log.info("bootstrap administrator created; remove PG_BOOTSTRAP_ADMIN_PASSWORD from the environment now")
    if s.seed_demo_data:
        from app.demo import seed_demo
        seed_demo(db)
