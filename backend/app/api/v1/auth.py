from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.deps import client_ip, current_user, require_roles
from app.models import Role, User
from app.schemas import LoginRequest, Page, TokenResponse, UserCreate, UserOut, UserUpdate
from app.security import (
    create_access_token, hash_password, login_throttle, validate_password_strength, verify_password,
)
from app.services import audit

router = APIRouter(tags=["auth"])
_DUMMY = hash_password("not-a-real-password-for-timing")


@router.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    email = body.email.strip().lower()
    key = f"{client_ip(request)}:{email}"
    if login_throttle.blocked(key):
        raise HTTPException(429, "Too many failed attempts; try again later")
    user = db.scalar(select(User).where(User.email == email))
    ok = verify_password(body.password, user.password_hash if user else _DUMMY)  # constant-ish time either way
    if not user or not ok or not user.is_active:
        login_throttle.fail(key)
        audit.record(db, actor=email, action="auth.login_failed", ip=client_ip(request))
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    login_throttle.clear(key)
    audit.record(db, actor=user.email, action="auth.login", target_type="user", target_id=user.id, ip=client_ip(request))
    db.commit()
    return TokenResponse(access_token=create_access_token(user.id, user.role), expires_in=get_settings().jwt_ttl_minutes * 60)


@router.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> User:
    return user


@router.get("/users", response_model=Page[UserOut])
def list_users(limit: int = 50, offset: int = 0, db: Session = Depends(get_db), _: User = Depends(require_roles(Role.ADMIN))):
    limit = max(1, min(limit, 200))
    total = db.scalar(select(func.count()).select_from(User)) or 0
    items = db.scalars(select(User).order_by(User.created_at).limit(limit).offset(offset)).all()
    return Page[UserOut](items=[UserOut.model_validate(u) for u in items], total=total, limit=limit, offset=offset)


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db), admin: User = Depends(require_roles(Role.ADMIN))):
    try:
        validate_password_strength(body.password)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    email = body.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "A user with this email already exists")
    user = User(email=email, full_name=body.full_name, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.flush()
    audit.record(db, actor=admin.email, action="user.created", target_type="user", target_id=user.id,
                 details={"email": email, "role": body.role}, ip=client_ip(request))
    db.commit()
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: str, body: UserUpdate, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require_roles(Role.ADMIN))):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    if user.id == admin.id and (body.is_active is False or (body.role and body.role != Role.ADMIN.value)):
        raise HTTPException(409, "Administrators cannot demote or deactivate themselves")
    changes: dict[str, object] = {}
    if body.role and body.role != user.role:
        changes["role"] = {"from": user.role, "to": body.role}
        user.role = body.role
    if body.is_active is not None and body.is_active != user.is_active:
        changes["is_active"] = {"from": user.is_active, "to": body.is_active}
        user.is_active = body.is_active
    if changes:
        audit.record(db, actor=admin.email, action="user.updated", target_type="user", target_id=user.id, details=changes,
                     ip=client_ip(request))
    db.commit()
    return user
