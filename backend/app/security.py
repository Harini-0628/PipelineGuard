"""Password hashing, JWTs, repository ingest tokens, and small in-process rate limiting."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import get_settings

_ph = PasswordHasher()
TOKEN_PREFIX = "pgt_"


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password_strength(password: str) -> None:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    if password.lower() == password or password.upper() == password or not any(c.isdigit() for c in password):
        raise ValueError("password must mix upper/lower case letters and include a digit")


def create_access_token(user_id: str, role: str) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    payload = {"sub": user_id, "role": role, "iat": now, "exp": now + timedelta(minutes=s.jwt_ttl_minutes), "typ": "access"}
    return jwt.encode(payload, s.jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> dict[str, str]:
    payload = jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    if payload.get("typ") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return payload


def generate_ingest_token() -> tuple[str, str, str]:
    """Return (plaintext, sha256 hex digest, display prefix). The plaintext is shown exactly once."""
    plain = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return plain, hash_token(plain), plain[:10]


def hash_token(token: str) -> str:
    # High-entropy random tokens: a fast hash is appropriate (no need for a slow KDF).
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class SlidingWindowLimiter:
    """Per-process limiter. With multiple workers each worker enforces its own window; put a reverse-proxy
    or shared limiter in front for strict global limits (documented in README)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()


ingest_limiter = SlidingWindowLimiter()


class LoginThrottle:
    def __init__(self) -> None:
        self._fails: dict[str, list[float]] = defaultdict(list)

    def blocked(self, key: str) -> bool:
        s = get_settings()
        now = time.monotonic()
        self._fails[key] = [t for t in self._fails[key] if now - t < s.login_lockout_seconds]
        return len(self._fails[key]) >= s.login_max_attempts

    def fail(self, key: str) -> None:
        self._fails[key].append(time.monotonic())

    def clear(self, key: str) -> None:
        self._fails.pop(key, None)

    def reset(self) -> None:
        self._fails.clear()


login_throttle = LoginThrottle()
