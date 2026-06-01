"""Signed session cookies for authenticated users."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from scanners.users.models import User, UserRole
from scanners.users.repository import UserRepository

SESSION_COOKIE = "dast_session"
SESSION_MAX_AGE = 86400 * 7
SESSION_SECRET = os.environ.get("DAST_SESSION_SECRET") or secrets.token_hex(32)


def session_cookie_secure() -> bool:
    """Secure cookies in production (HTTPS). Set DAST_COOKIE_SECURE=false for local HTTP dev."""
    return os.environ.get("DAST_COOKIE_SECURE", "true").lower() in ("1", "true", "yes")


def session_cookie_kwargs(*, max_age: int | None = None) -> dict:
    """Shared Set-Cookie flags for session tokens."""
    return {
        "max_age": SESSION_MAX_AGE if max_age is None else max_age,
        "httponly": True,
        "samesite": "lax",
        "secure": session_cookie_secure(),
    }


@dataclass
class SessionUser:
    id: str
    email: str
    name: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN.value

    @classmethod
    def from_user(cls, user: User) -> SessionUser:
        return cls(
            id=user.id,
            email=user.email,
            name=user.name,
            role=user.role,
        )


def create_session_token(user_id: str) -> str:
    ts = str(int(time.time()))
    payload = f"v2:{user_id}:{ts}"
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}:{sig}"


def create_legacy_session_token(username: str) -> str:
    """Legacy v1 token (username:ts:sig) for local-dev compatibility."""
    ts = str(int(time.time()))
    payload = f"{username}:{ts}"
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}:{sig}"


def verify_session_token(token: str) -> Optional[str]:
    """Return user_id (v2) or username (v1 legacy) if valid."""
    if not token:
        return None
    parts = token.split(":")
    if len(parts) == 3:
        username, ts_str, sig = parts
        payload = f"{username}:{ts_str}"
        if not _check_sig(payload, sig):
            return None
        if not _check_ts(ts_str):
            return None
        return f"legacy:{username}"
    if len(parts) == 4 and parts[0] == "v2":
        _, user_id, ts_str, sig = parts
        payload = f"v2:{user_id}:{ts_str}"
        if not _check_sig(payload, sig):
            return None
        if not _check_ts(ts_str):
            return None
        return user_id
    return None


def resolve_session_user(token: str, repo: UserRepository) -> Optional[SessionUser]:
    """Resolve a cookie token to an active SessionUser."""
    resolved = verify_session_token(token)
    if not resolved:
        return None
    if resolved.startswith("legacy:"):
        username = resolved[7:]
        email = f"{username}@local.dev"
        user = repo.get_user_by_email(email)
        if not user:
            user = repo.create_user(
                email,
                name=username,
                role=UserRole.ADMIN.value,
            )
        if not user.is_active:
            return None
        return SessionUser.from_user(user)
    user = repo.get_user_by_id(resolved)
    if not user or not user.is_active:
        return None
    return SessionUser.from_user(user)


def _check_sig(payload: str, sig: str) -> bool:
    expected = hmac.new(
        SESSION_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()[:32]
    return hmac.compare_digest(sig, expected)


def _check_ts(ts_str: str) -> bool:
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    return time.time() - ts <= SESSION_MAX_AGE
