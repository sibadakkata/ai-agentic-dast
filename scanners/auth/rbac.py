"""Role-based access control helpers for FastAPI."""
from __future__ import annotations

from functools import wraps
from typing import Callable, Literal, Optional

from fastapi import Depends, HTTPException, Request

from scanners.auth.session import SESSION_COOKIE, SessionUser, resolve_session_user
from scanners.users.models import UserRole
from scanners.users.repository import UserRepository

_user_repo: UserRepository | None = None


def init_rbac(repo: UserRepository) -> None:
    global _user_repo
    _user_repo = repo


def get_user_repo() -> UserRepository:
    if _user_repo is None:
        raise RuntimeError("RBAC not initialised — call init_rbac() at app startup")
    return _user_repo


def _basic_auth_user(request: Request) -> Optional[SessionUser]:
    """Map DAST_AUTH_USER/PASS basic auth to a local admin SessionUser."""
    import hmac
    import os

    from fastapi.security import HTTPBasicCredentials

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("basic "):
        return None
    import base64

    try:
        decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
        username, _, password = decoded.partition(":")
    except Exception:
        return None
    auth_user = os.environ.get("DAST_AUTH_USER", "dast-admin")
    auth_pass = os.environ.get("DAST_AUTH_PASS", "changeme")
    if not (
        hmac.compare_digest(username.encode(), auth_user.encode())
        and hmac.compare_digest(password.encode(), auth_pass.encode())
    ):
        return None
    repo = get_user_repo()
    email = f"{username}@local.dev"
    user = repo.get_user_by_email(email)
    if not user:
        user = repo.create_user(email, name=username, role=UserRole.ADMIN.value)
    elif not user.is_active:
        return None
    return SessionUser.from_user(user)


async def current_user(request: Request) -> SessionUser:
    """Return the authenticated user or raise 401."""
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        su = resolve_session_user(cookie, get_user_repo())
        if su:
            return su
    su = _basic_auth_user(request)
    if su:
        return su
    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Basic"},
    )


async def optional_user(request: Request) -> Optional[SessionUser]:
    try:
        return await current_user(request)
    except HTTPException:
        return None


def require_role(*roles: str):
    """FastAPI dependency factory — user must have one of *roles*."""

    async def _dep(user: SessionUser = Depends(current_user)) -> SessionUser:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return _dep


require_admin = require_role(UserRole.ADMIN.value)

_SSO_REQUIRED_MSG = (
    "This action requires an interactive Web UI session. "
    "Automation (API/MCP/OpenClaw via Basic Auth) cannot modify budgets."
)


def caller_auth_kind(request: Request) -> Literal["sso", "basic", "none"]:
    """Return how this request was authenticated: SSO cookie, Basic Auth, or none."""
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        su = resolve_session_user(cookie, get_user_repo())
        if su:
            return "sso"
    if _basic_auth_user(request):
        return "basic"
    return "none"


async def require_sso_user(request: Request) -> SessionUser:
    """Require an interactive Web UI session (SSO cookie), not automation Basic Auth."""
    if caller_auth_kind(request) != "sso":
        raise HTTPException(status_code=403, detail=_SSO_REQUIRED_MSG)
    cookie = request.cookies.get(SESSION_COOKIE)
    su = resolve_session_user(cookie, get_user_repo()) if cookie else None
    if not su:
        raise HTTPException(status_code=403, detail=_SSO_REQUIRED_MSG)
    return su
