"""HTTP middleware: require authentication on protected routes."""
from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from scanners.auth.session import SESSION_COOKIE, resolve_session_user
from scanners.auth import rbac as rbac_mod

_PUBLIC_PREFIXES = (
    "/health",
    "/login",
    "/logout",
    "/sso/",
    "/api/auth/config",
    "/static/",
    "/docs",
    "/redoc",
    "/openapi.json",
)

_PUBLIC_EXACT = {"/"}


def _is_public(path: str) -> bool:
    if path in _PUBLIC_EXACT:
        return True
    return any(path.startswith(p) for p in _PUBLIC_PREFIXES)


def _is_api(path: str) -> bool:
    return path.startswith("/api/")


async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if _is_public(path):
        return await call_next(request)

    cookie = request.cookies.get(SESSION_COOKIE)
    user = None
    if cookie:
        try:
            user = resolve_session_user(cookie, rbac_mod.get_user_repo())
        except Exception:
            user = None
    if user is None:
        user = rbac_mod._basic_auth_user(request)

    if user is None:
        if _is_api(path) or path.startswith("/api"):
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"},
                headers={"WWW-Authenticate": "Basic"},
            )
        return RedirectResponse("/login", status_code=302)

    request.state.user = user
    return await call_next(request)
