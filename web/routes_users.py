"""User management and SSO API routes."""
from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from scanners.auth import saml as saml_mod
from scanners.auth.access import resolve_email_access
from scanners.auth.rbac import current_user, require_admin
from scanners.auth.session import (
    SESSION_COOKIE,
    SessionUser,
    create_session_token,
    session_cookie_kwargs,
)
from scanners.users.models import UserRole
from scanners.users.repository import UserRepository

router = APIRouter(tags=["Users"])

_repo: UserRepository | None = None


def init_user_routes(repo: UserRepository) -> None:
    global _repo
    _repo = repo


def _get_repo() -> UserRepository:
    if _repo is None:
        raise RuntimeError("User routes not initialised")
    return _repo


class InviteBody(BaseModel):
    email: str
    role: str = Field(default=UserRole.USER.value)


class RoleBody(BaseModel):
    role: str


def _user_dict(u) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "name": u.name,
        "role": u.role,
        "created_at": u.created_at,
        "last_login_at": u.last_login_at,
        "is_active": u.is_active,
    }


def _invite_url(request: Request, token: str) -> str:
    base = os.environ.get("PUBLIC_BASE_URL", "").strip()
    if not base:
        base = str(request.base_url).rstrip("/")
    return f"{base}/sso/login?invite={token}"


@router.get("/api/me")
async def api_me(user: SessionUser = Depends(current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
    }


@router.get("/api/auth/config")
async def auth_config():
    return {"sso_enabled": saml_mod.sso_enabled()}


@router.get("/api/users")
async def list_users(admin: SessionUser = Depends(require_admin)):
    users = _get_repo().list_users(include_inactive=True)
    return {"items": [_user_dict(u) for u in users]}


@router.post("/api/users/invite")
async def create_invite(
    body: InviteBody,
    request: Request,
    admin: SessionUser = Depends(require_admin),
):
    if body.role not in (UserRole.ADMIN.value, UserRole.USER.value):
        raise HTTPException(400, "role must be 'admin' or 'user'")
    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "Valid email required")
    existing = _get_repo().get_user_by_email(email)
    if existing and existing.is_active:
        raise HTTPException(409, "User already exists")
    inv = _get_repo().create_invite(email, body.role, admin.id)
    return {
        "invite_id": inv.id,
        "invite_url": _invite_url(request, inv.token),
        "expires_at": inv.expires_at,
        "email": inv.email,
        "role": inv.role,
    }


@router.post("/api/users/{user_id}/role")
async def change_role(
    user_id: str,
    body: RoleBody,
    admin: SessionUser = Depends(require_admin),
):
    if body.role not in (UserRole.ADMIN.value, UserRole.USER.value):
        raise HTTPException(400, "role must be 'admin' or 'user'")
    if user_id == admin.id and body.role != UserRole.ADMIN.value:
        admins = [u for u in _get_repo().list_users() if u.is_admin]
        if len(admins) <= 1:
            raise HTTPException(400, "Cannot demote the only admin")
    user = _get_repo().set_role(user_id, body.role)
    if not user:
        raise HTTPException(404, "User not found")
    return _user_dict(user)


@router.post("/api/users/{user_id}/deactivate")
async def deactivate_user(user_id: str, admin: SessionUser = Depends(require_admin)):
    if user_id == admin.id:
        raise HTTPException(400, "Cannot deactivate yourself")
    user = _get_repo().deactivate_user(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    return _user_dict(user)


@router.delete("/api/users/{user_id}")
async def delete_user(user_id: str, admin: SessionUser = Depends(require_admin)):
    if user_id == admin.id:
        raise HTTPException(400, "Cannot delete yourself")
    if not _get_repo().delete_user(user_id):
        raise HTTPException(404, "User not found")
    return {"deleted": True}


@router.get("/api/invites")
async def list_invites(admin: SessionUser = Depends(require_admin)):
    invites = _get_repo().list_pending_invites()
    return {
        "items": [
            {
                **inv.to_dict(),
                "is_expired": not _get_repo().is_invite_valid(inv),
            }
            for inv in invites
        ]
    }


@router.delete("/api/invites/{invite_id}")
async def revoke_invite(invite_id: str, admin: SessionUser = Depends(require_admin)):
    if not _get_repo().revoke_invite(invite_id):
        raise HTTPException(404, "Invite not found")
    return {"revoked": True}


def _set_session_cookie(response, user_id: str) -> None:
    token = create_session_token(user_id)
    response.set_cookie(key=SESSION_COOKIE, value=token, **session_cookie_kwargs())


@router.get("/sso/login")
async def sso_login(request: Request):
    if not saml_mod.sso_enabled():
        return RedirectResponse("/login", status_code=302)
    try:
        url = saml_mod.initiate_login(request)
    except Exception as exc:
        return HTMLResponse(f"SAML login error: {exc}", status_code=500)
    return RedirectResponse(url, status_code=302)


@router.post("/sso/acs")
async def sso_acs(request: Request):
    if not saml_mod.sso_enabled():
        return RedirectResponse("/login", status_code=302)
    form = await request.form()
    post_data = dict(form)
    result = saml_mod.process_acs(request, post_data)
    if not result.get("ok"):
        return RedirectResponse("/sso/denied?reason=saml_error", status_code=302)
    access = resolve_email_access(
        result["email"],
        result.get("name", ""),
        _get_repo(),
        groups=result.get("groups") or [],
    )
    if not access.allowed or not access.user:
        reason = access.reason or "not_authorized"
        return RedirectResponse(f"/sso/denied?reason={reason}", status_code=302)
    resp = RedirectResponse("/", status_code=302)
    _set_session_cookie(resp, access.user.id)
    return resp


@router.get("/sso/metadata")
async def sso_metadata():
    if not saml_mod.sso_enabled() and not saml_mod.sp_metadata_configured():
        raise HTTPException(404, "SSO not configured")
    try:
        xml = saml_mod.get_metadata_xml()
    except Exception as exc:
        raise HTTPException(500, str(exc)) from exc
    return HTMLResponse(content=xml, media_type="application/xml")


@router.get("/sso/logout")
async def sso_logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@router.get("/sso/denied", response_class=HTMLResponse)
async def sso_denied(request: Request, reason: str = "not_authorized"):
    reason_text = {
        "not_authorized": "Not authorized — contact your admin to request access.",
        "not_in_required_group": (
            "You are not in an Entra ID group allowed to use this application. "
            "Contact your admin or IT to be added to the correct security group."
        ),
        "saml_error": "Sign-in failed. Please try again or contact your administrator.",
        "deactivated": "Your account has been deactivated.",
    }.get(reason, "Access denied.")
    return HTMLResponse(
        f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Access Denied</title>
        <style>body{{font-family:Inter,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f5f6fa;margin:0;}}
        .box{{background:#fff;border:1px solid #e2e4ee;border-radius:12px;padding:40px;max-width:440px;text-align:center;}}
        h1{{font-size:20px;color:#0f1729;}} p{{color:#5c6478;font-size:14px;line-height:1.6;}}
        a{{color:#0400F5;}}</style></head><body><div class="box">
        <h1>Access Denied</h1><p>{reason_text}</p>
        <p><a href="/login">Back to sign in</a></p></div></body></html>"""
    )
