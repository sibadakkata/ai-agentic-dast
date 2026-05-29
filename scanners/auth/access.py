"""Post-SAML (or bootstrap) access resolution for email addresses."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from scanners.users.models import User, UserRole
from scanners.users.repository import UserRepository


def parse_initial_admin_emails() -> set[str]:
    raw = os.environ.get("INITIAL_ADMIN_EMAILS", "").strip()
    if not raw:
        return set()
    return {e.strip().lower() for e in raw.split(",") if e.strip()}


@dataclass
class AccessResult:
    allowed: bool
    user: Optional[User] = None
    reason: str = ""
    source: str = ""


def _apply_group_role(
    repo: UserRepository, user: User, group_role: str | None
) -> User:
    if group_role and user.role != group_role:
        synced = repo.set_role(user.id, group_role)
        if synced:
            return synced
    return user


def resolve_email_access(
    email: str,
    name: str,
    repo: UserRepository,
    *,
    initial_admins: set[str] | None = None,
    groups: list[str] | None = None,
) -> AccessResult:
    """Determine whether *email* may log in and return/create the user record."""
    from scanners.auth.groups import groups_mapping_enabled, resolve_role_from_groups

    email_n = email.strip().lower()
    if not email_n or "@" not in email_n:
        return AccessResult(False, reason="invalid_email")

    admins = initial_admins if initial_admins is not None else parse_initial_admin_emails()
    group_role = resolve_role_from_groups(groups or [])

    if email_n in admins:
        user = repo.upsert_login(email_n, name=name, role=UserRole.ADMIN.value)
        user = _apply_group_role(repo, user, group_role)
        return AccessResult(True, user=user, source="bootstrap")

    existing = repo.get_user_by_email(email_n)
    if existing:
        if not existing.is_active:
            return AccessResult(False, reason="deactivated")
        user = repo.upsert_login(email_n, name=name)
        user = _apply_group_role(repo, user, group_role)
        return AccessResult(True, user=user, source="existing")

    invite = repo.get_pending_invite_by_email(email_n)
    if invite and repo.is_invite_valid(invite):
        user = repo.create_user(email_n, name=name, role=invite.role)
        repo.accept_invite(email_n, user.id)
        user = repo.upsert_login(email_n, name=name)
        user = _apply_group_role(repo, user, group_role)
        return AccessResult(True, user=user, source="invite")

    if group_role is not None:
        user = repo.upsert_login(email_n, name=name, role=group_role)
        return AccessResult(True, user=user, source="group")

    if groups_mapping_enabled():
        return AccessResult(False, reason="not_in_required_group")

    return AccessResult(False, reason="not_authorized")
