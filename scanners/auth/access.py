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


def resolve_email_access(
    email: str,
    name: str,
    repo: UserRepository,
    *,
    initial_admins: set[str] | None = None,
) -> AccessResult:
    """Determine whether *email* may log in and return/create the user record."""
    email_n = email.strip().lower()
    if not email_n or "@" not in email_n:
        return AccessResult(False, reason="invalid_email")

    admins = initial_admins if initial_admins is not None else parse_initial_admin_emails()

    if email_n in admins:
        user = repo.upsert_login(email_n, name=name, role=UserRole.ADMIN.value)
        return AccessResult(True, user=user)

    existing = repo.get_user_by_email(email_n)
    if existing:
        if not existing.is_active:
            return AccessResult(False, reason="deactivated")
        user = repo.upsert_login(email_n, name=name)
        return AccessResult(True, user=user)

    invite = repo.get_pending_invite_by_email(email_n)
    if invite and repo.is_invite_valid(invite):
        user = repo.create_user(email_n, name=name, role=invite.role)
        repo.accept_invite(email_n, user.id)
        user = repo.upsert_login(email_n, name=name)
        return AccessResult(True, user=user)

    return AccessResult(
        False,
        reason="not_authorized",
    )
