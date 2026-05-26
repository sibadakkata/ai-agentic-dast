"""SQLite-backed user and invite repository."""
from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from scanners.users.models import Invite, User, UserRole
from web import db as scandb


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def _normalize_email(email: str) -> str:
    return email.strip().lower()


class UserRepository:
    """CRUD for users and invites in scanner.db."""

    INVITE_DEFAULT_DAYS = 7

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        row = scandb.users_get_by_id(user_id)
        return self._row_to_user(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[User]:
        row = scandb.users_get_by_email(_normalize_email(email))
        return self._row_to_user(row) if row else None

    def list_users(self, include_inactive: bool = False) -> list[User]:
        rows = scandb.users_list_all(include_inactive=include_inactive)
        return [self._row_to_user(r) for r in rows]

    def create_user(
        self,
        email: str,
        *,
        name: str = "",
        role: str = UserRole.USER.value,
        user_id: str | None = None,
    ) -> User:
        email_n = _normalize_email(email)
        if role not in (UserRole.ADMIN.value, UserRole.USER.value):
            raise ValueError(f"Invalid role: {role}")
        now = _iso(_utc_now())
        uid = user_id or str(uuid.uuid4())
        scandb.users_insert(
            {
                "id": uid,
                "email": email_n,
                "name": name or email_n.split("@")[0],
                "role": role,
                "created_at": now,
                "last_login_at": None,
                "is_active": 1,
            }
        )
        user = self.get_user_by_id(uid)
        assert user is not None
        return user

    def upsert_login(self, email: str, *, name: str = "", role: str | None = None) -> User:
        email_n = _normalize_email(email)
        existing = self.get_user_by_email(email_n)
        now = _iso(_utc_now())
        if existing:
            updates: dict = {"last_login_at": now}
            if name:
                updates["name"] = name
            if role is not None:
                updates["role"] = role
            scandb.users_update(existing.id, updates)
            return self.get_user_by_id(existing.id)  # type: ignore[return-value]
        return self.create_user(email_n, name=name, role=role or UserRole.USER.value)

    def set_role(self, user_id: str, role: str) -> Optional[User]:
        if role not in (UserRole.ADMIN.value, UserRole.USER.value):
            raise ValueError(f"Invalid role: {role}")
        scandb.users_update(user_id, {"role": role})
        return self.get_user_by_id(user_id)

    def deactivate_user(self, user_id: str) -> Optional[User]:
        scandb.users_update(user_id, {"is_active": 0})
        return self.get_user_by_id(user_id)

    def delete_user(self, user_id: str) -> bool:
        return scandb.users_delete(user_id)

    def get_first_admin_id(self) -> Optional[str]:
        for u in self.list_users():
            if u.is_admin and u.is_active:
                return u.id
        return None

    # ── Invites ───────────────────────────────────────────────────────

    def create_invite(
        self,
        email: str,
        role: str,
        created_by: str,
        *,
        expires_days: int | None = None,
    ) -> Invite:
        email_n = _normalize_email(email)
        if role not in (UserRole.ADMIN.value, UserRole.USER.value):
            raise ValueError(f"Invalid role: {role}")
        days = expires_days if expires_days is not None else self.INVITE_DEFAULT_DAYS
        now = _utc_now()
        invite_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        row = {
            "id": invite_id,
            "email": email_n,
            "role": role,
            "token": token,
            "created_by": created_by,
            "created_at": _iso(now),
            "expires_at": _iso(now + timedelta(days=days)),
            "used_at": None,
            "used_by_user_id": None,
        }
        scandb.invites_insert(row)
        inv = self.get_invite_by_id(invite_id)
        assert inv is not None
        return inv

    def get_invite_by_id(self, invite_id: str) -> Optional[Invite]:
        row = scandb.invites_get_by_id(invite_id)
        return self._row_to_invite(row) if row else None

    def get_pending_invite_by_email(self, email: str) -> Optional[Invite]:
        row = scandb.invites_get_pending_by_email(_normalize_email(email))
        return self._row_to_invite(row) if row else None

    def list_pending_invites(self) -> list[Invite]:
        rows = scandb.invites_list_pending()
        return [self._row_to_invite(r) for r in rows]

    def revoke_invite(self, invite_id: str) -> bool:
        return scandb.invites_delete(invite_id)

    def accept_invite(self, email: str, user_id: str) -> Optional[Invite]:
        inv = self.get_pending_invite_by_email(email)
        if not inv:
            return None
        now = _iso(_utc_now())
        scandb.invites_update(
            inv.id,
            {"used_at": now, "used_by_user_id": user_id},
        )
        return self.get_invite_by_id(inv.id)

    def is_invite_valid(self, invite: Invite) -> bool:
        if invite.used_at:
            return False
        try:
            exp = datetime.fromisoformat(invite.expires_at.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
        except ValueError:
            return False
        return _utc_now() < exp

    @staticmethod
    def _row_to_user(row: dict) -> User:
        return User(
            id=row["id"],
            email=row["email"],
            name=row.get("name") or "",
            role=row["role"],
            created_at=row["created_at"],
            last_login_at=row.get("last_login_at"),
            is_active=bool(row.get("is_active", 1)),
        )

    @staticmethod
    def _row_to_invite(row: dict) -> Invite:
        return Invite(
            id=row["id"],
            email=row["email"],
            role=row["role"],
            token=row["token"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            used_at=row.get("used_at"),
            used_by_user_id=row.get("used_by_user_id"),
        )
