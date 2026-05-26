"""User and invite data models."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"


@dataclass
class User:
    id: str
    email: str
    name: str
    role: str
    created_at: str
    last_login_at: Optional[str]
    is_active: bool

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN.value


@dataclass
class Invite:
    id: str
    email: str
    role: str
    token: str
    created_by: str
    created_at: str
    expires_at: str
    used_at: Optional[str]
    used_by_user_id: Optional[str]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "token": self.token,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "used_at": self.used_at,
            "used_by_user_id": self.used_by_user_id,
        }
