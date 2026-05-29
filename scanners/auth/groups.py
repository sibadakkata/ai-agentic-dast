"""Entra ID group claim mapping for SAML SSO."""
from __future__ import annotations

import os
from typing import Literal, Optional

DEFAULT_GROUP_CLAIM_URI = (
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
)


def _parse_id_set(env_name: str) -> set[str]:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return set()
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def admin_group_ids() -> set[str]:
    return _parse_id_set("SSO_ADMIN_GROUP_IDS")


def user_group_ids() -> set[str]:
    return _parse_id_set("SSO_USER_GROUP_IDS")


def groups_mapping_enabled() -> bool:
    return bool(admin_group_ids() or user_group_ids())


def group_claim_keys() -> tuple[str, ...]:
    custom = os.environ.get("SSO_GROUP_CLAIM_NAME", "").strip()
    if custom:
        return (custom, "groups", DEFAULT_GROUP_CLAIM_URI)
    return ("groups", DEFAULT_GROUP_CLAIM_URI)


def normalize_group_values(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    text = str(raw).strip()
    if not text:
        return []
    if "," in text and len(text) > 36:
        return [part.strip() for part in text.split(",") if part.strip()]
    return [text]


def extract_groups_from_saml_attributes(attrs: dict) -> list[str]:
    for key in group_claim_keys():
        if key in attrs:
            return normalize_group_values(attrs.get(key))
    return []


def resolve_role_from_groups(group_ids: list[str]) -> Optional[Literal["admin", "user"]]:
    if not groups_mapping_enabled():
        return None
    normalized = {gid.strip().lower() for gid in group_ids if gid and str(gid).strip()}
    if not normalized:
        return None
    if admin_group_ids() & normalized:
        return "admin"
    if user_group_ids() & normalized:
        return "user"
    return None
