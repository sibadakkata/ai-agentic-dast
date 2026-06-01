"""Read-only SSO configuration snapshot for admin UI / IdP handoff."""
from __future__ import annotations

import os

from scanners.auth.groups import DEFAULT_GROUP_CLAIM_URI, user_group_ids
from scanners.auth.saml import sso_enabled
from scanners.auth.access import parse_initial_admin_emails

_DEFAULT_HOST = "https://rt.ai.webscanner.gendigital.com"

_EMAIL_CLAIMS = [
    "email",
    "mail",
    "EmailAddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
]
_NAME_CLAIMS = [
    "name",
    "displayName",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "http://schemas.microsoft.com/identity/claims/displayname",
]
_GROUP_CLAIMS = [
    os.environ.get("SSO_GROUP_CLAIM_NAME", "").strip() or "groups",
    DEFAULT_GROUP_CLAIM_URI,
]


def _public_base_url() -> str:
    base = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    return base or _DEFAULT_HOST


def _idp_metadata_source() -> str:
    if os.environ.get("SAML_IDP_METADATA_URL", "").strip():
        return "url"
    if (
        os.environ.get("SAML_IDP_ENTITY_ID", "").strip()
        and os.environ.get("SAML_IDP_SSO_URL", "").strip()
    ):
        return "manual"
    return "unset"


def build_sso_config_snapshot() -> dict:
    base = _public_base_url()
    entity_id = os.environ.get("SAML_SP_ENTITY_ID", "").strip() or f"{base}/"
    acs_url = os.environ.get("SAML_SP_ACS_URL", "").strip() or f"{base}/sso/acs"
    metadata_url = f"{base}/sso/metadata"
    ug = user_group_ids()
    return {
        "enabled": sso_enabled(),
        "entity_id": entity_id,
        "acs_url": acs_url,
        "metadata_url": metadata_url,
        "slo_supported": False,
        "nameid_format": "emailAddress",
        "expected_attributes": [
            {"purpose": "email", "claim_names": list(_EMAIL_CLAIMS)},
            {"purpose": "name", "claim_names": list(_NAME_CLAIMS)},
            {"purpose": "groups", "claim_names": [c for c in _GROUP_CLAIMS if c]},
        ],
        "user_group_ids": {"configured": bool(ug), "count": len(ug)},
        "admin_group_auto_provision": False,
        "initial_admin_emails_configured": bool(parse_initial_admin_emails()),
        "idp_metadata_source": _idp_metadata_source(),
        "sp_signing_configured": bool(
            os.environ.get("SAML_SP_CERT_PATH", "").strip()
            and os.environ.get("SAML_SP_KEY_PATH", "").strip()
        ),
    }