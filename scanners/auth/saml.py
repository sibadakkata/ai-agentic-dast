"""SAML 2.0 Service Provider integration (Microsoft Entra ID).

Uses python3-saml (OneLogin) - standard for Python SP integrations.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_SAML_AVAILABLE = True
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
except ImportError:
    _SAML_AVAILABLE = False
    OneLogin_Saml2_Auth = None  # type: ignore[misc, assignment]
    OneLogin_Saml2_IdPMetadataParser = None  # type: ignore[misc, assignment]
    OneLogin_Saml2_Settings = None  # type: ignore[misc, assignment]


def sso_enabled() -> bool:
    return os.environ.get("SSO_ENABLED", "false").lower() in ("1", "true", "yes")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _prepare_request(request) -> dict:
    url = str(request.url)
    parsed = urlparse(url)
    https = parsed.scheme == "https"
    return {
        "https": "on" if https else "off",
        "http_host": request.headers.get("host", parsed.netloc),
        "server_port": parsed.port or (443 if https else 80),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": {},
    }


def _build_settings() -> dict:
    entity_id = _env("SAML_SP_ENTITY_ID")
    acs_url = _env("SAML_SP_ACS_URL")
    metadata_url = _env("SAML_IDP_METADATA_URL")
    if not entity_id or not acs_url:
        raise ValueError("SAML_SP_ENTITY_ID and SAML_SP_ACS_URL are required when SSO is enabled")

    sp_cert_path = _env("SAML_SP_CERT_PATH")
    sp_key_path = _env("SAML_SP_KEY_PATH")
    security: dict[str, Any] = {
        "wantAssertionsSigned": bool(sp_cert_path),
        "wantMessagesSigned": False,
    }
    if not sp_cert_path:
        security["wantAssertionsSigned"] = False
        security["wantNameIdEncrypted"] = False

    sp_settings: dict[str, Any] = {
        "entityId": entity_id,
        "assertionConsumerService": {
            "url": acs_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
    }
    if sp_cert_path and sp_key_path:
        cert = Path(sp_cert_path).read_text(encoding="utf-8")
        key = Path(sp_key_path).read_text(encoding="utf-8")
        sp_settings["x509cert"] = cert
        sp_settings["privateKey"] = key

    settings: dict[str, Any] = {
        "strict": True,
        "debug": _env("SAML_DEBUG", "false").lower() in ("1", "true", "yes"),
        "sp": sp_settings,
        "idp": {},
        "security": security,
    }

    if metadata_url:
        settings["idp"] = _load_idp_from_metadata(metadata_url)
    else:
        settings["idp"] = {
            "entityId": _env("SAML_IDP_ENTITY_ID"),
            "singleSignOnService": {
                "url": _env("SAML_IDP_SSO_URL"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": _env("SAML_IDP_CERT"),
        }

    return settings


def _load_idp_from_metadata(metadata_url: str) -> dict:
    import httpx

    resp = httpx.get(metadata_url, timeout=30)
    resp.raise_for_status()
    idp_data = OneLogin_Saml2_IdPMetadataParser.parse(resp.text)
    return idp_data.get("idp", idp_data)


def get_saml_auth(request, post_data: dict | None = None) -> Any:
    if not _SAML_AVAILABLE:
        raise RuntimeError("python3-saml is not installed")
    req = _prepare_request(request)
    if post_data is not None:
        req["post_data"] = post_data
    settings = _build_settings()
    return OneLogin_Saml2_Auth(req, settings)


def get_metadata_xml() -> str:
    settings = OneLogin_Saml2_Settings(_build_settings(), sp_validation_only=True)
    return settings.get_sp_metadata()


def initiate_login(request) -> str:
    auth = get_saml_auth(request)
    return auth.login()


def process_acs(request, post_data: dict) -> dict:
    auth = get_saml_auth(request, post_data=post_data)
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        return {
            "ok": False,
            "errors": errors,
            "reason": auth.get_last_error_reason() or "",
        }
    if not auth.is_authenticated():
        return {"ok": False, "errors": ["not_authenticated"], "reason": ""}
    attrs = auth.get_attributes() or {}
    email = (
        auth.get_nameid()
        or _first_attr(
            attrs,
            "email",
            "mail",
            "EmailAddress",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        )
    )
    name = _first_attr(
        attrs,
        "name",
        "displayName",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "http://schemas.microsoft.com/identity/claims/displayname",
    ) or (email.split("@")[0] if email else "")
    from scanners.auth.groups import extract_groups_from_saml_attributes

    groups = extract_groups_from_saml_attributes(attrs)
    return {
        "ok": True,
        "email": (email or "").strip().lower(),
        "name": str(name).strip(),
        "groups": groups,
    }


def _first_attr(attrs: dict, *keys: str) -> str:
    for key in keys:
        val = attrs.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            if val:
                return str(val[0])
        elif val:
            return str(val)
    return ""


def initiate_logout(request, name_id: str, session_index: str = "") -> str:
    auth = get_saml_auth(request)
    return auth.logout(name_id=name_id, session_index=session_index or None)
