"""Scan launch request models, sanitization, and body parsing for the HTTP API."""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

AI_INSTRUCTIONS_MAX_BYTES = 8192

_FENCE_RE = re.compile(r"```+[^\n]*\n?|```+")


def sanitize_ai_instructions(raw: str | None) -> str | None:
    """Strip fences, trim, and cap operator guidance for safe system-prompt injection."""
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    text = _FENCE_RE.sub("", text).strip()
    if not text:
        return None
    encoded = text.encode("utf-8")
    if len(encoded) > AI_INSTRUCTIONS_MAX_BYTES:
        text = encoded[:AI_INSTRUCTIONS_MAX_BYTES].decode("utf-8", errors="ignore").rstrip()
    return text or None


class ApiImportsJson(BaseModel):
    """API collection imports: filenames from prior upload or inline base64."""

    model_config = ConfigDict(extra="allow")

    postman: str | None = Field(
        default=None,
        description="Filename under imports/ from POST /api/upload",
    )
    postman_env: str | None = None
    openapi: str | None = None
    burp: str | None = None
    postman_b64: str | None = Field(
        default=None,
        description="Postman collection JSON as base64 (written to imports/ on launch)",
    )
    postman_env_b64: str | None = None
    openapi_b64: str | None = None
    burp_b64: str | None = None


class ScanLaunchRequest(BaseModel):
    """JSON body for POST /api/v1/scans — mirrors the UI launch form."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "target_url": "https://example.com",
                    "scan_mode": "both",
                    "model": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
                    "auth_type": "none",
                    "scan_scope": "directory",
                    "scan_intensity": "deep",
                    "llm_scan_depth": "standard",
                    "scan_profile": "vulnerability_scan",
                    "ai_instructions": (
                        "Focus on authentication and IDOR. Do not test /payments paths."
                    ),
                },
                {
                    "target_url": "https://staging.example.com",
                    "scan_mode": "both",
                    "model_policy": "auto",
                    "budget_cap_usd": 5.0,
                    "scan_intensity": "deep",
                    "llm_scan_depth": "standard",
                },
            ]
        }
    )

    target_url: str = Field(..., description="Base URL or entry point to scan")
    scan_mode: str = Field(
        default="both",
        description="website | api | both (alias: scan_type)",
        examples=["both"],
    )
    scan_type: str | None = Field(
        default=None,
        description="Alias for scan_mode (web/site/api/both)",
    )
    model: str = Field(default="", description="LLM model id from GET /api/models")
    model_policy: str = Field(
        default="manual",
        description='Model selection policy: "manual" (single model for all phases) or '
        '"auto" (Haiku/Sonnet/Opus per phase via ModelSelector)',
        examples=["manual", "auto"],
    )
    budget_cap_usd: float | None = Field(
        default=None,
        description="Optional USD budget cap; scan pauses at cap until owner/admin approves "
        "a higher limit. Omit for unlimited; if omitted at launch, defaults to "
        "recommended_budget_usd from POST /api/scans/estimate (~2× expected cost).",
        examples=[3.0, 5.0, 8.0],
    )
    username: str = ""
    password: str = ""
    username_b: str = ""
    password_b: str = ""
    auth_type: str = Field(default="auto", examples=["auto", "none", "form", "bearer"])
    auth: dict[str, Any] | None = Field(
        default=None,
        description="Optional auth object: kind/type, username, password, token, api_key",
    )
    credentials_admin: dict[str, Any] = Field(default_factory=dict)
    credentials_tenant_b: dict[str, Any] = Field(default_factory=dict)
    api_imports: ApiImportsJson | dict[str, Any] = Field(default_factory=dict)
    postman_collection_b64: str | None = Field(
        default=None,
        description="Shorthand: Postman collection JSON as base64",
    )
    burp_export_b64: str | None = Field(default=None, description="Burp export as base64")
    extra_domains: list[str] = Field(
        default_factory=list,
        description="Additional hosts in scope (comma-separated in UI)",
    )
    scope: str | None = Field(
        default=None,
        description="Alias for scan_scope: url_only | directory | full_site",
    )
    scan_scope: str = "directory"
    focus_urls: list[str] = Field(default_factory=list)
    focus_areas: list[str] = Field(default_factory=list)
    exclude_urls: list[str] = Field(default_factory=list)
    scan_intensity: str = Field(default="deep", examples=["light", "standard", "deep"])
    llm_scan_depth: str = "standard"
    scan_profile: str = "vulnerability_scan"
    skip_passive_sibling_tls: bool = False
    workflow_id: str | None = None
    business_flow: str | None = None
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Optional custom HTTP headers (stored on scan; agent support may vary)",
    )
    max_phases: int | None = Field(
        default=None,
        description="Reserved: phase cap (not enforced by scanner yet)",
    )
    phase_limit: int | None = Field(default=None, description="Alias for max_phases")
    ai_instructions: str | None = Field(
        default=None,
        description=(
            "Operator-specific guidance for the LLM agent, e.g. focus areas, "
            "out-of-scope paths, or credential usage rules"
        ),
        examples=["Focus on auth and IDOR; skip /admin/export"],
    )

    @field_validator("target_url")
    @classmethod
    def _strip_target(cls, v: str) -> str:
        return (v or "").strip()


class ScanCostEstimateRequest(BaseModel):
    """Body for POST /api/scans/estimate — same launch knobs as scan create."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "scan_mode": "web",
                    "scan_intensity": "deep",
                    "llm_scan_depth": "standard",
                    "model_policy": "auto",
                }
            ]
        }
    )

    target_url: str | None = Field(default=None, description="Optional; not used in math today")
    scan_mode: str = Field(default="both", examples=["website", "api", "both"])
    scan_intensity: str = Field(default="deep", examples=["light", "standard", "deep"])
    llm_scan_depth: str = Field(default="standard", examples=["standard", "deep"])
    model_policy: str = Field(
        default="auto",
        description='"manual" or "auto"',
        examples=["auto"],
    )
    model: str | None = Field(
        default=None,
        description="Manual model id when model_policy is manual",
    )


class ScanCostEstimateResponse(BaseModel):
    """Rough USD estimate (not a billing quote)."""

    low_usd: float
    expected_usd: float
    high_usd: float
    recommended_budget_usd: float
    assumptions: list[str] = Field(default_factory=list)
    per_phase: list[dict[str, Any]] = Field(default_factory=list)


class ScanBudgetResponse(BaseModel):
    """GET /api/scans/{scan_id}/budget."""

    cap_usd: float | None = None
    total_usd: float = 0
    status: str | None = None
    owner_user_id: str | None = None
    model_choices: dict[str, str] = Field(default_factory=dict)
    model_policy: str = "manual"
    estimated_cost_usd: float | None = None


class BudgetApproveRequest(BaseModel):
    """POST /api/scans/{scan_id}/budget/approve."""

    model_config = ConfigDict(json_schema_extra={"examples": [{"new_cap_usd": 5.0}]})

    new_cap_usd: float = Field(
        ...,
        description="New budget cap in USD; must exceed current spend (total_usd)",
        examples=[5.0, 10.0],
    )


class BudgetApproveResponse(BaseModel):
    scan_id: str
    budget_cap_usd: float
    budget_total_usd: float
    budget_status: str
    status: str | None = None


class BudgetStopResponse(BaseModel):
    scan_id: str
    budget_status: str
    status: str | None = None


class ScanLaunchResponse(BaseModel):
    """POST /api/v1/scans and legacy POST /api/scan success body."""

    scan_id: str
    status: str = Field(examples=["started"])


@dataclass
class ScanLaunchParams:
    """Normalized scan launch parameters used by app.py."""

    target_url: str
    username: str = ""
    password: str = ""
    username_b: str = ""
    password_b: str = ""
    credentials_admin: dict = field(default_factory=dict)
    credentials_tenant_b: dict = field(default_factory=dict)
    model: str = ""
    model_policy: str = "manual"
    budget_cap_usd: float | None = None
    scan_mode: str = "both"
    auth_type: str = "auto"
    api_imports: dict = field(default_factory=dict)
    extra_domains: list = field(default_factory=list)
    scan_scope: str = "directory"
    focus_urls: list = field(default_factory=list)
    focus_areas: list = field(default_factory=list)
    exclude_urls: list = field(default_factory=list)
    scan_intensity: str = "deep"
    llm_scan_depth: str = "standard"
    scan_profile: str = "vulnerability_scan"
    skip_passive_sibling_tls: bool = False
    workflow_id: str | None = None
    business_flow: str | None = None
    custom_headers: dict = field(default_factory=dict)
    ai_instructions: str | None = None


def _merge_auth(body: dict[str, Any], params: ScanLaunchParams) -> None:
    auth = body.get("auth")
    if not isinstance(auth, dict):
        return
    kind = (auth.get("kind") or auth.get("type") or "").strip()
    if kind:
        params.auth_type = kind
    if auth.get("username"):
        params.username = str(auth["username"]).strip()
    if auth.get("password"):
        params.password = str(auth["password"]).strip()
    token = auth.get("token") or auth.get("bearer_token") or auth.get("bearer")
    if token:
        params.credentials_admin = dict(params.credentials_admin or {})
        params.credentials_admin["bearer_token"] = str(token).strip()
    if auth.get("api_key"):
        params.credentials_admin = dict(params.credentials_admin or {})
        params.credentials_admin["api_key"] = str(auth["api_key"]).strip()


def _parse_budget_cap(raw: Any) -> float | None:
    if raw is None or raw == "":
        return None
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return None
    return val if val > 0 else None


def _normalize_scan_mode(raw: str) -> str:
    mode_map = {
        "standard": "both",
        "quick": "both",
        "deep": "both",
        "full": "both",
        "web": "website",
        "site": "website",
    }
    scan_mode = mode_map.get(raw, raw)
    if scan_mode not in ("website", "api", "both"):
        scan_mode = "both"
    return scan_mode


def materialize_api_imports(
    api_imports: dict[str, Any],
    imports_dir: Path,
    *,
    postman_collection_b64: str | None = None,
    burp_export_b64: str | None = None,
) -> dict[str, str]:
    """Resolve api_imports to filenames, writing base64 payloads into imports_dir."""
    imports_dir.mkdir(parents=True, exist_ok=True)
    merged = dict(api_imports or {})
    if postman_collection_b64:
        merged.setdefault("postman_b64", postman_collection_b64)
    if burp_export_b64:
        merged.setdefault("burp_b64", burp_export_b64)

    out: dict[str, str] = {}
    b64_specs = (
        ("postman", "postman_b64", "postman_collection.json"),
        ("postman_env", "postman_env_b64", "postman_env.json"),
        ("openapi", "openapi_b64", "openapi.json"),
        ("burp", "burp_b64", "burp_export.xml"),
    )
    for key, b64_key, default_name in b64_specs:
        if merged.get(key) and not merged.get(b64_key):
            out[key] = str(merged[key])
            continue
        b64_val = merged.get(b64_key)
        if not b64_val:
            continue
        try:
            raw = base64.b64decode(b64_val, validate=False)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"Invalid base64 for {b64_key}: {exc}") from exc
        fname = str(merged.get(key) or default_name).replace("..", "").replace("/", "_").replace("\\", "_")
        dest = imports_dir / fname
        dest.write_bytes(raw)
        out[key] = fname
    return out


def parse_scan_launch_dict(body: dict[str, Any]) -> ScanLaunchParams:
    """Parse a scan launch JSON body (UI or legacy API) into normalized params."""
    scan_mode_raw = body.get("scan_mode") or body.get("scan_type") or "both"
    scan_scope = body.get("scan_scope") or body.get("scope") or "directory"
    llm_scan_depth = (body.get("llm_scan_depth") or "standard").strip().lower()
    if llm_scan_depth not in ("standard", "deep"):
        llm_scan_depth = "standard"

    params = ScanLaunchParams(
        target_url=(body.get("target_url") or "").strip(),
        username=(body.get("username") or "").strip(),
        password=(body.get("password") or "").strip(),
        username_b=(body.get("username_b") or "").strip(),
        password_b=(body.get("password_b") or "").strip(),
        credentials_admin=body.get("credentials_admin") or {},
        credentials_tenant_b=body.get("credentials_tenant_b") or {},
        model=(body.get("model") or "").strip(),
        model_policy=(body.get("model_policy") or "manual").strip().lower(),
        budget_cap_usd=_parse_budget_cap(body.get("budget_cap_usd")),
        scan_mode=_normalize_scan_mode(scan_mode_raw),
        auth_type=(body.get("auth_type") or "auto").strip(),
        api_imports=dict(body.get("api_imports") or {}),
        extra_domains=list(body.get("extra_domains") or []),
        scan_scope=scan_scope,
        focus_urls=list(body.get("focus_urls") or []),
        focus_areas=list(body.get("focus_areas") or []),
        exclude_urls=list(body.get("exclude_urls") or []),
        scan_intensity=(body.get("scan_intensity") or "deep"),
        llm_scan_depth=llm_scan_depth,
        scan_profile=(body.get("scan_profile") or "vulnerability_scan").strip().lower(),
        skip_passive_sibling_tls=bool(body.get("skip_passive_sibling_tls")),
        workflow_id=(body.get("workflow_id") or "").strip() or None,
        business_flow=(body.get("business_flow") or "").strip() or None,
        custom_headers=dict(body.get("headers") or {}),
        ai_instructions=sanitize_ai_instructions(body.get("ai_instructions")),
    )
    _merge_auth(body, params)
    return params


def validate_scan_launch_params(params: ScanLaunchParams) -> str | None:
    """Return an error message if params are invalid, else None."""
    if not params.target_url:
        return "Target URL is required"
    if params.scan_scope not in ("url_only", "directory", "full_site"):
        params.scan_scope = "directory"
    if params.scan_intensity not in ("light", "standard", "deep"):
        params.scan_intensity = "deep"
    if params.focus_areas:
        params.scan_intensity = "deep"
    if params.scan_profile not in ("vulnerability_scan", "crawl_only", "multi_agent"):
        params.scan_profile = "vulnerability_scan"
    if params.scan_profile == "crawl_only":
        params.focus_areas = []
    if params.model_policy not in ("manual", "auto"):
        params.model_policy = "manual"
    return None


def request_to_launch_params(req: ScanLaunchRequest) -> ScanLaunchParams:
    """Convert a Pydantic v1 scan request to normalized launch params."""
    body = req.model_dump(exclude_none=True)
    if req.api_imports is not None:
        if hasattr(req.api_imports, "model_dump"):
            body["api_imports"] = req.api_imports.model_dump(exclude_none=True)
        else:
            body["api_imports"] = dict(req.api_imports)
    return parse_scan_launch_dict(body)


