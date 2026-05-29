"""One-shot sync of repo docs to Confluence (reads CONFLUENCE_PAT from env)."""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from html import escape
from pathlib import Path

BASE = os.environ.get("CONFLUENCE_BASE", "https://confluence.corp.nortonlifelock.com").rstrip("/")
PAGE_ID = os.environ.get("CONFLUENCE_PAGE_ID", "954017481")
REPO = Path(__file__).resolve().parents[1]

MARKERS = (
    "overview",
    "architecture",
    "sso-rbac",
    "user-management",
    "deployment",
    "api",
    "entra-idp",
)


def _request(method: str, url: str, data: dict | None = None, pat: str = "") -> dict:
    body = None if data is None else json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("Authorization", f"Bearer {pat}")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
        import base64

        user = os.environ.get("CONFLUENCE_USER", "confluence")
        token = base64.b64encode(f"{user}:{pat}".encode()).decode()
        req2 = urllib.request.Request(url, data=body, method=method)
        req2.add_header("Content-Type", "application/json")
        req2.add_header("Accept", "application/json")
        req2.add_header("Authorization", f"Basic {token}")
        with urllib.request.urlopen(req2, timeout=120) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}


def _read_doc(rel: str) -> str:
    p = REPO / rel
    return p.read_text(encoding="utf-8") if p.is_file() else ""


def _md_table_to_html(block: str) -> str:
    lines = [ln.strip() for ln in block.strip().splitlines() if ln.strip()]
    if len(lines) < 2 or "|" not in lines[0]:
        return f"<p>{escape(block)}</p>"
    rows = [[c.strip() for c in ln.strip("|").split("|")] for ln in lines]
    sep = rows[1]
    if all(set(c) <= {"-", ":"} for c in sep):
        rows = [rows[0]] + rows[2:]
    out = ["<table><tbody>"]
    for i, row in enumerate(rows):
        tag = "th" if i == 0 else "td"
        out.append("<tr>" + "".join(f"<{tag}>{escape(c)}</{tag}>" for c in row) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def _md_to_storage(md: str) -> str:
    parts: list[str] = []
    buf: list[str] = []
    in_code = False

    def flush_para():
        nonlocal buf
        if not buf:
            return
        text = "\n".join(buf).strip()
        buf = []
        if not text:
            return
        if text.startswith("|"):
            parts.append(_md_table_to_html(text))
        else:
            parts.append(f"<p>{escape(text)}</p>")

    for line in md.splitlines():
        if line.strip().startswith("```"):
            flush_para()
            in_code = not in_code
            continue
        if in_code:
            buf.append(line)
            continue
        if line.startswith("### "):
            flush_para()
            parts.append(f"<h3>{escape(line[4:].strip())}</h3>")
        elif line.startswith("## "):
            flush_para()
            parts.append(f"<h2>{escape(line[3:].strip())}</h2>")
        elif line.startswith("# "):
            flush_para()
            parts.append(f"<h1>{escape(line[2:].strip())}</h1>")
        elif line.strip() == "":
            flush_para()
        elif line.strip().startswith("- "):
            flush_para()
            parts.append(f"<p>&bull; {escape(line.strip()[2:])}</p>")
        elif re.match(r"^\d+\.\s", line.strip()):
            flush_para()
            parts.append(f"<p>{escape(line.strip())}</p>")
        else:
            buf.append(line)
    flush_para()
    if in_code and buf:
        code = escape("\n".join(buf))
        parts.append(f'<ac:structured-macro ac:name="code"><ac:plain-text-body><![CDATA[{code}]]></ac:plain-text-body></ac:structured-macro>')
    return "".join(parts)


def _section(name: str, title: str, html: str) -> str:
    return (
        f"<!-- BEGIN: {name} -->"
        f"<h1>{escape(title)}</h1>{html}"
        f"<!-- END: {name} -->"
    )


def _info_macro(text: str) -> str:
    return (
        '<ac:structured-macro ac:name="info"><ac:rich-text-body>'
        f"<p>{escape(text)}</p></ac:rich-text-body></ac:structured-macro>"
    )


def build_page_body() -> str:
    sso = _read_doc("docs/SSO_RBAC.md")
    deploy = _read_doc("docs/deployment.md")
    api = _read_doc("docs/api.md")
    arch = _read_doc("docs/architecture/scalable-scanner-platform-proposal.md")
    arch_excerpt = "\n".join(arch.splitlines()[:120]) if arch else ""

    overview = """
# Red Team AI Web Scanner

LLM-powered Dynamic Application Security Testing (DAST) for websites, APIs, SPAs, and LLM-backed applications.
Multi-agent mode runs specialist agents in parallel (OWASP Web/API/LLM coverage) with Playwright + AWS Bedrock.

**Audiences:** security architecture review, AppSec, red team, QA security champions.

**Canonical hostname:** https://rt.ai.webscanner.gendigital.com (use for SAML ACS, Entity ID, and IdP callbacks — not raw ALB DNS).

## Access model

| Who | How |
|-----|-----|
| **End users (Red Team operators)** | **SSO** — Microsoft Entra ID, SAML 2.0 |
| **API / CI / automation scripts** | HTTP Basic Auth (DAST_AUTH_USER / DAST_AUTH_PASS) |

SSO is the canonical platform access path. Basic Auth is for scripting and interim rollout only — do not share Basic Auth credentials with end users.
"""

    arch_block = """
## Production platform (current)

```text
Human operators --> SSO (Entra SAML) --+
Automation / CI   --> HTTP Basic Auth -+--> rt.ai.webscanner.gendigital.com
                                        --> ALB + WAFv2 (us-east-2)
                                              --> EC2 3.20.180.251 : dast-scanner :80
                      |-- SCAN_LAUNCHER=fargate --> ECS Fargate (1 task / scan)
                      |-- RDS PostgreSQL 16 Multi-AZ (dual-write web/db_pg.py)
                      `-- ElastiCache Redis (live events / SSE)
```

| Layer | Value |
|-------|-------|
| Public URL | https://rt.ai.webscanner.gendigital.com |
| UI host | EC2 3.20.180.251, container dast-scanner, GET /healthz |
| Scan workers | ECR dast-scanner-runner, one Fargate task per scan |
| Database | RDS PostgreSQL + SQLite read path during rollout |
| Region | us-east-2 |
"""

    user_mgmt = """
## User management (admin workflow)

1. Sign in as **admin** via **SSO** (Microsoft Entra ID). HTTP Basic Auth is not the operator login path.
2. Sidebar **User Management** (SECURITY).
3. **Invite User** — email + role (`admin` or `user`); share invite link (7-day expiry).
4. **Change role** — dropdown on user row (last admin cannot be demoted).
5. **Deactivate** — disables sign-in; does not delete scan history.

**API (admin session or Basic Auth):**
- POST /api/users/invite
- PATCH /api/users/{user_id}/role
- POST /api/users/{user_id}/deactivate
- GET /api/users, GET /api/invites

When SSO group env vars are set, Entra group membership can replace per-user invites (see SSO section).
"""

    entra = """
## Entra ID / ServiceNow checklist (IdP team)

**SP endpoints (canonical host only):**
- ACS: https://rt.ai.webscanner.gendigital.com/sso/acs
- Metadata: https://rt.ai.webscanner.gendigital.com/sso/metadata
- Entity ID: must match SAML_SP_ENTITY_ID on server

**Required SAML claims:** email (or NameID=email), display name, **groups** (security group object IDs).

**Groups claim (Attributes & Claims):**
- Name: http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
- Source: Security groups, value = Group ID (GUID)

**Scanner env (operator sets on EC2, not in git):**
- SSO_ENABLED=true
- SSO_ADMIN_GROUP_IDS=<admin-group-object-id>
- SSO_USER_GROUP_IDS=<user-group-object-id>
- SSO_GROUP_CLAIM_NAME (optional override)

Provide IdP team two Entra group object IDs (admin + user). Users in those groups sign in without manual invite; role re-syncs every login.
"""

    sections = [
        _section("overview", "Overview", _md_to_storage(overview)),
        _section("architecture", "Architecture & infrastructure", _md_to_storage(arch_block + "\n\n" + arch_excerpt)),
        _section("sso-rbac", "SSO & RBAC", _md_to_storage(sso)),
        _section("user-management", "User management", _md_to_storage(user_mgmt)),
        _section("deployment", "Deployment", _md_to_storage(deploy[:8000])),
        _section("api", "HTTP API", _md_to_storage(api[:6000])),
        _section("entra-idp", "Entra / IdP configuration", _md_to_storage(entra)),
    ]
    header = _info_macro(
        "Auto-synced from ai-agentic-dast repo docs. "
        f"Last sync UTC: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}. "
        "Sections are bounded by HTML comments for idempotent updates."
    )
    return header + "".join(sections)


def _replace_marked_sections(existing: str, new_body: str) -> str:
    if "<!-- BEGIN: overview -->" not in existing:
        return new_body
    out = existing
    for name in MARKERS:
        pattern = re.compile(
            rf"<!-- BEGIN: {re.escape(name)} -->.*?<!-- END: {re.escape(name)} -->",
            re.DOTALL,
        )
        chunk = re.search(
            rf"<!-- BEGIN: {re.escape(name)} -->.*?<!-- END: {re.escape(name)} -->",
            new_body,
            re.DOTALL,
        )
        if chunk:
            out = pattern.sub(chunk.group(0), out, count=1)
    return out


def main() -> int:
    pat = os.environ.get("CONFLUENCE_PAT", "").strip()
    if not pat:
        print("CONFLUENCE_PAT not set", file=sys.stderr)
        return 1
    url = f"{BASE}/rest/api/content/{PAGE_ID}?expand=version,title,body.storage,space"
    page = _request("GET", url, pat=pat)
    title = page.get("title", "Red Team AI Web Scanner")
    version = page["version"]["number"]
    existing = page.get("body", {}).get("storage", {}).get("value", "")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = REPO / f"Confluence-backup-{PAGE_ID}-{ts}.xml"
    backup.write_text(existing, encoding="utf-8")
    print(f"Backup: {backup}")
    new_html = build_page_body()
    merged = _replace_marked_sections(existing, new_html) if existing else new_html
    payload = {
        "id": PAGE_ID,
        "type": "page",
        "title": title,
        "version": {"number": version + 1},
        "body": {"storage": {"value": merged, "representation": "storage"}},
    }
    put_url = f"{BASE}/rest/api/content/{PAGE_ID}"
    result = _request("PUT", put_url, data=payload, pat=pat)
    new_ver = result.get("version", {}).get("number", version + 1)
    print(f"Updated page {PAGE_ID} title={title!r} version {version} -> {new_ver}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
