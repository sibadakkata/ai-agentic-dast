"""MCP Server for the AI Agentic Web Scanner.

Exposes the scanner's full capabilities as MCP tools that any MCP-compatible
client (Cursor, Claude Desktop, etc.) can invoke.

Two modes:
  - Remote: Connects to a running scanner instance via REST API (default).
  - Embedded: Imports scanner modules directly (for same-machine usage).

Usage:
  # Remote mode (connects to scanner at SCANNER_URL)
  SCANNER_URL=http://your-host:8080 SCANNER_USER=dast-admin SCANNER_PASS=secret python mcp_server.py

  # Stdio transport (for Cursor / Claude Desktop)
  SCANNER_URL=http://your-host:8080 python mcp_server.py --transport stdio
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

SCANNER_URL = os.environ.get("SCANNER_URL", "http://localhost:8080")
SCANNER_USER = os.environ.get("SCANNER_USER", "dast-admin")
SCANNER_PASS = os.environ.get("SCANNER_PASS", "")

mcp = FastMCP(
    "Agentic Web Scanner",
    instructions="AI-powered security scanner for websites, APIs, and SPAs. "
                 "Runs OWASP Top 10 + business logic tests using LLM agents.",
)


def _client() -> httpx.Client:
    auth = (SCANNER_USER, SCANNER_PASS) if SCANNER_PASS else None
    return httpx.Client(base_url=SCANNER_URL, auth=auth, timeout=30.0)


def _request(method: str, path: str, **kwargs) -> dict[str, Any]:
    with _client() as c:
        resp = c.request(method, path, **kwargs)
        resp.raise_for_status()
        return resp.json()


# ── Tools ─────────────────────────────────────────────────────────────


@mcp.tool()
def health_check() -> dict:
    """Check if the scanner is running and healthy.

    Returns status, number of running scans, and total scan count.
    """
    return _request("GET", "/health")


@mcp.tool()
def list_models() -> dict:
    """List all available LLM models for scanning.

    Returns model IDs, display names, and descriptions.
    Use the model ID when starting a scan.
    """
    return _request("GET", "/api/models")


@mcp.tool()
def start_scan(
    target_url: str,
    model: str = "",
    scan_mode: str = "both",
    username: str = "",
    password: str = "",
    auth_type: str = "auto",
    extra_domains: str = "",
    postman_file: str = "",
) -> dict:
    """Start a new security scan against a target.

    Args:
        target_url: The URL to scan (e.g., https://example.com).
        model: LLM model ID from list_models(). Leave empty for default (Haiku).
        scan_mode: 'website', 'api', or 'both' (default).
        username: Login username (leave empty for unauthenticated scan).
        password: Login password.
        auth_type: 'auto', 'form', 'sso', 'oauth', 'api_key', or 'bearer'.
        extra_domains: Comma-separated additional domains to include in scope.
        postman_file: Filename of previously uploaded Postman collection.

    Returns:
        scan_id and status. Use get_scan_status() to poll progress.
    """
    body: dict[str, Any] = {
        "target_url": target_url,
        "scan_mode": scan_mode,
        "auth_type": auth_type,
    }
    if model:
        body["model"] = model
    if username:
        body["username"] = username
    if password:
        body["password"] = password
    if extra_domains:
        body["extra_domains"] = extra_domains
    if postman_file:
        body["api_imports"] = {"postman": postman_file}
    return _request("POST", "/api/scan", json=body)


@mcp.tool()
def get_scan_status(scan_id: str) -> dict:
    """Get the current status of a scan.

    Args:
        scan_id: The scan ID returned by start_scan().

    Returns:
        Status ('running', 'stopping', 'completed', 'cancelled', 'error'),
        current phase, progress log, findings count, duration, and cost.
    """
    return _request("GET", f"/api/scan/{scan_id}")


@mcp.tool()
def stop_scan(scan_id: str) -> dict:
    """Stop a running scan to save cost.

    Sends a cancellation signal. The scan will halt after the current LLM step
    completes and save any partial findings collected so far.

    Args:
        scan_id: The scan ID returned by start_scan().

    Returns:
        Confirmation with updated status ('stopping'). The scan will transition
        to 'cancelled' once it fully stops.
    """
    return _request("POST", f"/api/scan/{scan_id}/stop")


@mcp.tool()
def retry_scan(scan_id: str, force_restart: bool = False) -> dict:
    """Re-run a failed or cancelled scan in-place (same scan ID).

    By default, tries to continue from the last completed phase.  If no
    phases completed or force_restart is True, re-runs from scratch.

    Args:
        scan_id: The scan ID of the errored/cancelled scan to retry.
        force_restart: If True, ignore prior progress and re-run from scratch.

    Returns:
        Same scan ID with status 'started', mode ('continuing'/'restarting'),
        and start_from_phase.
    """
    body = {"force_restart": force_restart} if force_restart else {}
    return _request("POST", f"/api/scan/{scan_id}/retry", json=body)


@mcp.tool()
def rescan(scan_id: str) -> dict:
    """Create a new scan with the same parameters as an existing scan.

    Useful to re-run a completed scan — creates a separate entry in history.
    Works on any scan status (completed, error, cancelled).

    Args:
        scan_id: The scan ID to re-scan.

    Returns:
        New scan ID with status 'started'.
    """
    return _request("POST", f"/api/scan/{scan_id}/rescan")


@mcp.tool()
def wait_for_scan(scan_id: str, poll_interval: int = 15, timeout: int = 3600) -> dict:
    """Wait for a scan to complete, polling periodically.

    Args:
        scan_id: The scan ID returned by start_scan().
        poll_interval: Seconds between status checks (default 15).
        timeout: Maximum seconds to wait (default 3600 = 1 hour).

    Returns:
        Final scan status when completed or error, or timeout message.
    """
    start = time.time()
    while time.time() - start < timeout:
        status = _request("GET", f"/api/scan/{scan_id}")
        if status.get("status") in ("completed", "error", "cancelled"):
            return status
        time.sleep(poll_interval)
    return {"error": "timeout", "scan_id": scan_id, "waited_seconds": timeout}


@mcp.tool()
def get_scan_results(scan_id: str) -> dict:
    """Get full results of a completed scan.

    Args:
        scan_id: The scan ID.

    Returns:
        AI findings, triaged findings with verdicts, crawled endpoints,
        payloads by endpoint, coverage stats, and severity breakdown.
    """
    return _request("GET", f"/api/results/{scan_id}")


@mcp.tool()
def get_live_activity(scan_id: str, since_test: int = 0, since_finding: int = 0) -> dict:
    """Get real-time activity for a running scan.

    Args:
        scan_id: The scan ID.
        since_test: Index to start from for tool calls (for pagination).
        since_finding: Index to start from for findings (for pagination).

    Returns:
        Recent tool calls, findings, crawled URLs, and phase progress.
    """
    return _request("GET", f"/api/scan/{scan_id}/live",
                     params={"since_test": since_test, "since_finding": since_finding})


def _get_all_scans() -> list[dict]:
    """Fetch all scans, handling paginated response."""
    data = _request("GET", "/api/scans", params={"per_page": 100})
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "items" in data:
        return data["items"]
    return []


@mcp.tool()
def list_scans() -> list:
    """List all scans (past and running).

    Returns:
        Array of scans with id, target, model, status, duration, cost, findings_count.
    """
    return _get_all_scans()


@mcp.tool()
def generate_report(scan_id: str) -> dict:
    """Generate a PDF report for a completed scan.

    Args:
        scan_id: The scan ID.

    Returns:
        Path to the generated PDF report (downloadable via the scanner URL).
    """
    return _request("POST", f"/api/results/{scan_id}/report")


@mcp.tool()
def download_payloads(scan_id: str) -> dict:
    """Download all payloads tested during a scan, grouped by phase.

    Args:
        scan_id: The scan ID.

    Returns:
        JSON with all payloads organized by scan phase.
    """
    return _request("GET", f"/api/results/{scan_id}/payloads")


@mcp.tool()
def upload_api_spec(file_path: str) -> dict:
    """Upload a Postman collection or OpenAPI spec for API scanning.

    Args:
        file_path: Local path to the file to upload.

    Returns:
        Upload confirmation with filename. Reference this filename in start_scan().
    """
    with open(file_path, "rb") as f:
        filename = os.path.basename(file_path)
        with _client() as c:
            resp = c.post("/api/upload", files={"file": (filename, f)})
            resp.raise_for_status()
            return resp.json()


@mcp.tool()
def delete_scan(scan_id: str) -> dict:
    """Stop (if running) and permanently delete a scan, its results, and reports.

    If the scan is currently running or paused, it is stopped immediately
    (no further LLM calls) before deletion.

    Args:
        scan_id: The scan ID to delete.

    Returns:
        List of deleted items (scan record, result files, reports).
    """
    return _request("DELETE", f"/api/scan/{scan_id}")


@mcp.tool()
def get_findings_summary(scan_id: str) -> str:
    """Get a concise text summary of triaged findings for a completed scan.

    Args:
        scan_id: The scan ID.

    Returns:
        Human-readable summary with severity counts and top findings.
    """
    data = _request("GET", f"/api/results/{scan_id}")
    findings = data.get("triaged_findings", [])
    if not findings:
        return f"Scan {scan_id}: No findings after triage."

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("final_severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines = [f"## Scan Results: {scan_id}", f"**{len(findings)} findings after triage**\n"]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev in severity_counts:
            lines.append(f"- {sev}: {severity_counts[sev]}")
    lines.append("\n### Top Findings:\n")
    for f in findings[:10]:
        verdict = f.get("verdict", "")
        lines.append(f"- [{f.get('final_severity', '?')}] **{f.get('title', '?')}** — {verdict}")
    if len(findings) > 10:
        lines.append(f"\n... and {len(findings) - 10} more findings.")
    return "\n".join(lines)


@mcp.tool()
def query_findings(
    target: str = "",
    keyword: str = "",
    severity: str = "",
    verdict: str = "",
    scan_id: str = "",
) -> str:
    """Search and filter findings across all scans (or a specific scan).

    Use this to answer questions like:
      - "How many issues were found in the NGP scan?"
      - "Show me all SQL injection findings"
      - "What Critical vulnerabilities exist across all scans?"
      - "How many false positives in the last scan?"

    Args:
        target: Filter by target URL keyword (e.g., 'myapp', 'staging', 'api.example.com').
                 Case-insensitive partial match.
        keyword: Filter findings by title keyword (e.g., 'sql injection', 'xss',
                 'idor', 'missing header', 'csrf'). Case-insensitive partial match.
        severity: Filter by final triage severity: 'Critical', 'High', 'Medium',
                  'Low', or 'Info'. Leave empty for all.
        verdict: Filter by triage verdict: 'TRUE_POSITIVE', 'FALSE_POSITIVE',
                 'NOT_A_FINDING', or 'NEEDS_VERIFICATION'. Leave empty for all.
        scan_id: Filter to a specific scan ID. Leave empty to search all scans.

    Returns:
        Matching findings with scan context, severity counts, and per-scan breakdown.
    """
    scans = _get_all_scans()
    if not scans:
        return "No scans found."

    if scan_id:
        scans = [s for s in scans if s.get("id") == scan_id]
    if target:
        t_lower = target.lower()
        scans = [s for s in scans if t_lower in (s.get("target", "") or "").lower()]

    completed = [s for s in scans if s.get("status") == "completed"]
    if not completed:
        matching_any = [s for s in scans if s.get("status") != "completed"]
        if matching_any:
            return (f"Found {len(matching_any)} scan(s) matching '{target or scan_id}' "
                    f"but none are completed (statuses: "
                    f"{[s.get('status') for s in matching_any]}). "
                    f"Only completed scans have queryable findings.")
        return f"No scans found matching '{target or scan_id}'."

    all_matches = []
    severity_counts: dict[str, int] = {}
    verdict_counts: dict[str, int] = {}
    scan_summaries = []

    for scan in completed:
        sid = scan["id"]
        try:
            results = _request("GET", f"/api/results/{sid}")
        except Exception:
            continue

        triaged = results.get("triaged_findings", [])
        scan_matches = []

        for f in triaged:
            title = (f.get("title") or "").lower()
            f_sev = f.get("final_severity", "")
            f_verdict = f.get("verdict", "")

            if keyword and keyword.lower() not in title:
                continue
            if severity and f_sev.lower() != severity.lower():
                continue
            if verdict and f_verdict.lower() != verdict.lower():
                continue

            scan_matches.append(f)
            severity_counts[f_sev] = severity_counts.get(f_sev, 0) + 1
            verdict_counts[f_verdict] = verdict_counts.get(f_verdict, 0) + 1

        if scan_matches:
            scan_summaries.append({
                "scan_id": sid,
                "target": scan.get("target", ""),
                "model": scan.get("model", ""),
                "match_count": len(scan_matches),
                "total_findings": len(triaged),
            })
            for m in scan_matches:
                m["_scan_id"] = sid
                m["_target"] = scan.get("target", "")
            all_matches.extend(scan_matches)

    if not all_matches:
        filters = []
        if target:
            filters.append(f"target='{target}'")
        if keyword:
            filters.append(f"keyword='{keyword}'")
        if severity:
            filters.append(f"severity='{severity}'")
        if verdict:
            filters.append(f"verdict='{verdict}'")
        return (f"No findings matched filters: {', '.join(filters)}. "
                f"Searched {len(completed)} completed scan(s).")

    lines = [f"## Query Results: {len(all_matches)} finding(s) matched\n"]

    filters_desc = []
    if target:
        filters_desc.append(f"target contains '{target}'")
    if keyword:
        filters_desc.append(f"title contains '{keyword}'")
    if severity:
        filters_desc.append(f"severity = {severity}")
    if verdict:
        filters_desc.append(f"verdict = {verdict}")
    if filters_desc:
        lines.append(f"**Filters:** {', '.join(filters_desc)}")
    lines.append(f"**Scans searched:** {len(completed)}\n")

    lines.append("### Severity Breakdown")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev in severity_counts:
            lines.append(f"- **{sev}**: {severity_counts[sev]}")

    lines.append("\n### Verdict Breakdown")
    for v in ["TRUE_POSITIVE", "FALSE_POSITIVE", "NOT_A_FINDING", "NEEDS_VERIFICATION"]:
        if v in verdict_counts:
            lines.append(f"- {v}: {verdict_counts[v]}")

    if len(scan_summaries) > 1:
        lines.append("\n### Per-Scan Breakdown")
        for ss in scan_summaries:
            lines.append(f"- **{ss['target']}** ({ss['scan_id']}): "
                         f"{ss['match_count']}/{ss['total_findings']} findings matched")

    lines.append("\n### Findings\n")
    for f in all_matches[:30]:
        sev = f.get("final_severity", "?")
        title = f.get("title", "?")
        v = f.get("verdict", "?")
        url = f.get("url", "")
        cwe = f.get("cwe", "")
        reason = (f.get("reason") or "")[:150]
        scan_target = f.get("_target", "")

        line = f"- [{sev}] **{title}** — {v}"
        if url:
            line += f" | {url[:80]}"
        if cwe:
            line += f" | {cwe}"
        lines.append(line)
        if reason:
            lines.append(f"  _{reason}_")

    if len(all_matches) > 30:
        lines.append(f"\n... and {len(all_matches) - 30} more findings.")

    return "\n".join(lines)


@mcp.tool()
def get_scan_stats(scan_id: str = "", target: str = "") -> str:
    """Get aggregated statistics for a scan or across all scans.

    Use this to answer questions like:
      - "Give me a summary of the NGP scan"
      - "How many total issues across all scans?"
      - "What was the cost of the last scan?"
      - "Compare findings across all targets"

    Args:
        scan_id: Specific scan ID. Leave empty for all scans.
        target: Filter by target URL keyword (e.g., 'myapp', 'staging').
                 Case-insensitive partial match. Leave empty for all.

    Returns:
        Statistics: finding counts by severity/verdict/type, scan metadata
        (duration, cost, model), and comparison across scans if multiple match.
    """
    scans = _get_all_scans()
    if not scans:
        return "No scans found."

    if scan_id:
        scans = [s for s in scans if s.get("id") == scan_id]
    if target:
        t_lower = target.lower()
        scans = [s for s in scans if t_lower in (s.get("target", "") or "").lower()]

    if not scans:
        return f"No scans found matching '{target or scan_id}'."

    lines = []
    total_findings = 0
    total_cost = 0.0
    total_duration = 0.0
    grand_severity: dict[str, int] = {}
    grand_verdict: dict[str, int] = {}
    grand_categories: dict[str, int] = {}

    for scan in scans:
        sid = scan["id"]
        scan_target = scan.get("target", "?")
        model = scan.get("model", "?")
        status = scan.get("status", "?")
        duration = scan.get("duration", 0) or 0
        cost = scan.get("cost", 0) or 0
        fcount = scan.get("findings_count", 0) or 0

        total_cost += cost
        total_duration += duration
        total_findings += fcount

        scan_lines = [f"### {scan_target}", f"- **Scan ID:** {sid}",
                      f"- **Model:** {model}", f"- **Status:** {status}",
                      f"- **Duration:** {round(duration/60, 1)} min",
                      f"- **Cost:** ${round(cost, 4)}",
                      f"- **AI Findings:** {fcount}"]

        if status == "completed":
            try:
                results = _request("GET", f"/api/results/{sid}")
                triaged = results.get("triaged_findings", [])
                sev_counts: dict[str, int] = {}
                ver_counts: dict[str, int] = {}
                cat_counts: dict[str, int] = {}

                for f in triaged:
                    sev = f.get("final_severity", "Unknown")
                    ver = f.get("verdict", "Unknown")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                    ver_counts[ver] = ver_counts.get(ver, 0) + 1
                    grand_severity[sev] = grand_severity.get(sev, 0) + 1
                    grand_verdict[ver] = grand_verdict.get(ver, 0) + 1

                    title = (f.get("title") or "").lower()
                    for cat, kws in [
                        ("SQL Injection", ["sql injection", "sqli"]),
                        ("XSS", ["xss", "cross-site scripting"]),
                        ("SSRF", ["ssrf"]),
                        ("IDOR", ["idor", "insecure direct object"]),
                        ("Command Injection", ["command injection", "rce"]),
                        ("Missing Headers", ["missing header", "hsts", "csp", "x-frame"]),
                        ("Auth Issues", ["auth", "session", "jwt", "token"]),
                        ("Info Disclosure", ["info", "disclosure", "sensitive data"]),
                        ("Outdated Components", ["outdated", "version", "library", "jquery"]),
                        ("CSRF", ["csrf"]),
                        ("Business Logic", ["business logic", "rate limit"]),
                    ]:
                        if any(k in title for k in kws):
                            cat_counts[cat] = cat_counts.get(cat, 0) + 1
                            grand_categories[cat] = grand_categories.get(cat, 0) + 1
                            break

                scan_lines.append(f"- **Triaged Findings:** {len(triaged)}")
                sev_str = ", ".join(f"{s}: {c}" for s, c in
                                    sorted(sev_counts.items(),
                                           key=lambda x: ["Critical","High","Medium","Low","Info"].index(x[0])
                                           if x[0] in ["Critical","High","Medium","Low","Info"] else 99))
                scan_lines.append(f"- **By Severity:** {sev_str}")
                tp = ver_counts.get("TRUE_POSITIVE", 0)
                fp = ver_counts.get("FALSE_POSITIVE", 0)
                nf = ver_counts.get("NOT_A_FINDING", 0)
                nv = ver_counts.get("NEEDS_VERIFICATION", 0)
                scan_lines.append(f"- **Verdicts:** {tp} confirmed, {fp} false positive, {nv} needs verification, {nf} not a finding")
                if cat_counts:
                    scan_lines.append("- **By Category:** " + ", ".join(
                        f"{k}: {v}" for k, v in sorted(cat_counts.items(), key=lambda x: -x[1])))

                coverage = results.get("coverage", {})
                if coverage:
                    scan_lines.append(f"- **Coverage:** {coverage.get('pages_crawled', 0)} pages, "
                                      f"{coverage.get('api_endpoints', 0)} API endpoints, "
                                      f"{coverage.get('total_tool_calls', 0)} tool calls, "
                                      f"{coverage.get('phases_completed', 0)} phases")
            except Exception:
                scan_lines.append("- _(could not load detailed results)_")

        lines.extend(scan_lines)
        lines.append("")

    if len(scans) > 1:
        lines.insert(0, f"## Scan Statistics: {len(scans)} scan(s)\n")
        lines.insert(1, f"**Total findings:** {total_findings} | "
                        f"**Total cost:** ${round(total_cost, 4)} | "
                        f"**Total duration:** {round(total_duration/60, 1)} min\n")
        if grand_severity:
            sev_str = ", ".join(f"{s}: {c}" for s, c in
                                sorted(grand_severity.items(),
                                       key=lambda x: ["Critical","High","Medium","Low","Info"].index(x[0])
                                       if x[0] in ["Critical","High","Medium","Low","Info"] else 99))
            lines.insert(2, f"**All severities:** {sev_str}")
        if grand_categories:
            lines.insert(3, "**All categories:** " + ", ".join(
                f"{k}: {v}" for k, v in sorted(grand_categories.items(), key=lambda x: -x[1])))
            lines.insert(4, "")
    else:
        lines.insert(0, f"## Scan Statistics\n")

    return "\n".join(lines)


# ── Resources ─────────────────────────────────────────────────────────


@mcp.resource("scanner://health")
def scanner_health() -> str:
    """Current scanner health status."""
    return json.dumps(_request("GET", "/health"), indent=2)


@mcp.resource("scanner://models")
def scanner_models() -> str:
    """Available LLM models for scanning."""
    return json.dumps(_request("GET", "/api/models"), indent=2)


@mcp.resource("scanner://scans")
def scanner_scans() -> str:
    """All scan history."""
    return json.dumps(_get_all_scans(), indent=2)


# ── Prompts ───────────────────────────────────────────────────────────


@mcp.prompt()
def scan_website(url: str) -> str:
    """Generate a prompt to scan a website."""
    return (
        f"I need to run a security scan on {url}. "
        f"Please use the start_scan tool with target_url='{url}' and scan_mode='website'. "
        f"Then wait for it to complete using wait_for_scan, and finally show me "
        f"the findings summary using get_findings_summary."
    )


@mcp.prompt()
def scan_api(url: str, collection_file: str = "") -> str:
    """Generate a prompt to scan an API."""
    parts = [
        f"I need to run an API security scan on {url}. ",
    ]
    if collection_file:
        parts.append(f"First upload the Postman collection at '{collection_file}' using upload_api_spec. ")
        parts.append(f"Then start the scan with scan_mode='api' and reference the uploaded file. ")
    else:
        parts.append(f"Start the scan with scan_mode='api'. ")
    parts.append("Wait for completion, then show the triaged findings summary.")
    return "".join(parts)


if __name__ == "__main__":
    import sys
    transport = "stdio"
    for arg in sys.argv[1:]:
        if arg.startswith("--transport="):
            transport = arg.split("=", 1)[1]
        elif arg == "--transport" and sys.argv.index(arg) + 1 < len(sys.argv):
            transport = sys.argv[sys.argv.index(arg) + 1]
    mcp.run(transport=transport)
