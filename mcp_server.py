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


@mcp.tool()
def list_scans() -> list:
    """List all scans (past and running).

    Returns:
        Array of scans with id, target, model, status, duration, cost, findings_count.
    """
    return _request("GET", "/api/scans")


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
    """Upload a Postman collection, Burp export, or OpenAPI spec for API scanning.

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
    """Delete a scan and its results.

    Args:
        scan_id: The scan ID to delete.

    Returns:
        Confirmation of deletion.
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
    return json.dumps(_request("GET", "/api/scans"), indent=2)


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
