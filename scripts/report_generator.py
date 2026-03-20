"""Per-model security reports with CVE/CVSS, logical severity, and exploit evidence.

Auto-discovers scan results from results/raw/ -- works for any target.
CVE/CVSS data sourced dynamically from NVD API + OSV.dev (cached locally).
ZERO LLM cost - pure offline analysis.

Usage:
    python scripts/report_generator.py                  # process all results
    python scripts/report_generator.py --file result.json  # process one file
"""
import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fpdf import FPDF
from cve_lookup import (
    enrich_library_finding, extract_libraries, lookup_cve, get_cwe_info
)
from triage_engine import classify as universal_classify
from triage_engine import find_tests as universal_find_tests
from triage_engine import _build_curl as universal_build_curl

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE, "results", "raw")
OUT_DIR = os.path.join(BASE, "results", "reports")


def _discover_results(raw_dir):
    """Auto-discover all aiagent_*.json result files in raw_dir."""
    pattern = os.path.join(raw_dir, "aiagent_*.json")
    files = sorted(glob.glob(pattern))
    discovered = []
    for fpath in files:
        for enc in ("utf-8", "utf-8-sig"):
            try:
                with open(fpath, encoding=enc) as f:
                    data = json.load(f)
                model = data.get("model", "") or data.get("metadata", {}).get("model", "")
                if not model:
                    base = os.path.basename(fpath)
                    model = base.replace("aiagent_", "").rsplit("_T", 1)[0]
                discovered.append({"path": fpath, "model": model, "encoding": enc, "data": data})
                break
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
    return discovered


def _model_display(model_key):
    """Generate a human-readable model name from the raw model key."""
    name = model_key
    name = re.sub(r"^(us\.anthropic\.|anthropic\.)", "", name)
    name = re.sub(r"^gemini/", "", name)
    name = re.sub(r"-\d{8}(-v\d:\d)?$", "", name)
    name = name.replace("-", " ").replace("_", " ").title()
    return name


def _model_slug(model_key):
    """Generate a safe filename slug from the model key."""
    slug = model_key
    slug = re.sub(r"^(us\.anthropic\.|anthropic\.)", "", slug)
    slug = re.sub(r"^gemini/", "", slug)
    slug = re.sub(r"-\d{8}(-v\d:\d)?$", "", slug)
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", slug).strip("_")
    return slug

SEV_COLORS = {"Critical": (180, 30, 30), "High": (220, 80, 30), "Medium": (220, 160, 30), "Low": (60, 140, 200), "Info": (120, 120, 120), "Not Exploitable": (20, 140, 60), "TBD": (217, 119, 6)}
VERDICT_COLORS = {"TRUE_POSITIVE": (200, 40, 40), "FALSE_POSITIVE": (20, 140, 60), "NEEDS_VERIFICATION": (200, 160, 20), "NOT_A_FINDING": (120, 120, 120), "MANUAL_REVIEW": (217, 119, 6)}
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


_rg_unicode_font = None

def _rg_init_fonts(pdf):
    """Register Unicode TTF font if available on the system."""
    global _rg_unicode_font
    if _rg_unicode_font is False:
        return
    if _rg_unicode_font:
        for style, path in _rg_unicode_font.items():
            pdf.add_font("DJV", style, path, uni=True)
        return
    from pathlib import Path as _P
    candidates = {
        "": ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/TTF/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans.ttf"],
        "B": ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"],
        "I": ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf"],
    }
    found = {}
    for style, paths in candidates.items():
        for p in paths:
            if _P(p).exists():
                found[style] = p
                break
    if "" in found:
        _rg_unicode_font = {"": found[""], "B": found.get("B", found[""]), "I": found.get("I", found[""]), "BI": found.get("B", found[""])}
        for style, path in _rg_unicode_font.items():
            pdf.add_font("DJV", style, path, uni=True)
    else:
        _rg_unicode_font = False


def _safe(text):
    if not text:
        return ""
    s = str(text)
    s = s.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "").replace("\ufeff", "")
    if _rg_unicode_font:
        return s[:3500]
    s = s.replace("\u2014", " -- ").replace("\u2013", " - ")
    s = s.replace("\u2018", "'").replace("\u2019", "'")
    s = s.replace("\u201c", '"').replace("\u201d", '"')
    s = s.replace("\u2026", "...").replace("\u00a0", " ")
    s = s.replace("\u2022", "*").replace("\u2192", "->").replace("\u2190", "<-")
    s = s.replace("\u2605", "*").replace("\u00b7", "-")
    s = s.replace("\u2713", "[PASS]").replace("\u2714", "[PASS]")
    s = s.replace("\u2717", "[FAIL]").replace("\u2718", "[FAIL]")
    s = s.replace("\u25cf", "*").replace("\u25cb", "o").replace("\u25a0", "#").replace("\u25a1", "[ ]")
    return s.encode("latin-1", errors="replace").decode("latin-1")[:3500]


def _rg_font(pdf, style="", size=10):
    """Use Unicode font if available, else Helvetica."""
    family = "DJV" if _rg_unicode_font else "Helvetica"
    pdf.set_font(family, style, size)


def _build_curl(t):
    req = t.get("request", {})
    m, u = req.get("method", "GET"), req.get("url", "") or req.get("endpoint", "")
    if not u: return ""
    parts = [f"curl -X {m}"]
    headers = req.get("headers", {})
    for k, v in list(headers.items())[:8]:
        parts.append(f"  -H '{_safe(str(k))}: {_safe(str(v)[:120])}'")
    body = req.get("body", "")
    if body:
        if isinstance(body, str):
            try:
                body_obj = json.loads(body)
                b = json.dumps(body_obj, indent=2, default=str)
            except (json.JSONDecodeError, ValueError):
                b = body
        elif isinstance(body, (dict, list)):
            b = json.dumps(body, indent=2, default=str)
        else:
            b = str(body)
        if "content-type" not in {k.lower() for k in headers}:
            parts.append("  -H 'Content-Type: application/json'")
        parts.append(f"  -d '{_safe(b[:1200])}'")
    parts.append(f"  '{_safe(u[:400])}'")
    return " \\\n".join(parts)


def find_tests(finding, test_log, limit=3):
    url = (finding.get("url", "") or "").split("?")[0]
    param = finding.get("parameter", "") or ""
    matched = []
    for t in test_log:
        req = t.get("request", {})
        t_url = req.get("url", "") or req.get("endpoint", "")
        score = 0
        if url and url in t_url: score += 3
        if param and param.lower() in json.dumps(req, default=str).lower(): score += 2
        if score > 0: matched.append((score, t))
    matched.sort(key=lambda x: -x[0])
    return [m[1] for m in matched[:limit]]


def get_statuses(tests):
    statuses = []
    for t in tests:
        resp = t.get("response_summary", {})
        if not isinstance(resp, dict): continue
        s = resp.get("status")
        if s: statuses.append(s)
        for r in resp.get("results", []):
            if isinstance(r, dict) and r.get("status"):
                statuses.append(r["status"])
    return statuses



# Classification is handled by triage_engine.py (universal_classify).
# CWE/CVSS profiles are defined in triage_engine.CWE_PROFILES.
# CVE lookup for libraries is handled by cve_lookup.py.


# ==========================================================================
# PDF Report
# ==========================================================================

class Report(FPDF):
    def __init__(self, model, target=""):
        super().__init__()
        self._model = model
        self._target = target

    def header(self):
        _rg_font(self, "B", 9)
        self.set_text_color(80, 80, 80)
        label = _safe(f"Security Report - {self._model}")
        if self._target:
            label = _safe(f"Security Report - {self._model} | {self._target}")
        self.cell(0, 7, label, align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        _rg_font(self, "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, _safe(f"Page {self.page_no()}/{{nb}} | {self._model} | {datetime.now().strftime('%Y-%m-%d')}"), align="C")

    def section(self, title, color=(30, 60, 120)):
        _rg_font(self, "B", 14)
        self.set_text_color(*color)
        self.cell(0, 10, _safe(title), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*color)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def kv(self, label, value, lc=(80, 80, 80), vc=(30, 30, 30)):
        _rg_font(self, "B", 9)
        self.set_text_color(*lc)
        self.cell(32, 5, _safe(label))
        _rg_font(self, "", 9)
        self.set_text_color(*vc)
        self.multi_cell(0, 5, _safe(value))
        self.ln(0.5)

    def box(self, label, text, bg, border=None, tc=(30, 30, 30)):
        if not text: return
        self.ln(1)
        _rg_font(self, "B", 8)
        self.set_text_color(*tc)
        self.cell(0, 5, _safe(label), new_x="LMARGIN", new_y="NEXT")
        x, y, w = self.get_x(), self.get_y(), 190
        _rg_font(self, "", 7)
        safe_text = _safe(text[:3000])
        lines = self.multi_cell(w - 6, 3.5, safe_text, dry_run=True, output="LINES")
        h = min(max(len(lines) * 3.5 + 6, 10), 240)
        if y + h > 270:
            self.add_page()
            y = self.get_y()
            if h > 260:
                h = 260
        self.set_fill_color(*bg)
        if border:
            self.set_draw_color(*border)
            self.rect(x, y, w, h, style="DF")
        else:
            self.rect(x, y, w, h, style="F")
        self.set_xy(x + 3, y + 3)
        self.set_text_color(*tc)
        self.multi_cell(w - 6, 3.5, safe_text)
        self.set_y(y + h + 1)

    def badge(self, sev, verdict):
        c = SEV_COLORS.get(sev, (100, 100, 100))
        vc = VERDICT_COLORS.get(verdict, (100, 100, 100))
        self.set_fill_color(*c)
        self.set_text_color(255, 255, 255)
        _rg_font(self, "B", 8)
        self.cell(22, 6, _safe(sev), fill=True, align="C")
        self.cell(2, 6, "")
        self.set_fill_color(*vc)
        self.cell(42, 6, _safe(verdict.replace("_", " ").title()), fill=True, align="C")
        self.ln(8)

    def stage_header(self, label, color=(60, 60, 60), bg=(240, 240, 240)):
        if self.get_y() > 260:
            self.add_page()
        self.ln(2)
        self.set_fill_color(*bg)
        self.set_draw_color(*color)
        _rg_font(self, "B", 8)
        self.set_text_color(*color)
        self.cell(190, 6, _safe(f"  {label}"), fill=True, border="LTR",
                  new_x="LMARGIN", new_y="NEXT")
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_line_width(0.2)
        self.ln(1)


def _impact_oneliner(f):
    """Generate a concise impact statement from finding data."""
    title = (f.get("title", "") or "").lower()
    v = f["verdict"]
    if v == "FALSE_POSITIVE":
        return "No impact - false positive"
    if v == "NOT_A_FINDING":
        return "Positive observation"
    if "rate limit" in title or "brute" in title:
        return "Credential brute-force possible against login endpoint"
    if "react" in title and ("version" in title or "outdated" in title or "cve" in title):
        return "Known XSS vectors in React 16.x (CVE-2018-6341)"
    if "jquery" in title or "bootstrap" in title or "outdated javascript" in title:
        return "Known XSS via jQuery/Bootstrap CVEs"
    if "hsts" in title:
        return "MITM possible on first HTTP visit (no HSTS preload)"
    if "csp" in title:
        return "No XSS mitigation layer if injection found"
    if "sri" in title or "integrity" in title or "subresource" in title:
        return "CDN compromise leads to full JS execution on users"
    if "clickjack" in title or "x-frame" in title:
        return "UI redressing attacks possible"
    if "missing header" in title or "missing security" in title or "missing critical" in title:
        return "Multiple defense-in-depth headers absent"
    if "csrf" in title:
        return "Cross-site request forgery on endpoint"
    if "sql" in title and "injection" in title:
        return "HTTP 500 on special chars (error handling, not SQLi)"
    if "ssrf" in title:
        return "SSRF attempt - server redirected (not exploitable)"
    if "information disclosure" in title or "server stack" in title or "infrastructure" in title:
        return "Server version/stack leaked (aids reconnaissance)"
    if "status" in title and "accessible" in title:
        return "Internal status page publicly accessible"
    if "cors" in title:
        return "CORS not configured (browser default is safe)"
    if "staging" in title or "development" in title:
        return "Staging/debug references in production code"
    if "third-party" in title or "tag management" in title:
        return "External scripts loaded without SRI protection"
    if "input validation" in title or "accepts negative" in title:
        return "Server accepts invalid input values"
    if "error" in title and "handling" in title:
        return "HTTP 500 on malformed input (unhandled exception)"
    if "logging" in title:
        return "No security event logging detected"
    if "oauth" in title or "oidc" in title or "pkce" in title:
        return "OAuth/OIDC configuration may have weaknesses"
    if "session" in title:
        return "Session management issue suspected"
    if "prototype" in title:
        return "Client-side prototype pollution possible"
    if "redirect" in title:
        return "Open redirect may enable phishing"
    if "timing" in title:
        return "Timing differences may reveal valid accounts"
    if "method" in title:
        return "HTTP method handling reveals endpoint info"
    if "access control" in title:
        return "Auth check order issue (501 before 401)"
    if "form" in title:
        return "Login form has novalidate attribute"
    if "configuration" in title:
        return "Internal API config exposed client-side"
    if "replay" in title or "idempotency" in title:
        return "Request replay accepted on log endpoint"
    reason = f.get("reason", "") or f.get("dev_action", "") or ""
    return reason[:70] + "..." if len(reason) > 70 else reason or "See details"


def _build_repro_steps(f):
    """Auto-generate clear, copy-pasteable steps to reproduce from finding data."""
    url = f.get("url") or ""
    param = f.get("parameter") or ""
    title = f.get("title") or ""
    curls = f.get("all_curls") or []
    curl_single = f.get("curl") or ""
    responses = f.get("all_responses") or []
    evidence = f.get("scanner_evidence") or ""
    v_method = f.get("verification_method") or ""
    v_evidence = f.get("verification_evidence") or ""
    title_lower = title.lower()

    best_curl = ""
    if curls:
        with_body = [c for c in curls if "-d " in c]
        best_curl = with_body[0] if with_body else curls[0]
    elif curl_single:
        best_curl = curl_single

    resp_status = ""
    if responses and isinstance(responses[0], dict):
        resp_status = str(responses[0].get("status", ""))

    steps = []
    s = 1

    # -- Prerequisites --
    steps.append(f"{s}. Prerequisites:")
    steps.append("   - Tool: curl (terminal) or Postman")
    if url:
        steps.append(f"   - Target URL: {url}")
    if param:
        steps.append(f"   - Affected parameter/component: {param}")
    s += 1

    # -- Send the request --
    if best_curl:
        steps.append(f"\n{s}. Copy and run this exact request:")
        steps.append(f"\n{best_curl[:600]}")
        s += 1
    elif url:
        steps.append(f"\n{s}. Send a request to: {url}")
        s += 1

    # -- Expected behavior / what to look for (type-specific) --
    steps.append(f"\n{s}. What to look for in the response:")

    if "header" in title_lower or "hsts" in title_lower or "csp" in title_lower or "x-frame" in title_lower:
        steps.append("   - Open browser DevTools (F12) > Network tab > click the request")
        steps.append("   - Check 'Response Headers' section")
        steps.append(f"   - Confirm the header '{param or title}' is ABSENT from the response")
        if v_evidence:
            steps.append(f"   - Scanner confirmed: {v_evidence[:200]}")
    elif "cookie" in title_lower or "httponly" in title_lower or "samesite" in title_lower:
        steps.append("   - Inspect the Set-Cookie response headers")
        steps.append("   - Check if HttpOnly, Secure, and SameSite flags are present")
        steps.append(f"   - Missing attribute: {param or 'see evidence above'}")
    elif "sql" in title_lower and "injection" in title_lower:
        steps.append(f"   - Inject a single quote (') into the '{param}' parameter")
        steps.append("   - Look for SQL error messages in the response (e.g. 'syntax error', 'mysql', 'ORA-')")
        steps.append("   - Also try: ' OR '1'='1 vs ' OR '1'='2 — compare response lengths")
        if resp_status:
            steps.append(f"   - Original response returned HTTP {resp_status}")
    elif "xss" in title_lower or "cross-site scripting" in title_lower:
        steps.append(f"   - Inject a test payload into '{param}': <script>alert(1)</script>")
        steps.append("   - Check if the payload appears UNENCODED in the HTML response")
        steps.append("   - If encoded as &lt;script&gt; — it is properly sanitized (not vulnerable)")
    elif "ssrf" in title_lower:
        steps.append(f"   - Set '{param}' to: http://169.254.169.254/latest/meta-data/")
        steps.append("   - Check if the response contains AWS metadata (ami-id, instance-id)")
        steps.append("   - Also try: http://127.0.0.1:80/ and check for internal content")
    elif "redirect" in title_lower:
        steps.append(f"   - Set '{param}' to: https://evil.example.com/")
        steps.append("   - Check if the server returns 301/302 with Location: https://evil.example.com/")
        steps.append("   - If it does, open redirect is confirmed")
    elif "csrf" in title_lower:
        steps.append("   - Submit the form/POST request WITHOUT any CSRF token")
        steps.append("   - If the server accepts it (HTTP 200/201), CSRF protection is missing")
        steps.append("   - If the server rejects it (HTTP 403/422), protection is enforced")
    elif "rate limit" in title_lower or "brute" in title_lower:
        steps.append("   - Send the same POST request 15+ times rapidly")
        steps.append("   - Check if you ever get HTTP 429 (Too Many Requests)")
        steps.append("   - If all requests return 200, no rate limiting is in place")
    elif "idor" in title_lower or "insecure direct" in title_lower:
        steps.append("   - Change the numeric ID in the URL to a different user's ID (e.g. +1)")
        steps.append("   - If you get HTTP 200 with different user data, IDOR is confirmed")
        steps.append("   - If you get HTTP 403/401, access control is enforced")
    elif "path traversal" in title_lower or "file inclusion" in title_lower:
        steps.append(f"   - Set '{param}' to: ../../../../../../etc/passwd")
        steps.append("   - Check if the response contains 'root:x:0' or similar OS file content")
    elif "command" in title_lower and "injection" in title_lower:
        steps.append(f"   - Set '{param}' to: ; sleep 5")
        steps.append("   - Measure response time — if it takes ~5s longer than normal, OS command executed")
        steps.append("   - Also try: ; id  — look for 'uid=' in the response")
    elif "exposure" in title_lower or "sensitive" in title_lower or "information" in title_lower:
        steps.append("   - Examine the response body for sensitive data:")
        steps.append("   - Look for: internal IPs, stack traces, API keys, version numbers, user data")
    elif "auth" in title_lower or "session" in title_lower or "token" in title_lower:
        steps.append("   - Try accessing the endpoint without authentication headers")
        steps.append("   - If access is granted, authentication bypass is confirmed")
    else:
        steps.append("   - Compare the response with a normal/baseline request")
        steps.append("   - Look for unexpected behavior, error messages, or data leakage")
    s += 1

    # -- Actual observed behavior --
    if resp_status or evidence:
        steps.append(f"\n{s}. What the scanner actually observed:")
        if resp_status:
            steps.append(f"   - Server responded with HTTP {resp_status}")
        if evidence:
            ev_short = evidence[:300].replace("\n", " ")
            steps.append(f"   - Evidence: {ev_short}")
        s += 1

    # -- Verification --
    if v_method and v_method != "none":
        steps.append(f"\n{s}. Runtime verification result:")
        steps.append(f"   - Method: {v_method.replace('_', ' ').title()}")
        if v_evidence:
            steps.append(f"   - Result: {v_evidence[:250]}")
        s += 1

    # -- Baseline comparison --
    steps.append(f"\n{s}. To confirm: send a clean/normal request (no payload) and compare both responses.")

    return "\n".join(steps)


def _remediation_oneliner(f):
    """Generate a concise remediation from dev_action."""
    da = f.get("dev_action", "") or ""
    if not da:
        return "Manual review required"
    first_sentence = da.split(".")[0].strip()
    if len(first_sentence) > 75:
        return first_sentence[:72] + "..."
    return first_sentence


def _format_resp_line(ri, resp):
    """Format a single response entry from the test log with full detail."""
    lines = []
    status = resp.get("status", "")
    if status:
        lines.append(f"HTTP {status}")
    if resp.get("anomaly"):
        lines.append(">>> ANOMALY DETECTED <<<")
    if resp.get("reflected"):
        lines.append(f"Payload Reflected: {resp['reflected']}")
    if resp.get("accessible") is not None:
        lines.append(f"Accessible: {resp['accessible']}")
    if resp.get("error"):
        lines.append(f"Error: {resp['error']}")
    hdrs = resp.get("headers")
    if hdrs and isinstance(hdrs, dict):
        hdr_lines = [f"  {k}: {v}" for k, v in list(hdrs.items())[:10]]
        lines.append("Response Headers:\n" + "\n".join(hdr_lines))
    body = resp.get("body", "")
    if body:
        body_str = str(body)[:1000]
        try:
            body_obj = json.loads(body_str) if isinstance(body_str, str) else body_str
            if isinstance(body_obj, (dict, list)):
                body_str = json.dumps(body_obj, indent=2, default=str)[:1000]
        except (json.JSONDecodeError, ValueError):
            pass
        lines.append(f"Response Body:\n{body_str}")
    if not lines:
        lines.append("(no response data)")
    return "\n".join(lines)


def render(pdf, idx, f, link_id=None):
    if pdf.get_y() > 195:
        pdf.add_page()

    if link_id is not None:
        pdf.set_link(link_id, y=pdf.get_y(), page=pdf.page)

    v = f["verdict"]
    sev = f["final_severity"]
    sc = VERDICT_COLORS.get(v, (100, 100, 100))
    pdf.set_draw_color(*sc)
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(2)

    _rg_font(pdf, "B", 10)
    pdf.set_text_color(30, 30, 30)
    pdf.multi_cell(0, 5, _safe(f"#{idx}  {f['title']}"))
    pdf.ln(1)
    pdf.badge(sev, v)

    if f["scanner_severity"] != sev:
        pdf.kv("AI Sev -> Triage Sev:", f"{f['scanner_severity']} -> {sev}", vc=(180, 30, 30))
    if f.get("cvss"):
        pdf.kv("CVSS:", f"{f['cvss']:.1f} ({f.get('cvss_vector', '')})")
    if f.get("cvss_rationale"):
        pdf.kv("CVSS Rationale:", f["cvss_rationale"])
    if f.get("cve"):
        pdf.kv("CVE/CWE:", f["cve"])
    if f.get("cwe") and f["cwe"] not in (f.get("cve") or ""):
        pdf.kv("CWE:", f["cwe"])
    if f.get("owasp"):
        pdf.kv("OWASP:", f["owasp"])
    if f["url"]:
        pdf.kv("URL:", f["url"])
    if f["parameter"]:
        pdf.kv("Param:", f["parameter"])

    # ══════════════════════════════════════════════════════════════
    # STAGE 1: AI AGENT — what the LLM found during scanning
    # ══════════════════════════════════════════════════════════════
    has_scan_evidence = (
        f.get("scanner_evidence")
        or f.get("all_curls")
        or f.get("curl")
        or f.get("all_responses")
        or f.get("response_status")
    )
    if has_scan_evidence and v not in ("NOT_A_FINDING",):
        pdf.stage_header(
            "STAGE 1: AI AGENT SCAN  (LLM-driven testing during the scan)",
            color=(30, 60, 120), bg=(230, 238, 255),
        )

        if f.get("scanner_evidence"):
            if v == "TRUE_POSITIVE":
                ev_label = "EXPLOIT EVIDENCE (what the AI agent detected):"
                ev_bg, ev_border = (255, 245, 230), (200, 120, 30)
            elif v == "MANUAL_REVIEW":
                ev_label = "AI EVIDENCE (requires human verification):"
                ev_bg, ev_border = (255, 248, 230), (217, 119, 6)
            else:
                ev_label = "LLM EVIDENCE (what the AI agent reported):"
                ev_bg, ev_border = (240, 248, 255), (100, 150, 200)
            pdf.box(ev_label, f["scanner_evidence"], bg=ev_bg, border=ev_border)

        all_curls = f.get("all_curls", [])
        all_responses = f.get("all_responses", [])

        if all_curls:
            for ci, curl in enumerate(all_curls[:3], 1):
                label = f"REQUEST #{ci} (sent by AI agent):"
                pdf.box(label, curl,
                        bg=(245, 248, 255), border=(100, 120, 180))

                if ci <= len(all_responses):
                    resp = all_responses[ci - 1]
                    resp_text = _format_resp_line(ci, resp)
                    is_anomaly = resp.get("anomaly")
                    pdf.box(
                        f"  RESPONSE #{ci}:" + (" >>> ANOMALY <<<" if is_anomaly else ""),
                        resp_text,
                        bg=(255, 230, 230) if is_anomaly else (255, 252, 245),
                        border=(200, 40, 40) if is_anomaly else (180, 160, 100),
                    )
        elif f.get("curl"):
            pdf.box("SCAN REQUEST (sent by AI agent):", f["curl"],
                    bg=(245, 248, 255), border=(100, 120, 180))

        remaining_responses = all_responses[len(all_curls):] if all_curls else all_responses
        if remaining_responses:
            resp_lines = [_format_resp_line(ri, resp)
                          for ri, resp in enumerate(remaining_responses, len(all_curls) + 1)]
            pdf.box("ADDITIONAL RESPONSES:", "\n---\n".join(resp_lines[:5]),
                    bg=(255, 252, 245), border=(180, 160, 100))

        if not all_curls and not f.get("curl") and f.get("response_status"):
            pdf.box("APPLICATION RESPONSE STATUS CODES:",
                    f"Status codes observed: {f['response_status']}",
                    bg=(255, 252, 245), border=(180, 160, 100))

    # ══════════════════════════════════════════════════════════════
    # STAGE 2: RUNTIME VERIFICATION — replay against live target
    # ══════════════════════════════════════════════════════════════
    v_method = f.get("verification_method", "none")
    v_evidence = f.get("verification_evidence", "")
    has_verification = v_method and v_method != "none"

    if has_verification and v not in ("NOT_A_FINDING",):
        rv_prefix = ""
        if "[RUNTIME VERIFIED]" in (f.get("reason") or ""):
            rv_prefix = "CONFIRMED"
        elif "[RUNTIME DISPROVED]" in (f.get("reason") or ""):
            rv_prefix = "DISPROVED"
        elif "[RUNTIME INCONCLUSIVE]" in (f.get("reason") or ""):
            rv_prefix = "INCONCLUSIVE"

        if rv_prefix == "CONFIRMED":
            stg_color, stg_bg = (20, 100, 40), (220, 245, 220)
        elif rv_prefix == "DISPROVED":
            stg_color, stg_bg = (160, 30, 30), (255, 230, 230)
        else:
            stg_color, stg_bg = (140, 120, 20), (255, 250, 220)

        pdf.stage_header(
            f"STAGE 2: RUNTIME VERIFICATION  (payload replay against live target)"
            + (f"  [{rv_prefix}]" if rv_prefix else ""),
            color=stg_color, bg=stg_bg,
        )

        pdf.kv("Method:", v_method.replace("_", " ").title(),
               lc=(60, 60, 60), vc=(30, 30, 30))

        if v_evidence:
            if rv_prefix == "CONFIRMED":
                box_bg, box_bd = (220, 245, 220), (20, 140, 60)
            elif rv_prefix == "DISPROVED":
                box_bg, box_bd = (255, 230, 230), (200, 40, 40)
            else:
                box_bg, box_bd = (255, 250, 220), (180, 150, 40)
            pdf.box("REPLAY RESULT:", v_evidence, bg=box_bg, border=box_bd)

        v_details = f.get("verification_details") or {}
        exchanges = v_details.get("exchanges", [])
        for ei, ex in enumerate(exchanges[:5], 1):
            lbl = ex.get("label", f"Request #{ei}")
            method = ex.get("method", "GET")
            ex_url = ex.get("url", "")
            req_body = ex.get("request_body", "")
            status = ex.get("status")
            resp_body = ex.get("response_body", "")
            resp_size = ex.get("response_size", 0)

            req_text = f"{method} {ex_url}"
            if req_body:
                req_text += f"\nBody: {req_body}"
            pdf.box(f"REPLAY REQUEST #{ei} — {lbl}:", req_text,
                    bg=(240, 245, 255), border=(80, 100, 160))

            resp_text = f"HTTP {status or '(no response)'}"
            if resp_size:
                resp_text += f"  ({resp_size} chars)"
            if ex.get("response_headers"):
                resp_text += f"\n--- Headers ---\n{ex['response_headers'][:500]}"
            if ex.get("set_cookie_headers"):
                resp_text += "\n--- Set-Cookie ---\n" + "\n".join(ex["set_cookie_headers"])
            if resp_body and resp_body != "(no response)":
                resp_text += f"\n--- Body (first 600 chars) ---\n{resp_body[:600]}"
            pdf.box(f"  REPLAY RESPONSE #{ei}:", resp_text,
                    bg=(255, 252, 240), border=(160, 140, 80))
        if has_verification and has_scan_evidence:
            ai_sev = f.get("scanner_severity", "?")
            ai_title = (f.get("title") or "")[:80]
            rv_verdict = f.get("verdict", "?")
            comparison = (
                f"AI Agent reported: {ai_title} (severity: {ai_sev})\n"
                f"Runtime Replay:    {rv_prefix or rv_verdict} via {v_method.replace('_', ' ')}\n"
                f"Evidence match:    "
            )
            if rv_prefix == "CONFIRMED":
                comparison += "Runtime replay CONFIRMS the AI agent finding — independently exploitable."
            elif rv_prefix == "DISPROVED":
                comparison += "Runtime replay CONTRADICTS the AI agent — the finding is NOT exploitable in current state."
            else:
                comparison += "Runtime replay was INCONCLUSIVE — cannot independently confirm or deny."
            pdf.box("AI FINDING vs RUNTIME VERIFICATION:", comparison,
                    bg=(248, 248, 255), border=(120, 120, 180))

    elif v not in ("NOT_A_FINDING",) and has_scan_evidence:
        pdf.stage_header(
            "STAGE 2: RUNTIME VERIFICATION  (not attempted for this finding type)",
            color=(120, 120, 120), bg=(245, 245, 245),
        )
        _rg_font(pdf, "I", 8)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 4, _safe("No replay verifier available for this vulnerability class."),
                 new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    # ══════════════════════════════════════════════════════════════
    # STAGE 3: TRIAGE ENGINE — final verdict + reasoning
    # ══════════════════════════════════════════════════════════════
    if v not in ("NOT_A_FINDING",):
        if v == "TRUE_POSITIVE":
            stg_color, stg_bg = (20, 100, 40), (220, 245, 220)
        elif v == "FALSE_POSITIVE":
            stg_color, stg_bg = (160, 30, 30), (255, 230, 230)
        elif v == "MANUAL_REVIEW":
            stg_color, stg_bg = (160, 90, 0), (255, 243, 220)
        else:
            stg_color, stg_bg = (140, 120, 20), (255, 250, 220)

        pdf.stage_header(
            "STAGE 3: TRIAGE ENGINE DECISION  (automated evidence analysis)",
            color=stg_color, bg=stg_bg,
        )

        reason = f.get("reason") or ""
        if v == "TRUE_POSITIVE":
            pdf.box("VERDICT: CONFIRMED  -  This is a real vulnerability.",
                    reason or "Verified — see evidence above.",
                    bg=(220, 245, 220), border=(60, 160, 60))
        elif v == "FALSE_POSITIVE":
            pdf.box("VERDICT: FALSE POSITIVE  -  Not a real issue.",
                    reason,
                    bg=(255, 225, 225), border=(200, 40, 40))
        elif v == "MANUAL_REVIEW":
            pdf.box("VERDICT: MANUAL REVIEW REQUIRED  -  Cannot auto-classify.",
                    reason or "Insufficient evidence to decide. Human review needed.",
                    bg=(255, 243, 220), border=(217, 119, 6))
        elif v == "NEEDS_VERIFICATION":
            pdf.box("VERDICT: NEEDS MANUAL VERIFICATION",
                    reason or "Automated analysis was inconclusive. Manual testing required.",
                    bg=(255, 245, 210), border=(200, 160, 20))

        steps_text = f.get("steps") or ""
        if not steps_text:
            steps_text = _build_repro_steps(f)
        if steps_text:
            pdf.box("STEPS TO REPRODUCE:", steps_text,
                    bg=(255, 255, 235), border=(180, 140, 40))

        if f.get("dev_action"):
            pdf.box("DEVELOPER ACTION:", f["dev_action"],
                    bg=(230, 240, 255), border=(60, 100, 180))

    pdf.ln(2)


SOURCE_BADGE_COLORS = {"ai": (139, 92, 246)}


def _render_summary_table(pdf, all_findings, link_ids):
    """Render a clickable summary table. Each row links to the detail via link_ids."""
    has_sources = any(f.get("source") and f.get("source") != "ai" for f in all_findings)
    if has_sources:
        col_w = [7, 12, 12, 14, 55, 44, 46]
        headers = ["#", "AI Sev", "Triage", "Source", "Finding", "Impact", "Remediation"]
    else:
        col_w = [8, 14, 14, 62, 48, 44]
        headers = ["#", "AI Sev", "Triage", "Finding", "Impact", "Remediation"]
    row_h = 5.5
    hdr_h = 7

    def _draw_header():
        _rg_font(pdf, "B", 7)
        pdf.set_fill_color(30, 60, 120)
        pdf.set_text_color(255, 255, 255)
        for w, label in zip(col_w, headers):
            pdf.cell(w, hdr_h, _safe(label), border=1, fill=True, align="C")
        pdf.ln(hdr_h)

    _draw_header()

    _rg_font(pdf, "", 6.5)
    for i, f in enumerate(all_findings, 1):
        ai_sev = f.get("ai_severity", "") or f.get("scanner_severity", "") or ""
        triage_sev = f["final_severity"]
        ai_sc = SEV_COLORS.get(ai_sev, (100, 100, 100))
        tr_sc = SEV_COLORS.get(triage_sev, (100, 100, 100))
        title_short = (f["title"] or "")[:38 if has_sources else 42]
        impact = _impact_oneliner(f)[:34 if has_sources else 38]
        remed = _remediation_oneliner(f)[:34]
        lid = link_ids[i - 1] if i - 1 < len(link_ids) else None

        if pdf.get_y() + row_h > 272:
            pdf.add_page()
            _draw_header()
            _rg_font(pdf, "", 6.5)

        bg = (245, 248, 255) if i % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*bg)
        pdf.set_text_color(30, 30, 30)

        pdf.cell(col_w[0], row_h, str(i), border="LTB", fill=True, align="C")

        pdf.set_fill_color(*ai_sc)
        pdf.set_text_color(255, 255, 255)
        _rg_font(pdf, "B", 6)
        pdf.cell(col_w[1], row_h, _safe(ai_sev[:4]), border="TB", fill=True, align="C")

        pdf.set_fill_color(*tr_sc)
        pdf.set_text_color(255, 255, 255)
        _rg_font(pdf, "B", 6)
        pdf.cell(col_w[2], row_h, _safe(triage_sev[:4]), border="TB", fill=True, align="C")

        if has_sources:
            src = f.get("source", "ai")
            src_color = SOURCE_BADGE_COLORS.get(src, (100, 100, 100))
            pdf.set_fill_color(*src_color)
            pdf.set_text_color(255, 255, 255)
            _rg_font(pdf, "B", 5.5)
            pdf.cell(col_w[3], row_h, _safe(src.upper()), border="TB", fill=True, align="C")

        find_col = 4 if has_sources else 3
        pdf.set_fill_color(*bg)
        pdf.set_text_color(30, 60, 180)
        _rg_font(pdf, "U", 6.5)
        pdf.cell(col_w[find_col], row_h, _safe(title_short), border="TB", fill=True,
                 link=lid)

        pdf.set_text_color(60, 60, 60)
        _rg_font(pdf, "", 6)
        pdf.cell(col_w[find_col + 1], row_h, _safe(impact), border="TB", fill=True)

        pdf.set_text_color(30, 100, 30)
        _rg_font(pdf, "I", 6)
        pdf.cell(col_w[find_col + 2], row_h, _safe(remed), border="RTB", fill=True)
        pdf.ln(row_h)


def _find_best_tests(finding, test_log, limit=3):
    """Find the most relevant tests for a finding, preferring attack payloads over recon."""
    url = (finding.get("url", "") or "").split("?")[0]
    param = (finding.get("parameter", "") or "").lower()
    title = (finding.get("title", "") or "").lower()
    evidence = str(finding.get("scanner_evidence", "") or finding.get("evidence", "") or "").lower()

    ATTACK_TOOLS = {"inject_payload", "fuzz_parameter", "test_auth_bypass",
                    "test_method_override", "replay_with_modification", "api_request_raw"}

    param_parts = [p.strip().lower() for p in re.split(r'[,|/()]', param) if len(p.strip()) >= 3]

    scored = []
    for t in test_log:
        req = t.get("request", {})
        t_url = req.get("url", "") or req.get("endpoint", "")
        t_url_lower = t_url.lower()
        method = (req.get("method", "") or "").upper()
        body = req.get("body", "")
        body_str = json.dumps(body, default=str).lower() if isinstance(body, (dict, list)) else str(body).lower()
        resp = t.get("response_summary", {}) or {}
        resp_body = str(resp.get("body_snippet", "")).lower() if isinstance(resp, dict) else ""
        phase = (t.get("phase", "") or "").lower()
        tool = (t.get("tool", "") or "").lower()
        score = 0

        if url and url in t_url:
            score += 2
        for pp in param_parts:
            if pp in body_str:
                score += 4
            if pp in t_url_lower:
                score += 3

        if tool in ATTACK_TOOLS:
            score += 5

        if body and body != "{}":
            score += 3
        if method in ("POST", "PUT", "PATCH"):
            score += 1
        if method == "OPTIONS":
            score -= 3

        has_query = "?" in t_url and "=" in t_url
        if has_query and method == "GET":
            score += 2

        resp_status = resp.get("status") if isinstance(resp, dict) else None
        if resp_status and resp_status not in (404,):
            score += 1
        if resp.get("anomaly"):
            score += 5
        if resp.get("reflected"):
            score += 4
        if resp.get("error") and isinstance(resp.get("error"), str) and "unexpected" not in resp["error"].lower():
            score += 2

        title_keywords = re.findall(r'[a-z]{4,}', title)
        for kw in title_keywords[:5]:
            if kw in body_str or kw in resp_body or kw in t_url_lower:
                score += 1

        evidence_keywords = re.findall(r'[a-z_]{4,}', evidence)
        for kw in evidence_keywords[:5]:
            if kw in body_str or kw in resp_body or kw in t_url_lower:
                score += 2

        if "fuzz" in phase or "injection" in phase or "auth" in phase:
            score += 1
        if "recon" in phase and not body and method in ("OPTIONS", "HEAD"):
            score -= 3

        if score > 0:
            scored.append((score, t))

    scored.sort(key=lambda x: -x[0])
    return [m[1] for m in scored[:limit]]


def _enrich_with_all_tests(classified, test_log):
    """Attach full test evidence (all matching payloads + responses) to each finding."""
    for f in classified:
        tests = _find_best_tests(f, test_log, limit=3)
        curls = []
        responses = []
        for t in tests:
            curl = universal_build_curl(t)
            if curl:
                curls.append(curl)
            resp = t.get("response_summary", {})
            if isinstance(resp, dict):
                entry = {}
                if resp.get("status"):
                    entry["status"] = resp["status"]
                if resp.get("headers") and isinstance(resp["headers"], dict):
                    entry["headers"] = {k: str(v)[:120] for k, v in list(resp["headers"].items())[:12]}
                raw_body = resp.get("body_snippet") or resp.get("body") or ""
                if raw_body:
                    body_str = str(raw_body)[:1000]
                    try:
                        body_obj = json.loads(body_str) if isinstance(body_str, str) else body_str
                        if isinstance(body_obj, (dict, list)):
                            body_str = json.dumps(body_obj, indent=2, default=str)[:1000]
                    except (json.JSONDecodeError, ValueError):
                        pass
                    entry["body"] = body_str
                if resp.get("reflected"):
                    entry["reflected"] = resp["reflected"]
                if resp.get("anomaly"):
                    entry["anomaly"] = resp["anomaly"]
                if resp.get("error"):
                    entry["error"] = str(resp["error"])[:400]
                if resp.get("accessible") is not None:
                    entry["accessible"] = resp["accessible"]
                for r in resp.get("results", []):
                    if isinstance(r, dict):
                        sub = {}
                        if r.get("status"):
                            sub["status"] = r["status"]
                        raw_sub = r.get("body_snippet") or r.get("body") or ""
                        if raw_sub:
                            sub["body"] = str(raw_sub)[:800]
                        if r.get("reflected"):
                            sub["reflected"] = r["reflected"]
                        if r.get("anomaly"):
                            sub["anomaly"] = r["anomaly"]
                        if sub:
                            responses.append(sub)
                if entry:
                    responses.append(entry)
        if curls:
            f["all_curls"] = curls
        if responses:
            f["all_responses"] = responses
    return classified


def gen_report(model_key, classified, raw, scan_id=None):
    display = _model_display(model_key)
    slug = _model_slug(model_key)

    test_log = raw.get("summary", {}).get("test_log", []) if raw else []
    classified = _enrich_with_all_tests(classified, test_log)

    tp = [f for f in classified if f["verdict"] == "TRUE_POSITIVE"]
    fp = [f for f in classified if f["verdict"] == "FALSE_POSITIVE"]
    nv = [f for f in classified if f["verdict"] == "NEEDS_VERIFICATION"]
    mr = [f for f in classified if f["verdict"] == "MANUAL_REVIEW"]
    na = [f for f in classified if f["verdict"] == "NOT_A_FINDING"]
    total = len(classified)
    if not total:
        return None

    tp_sorted = sorted(tp, key=lambda x: SEV_ORDER.get(x["final_severity"], 5))
    nv_sorted = sorted(nv, key=lambda x: SEV_ORDER.get(x["final_severity"], 5))
    mr_sorted = sorted(mr, key=lambda x: x.get("confidence", 0), reverse=True)

    target_url = raw.get("target", "") if raw else ""
    pdf = Report(display, target=target_url)
    _rg_init_fonts(pdf)
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # ── Title ──
    _rg_font(pdf, "B", 20)
    pdf.set_text_color(30, 60, 120)
    pdf.cell(0, 12, _safe(f"Security Report: {display}"), align="C",
             new_x="LMARGIN", new_y="NEXT")
    _rg_font(pdf, "", 11)
    pdf.set_text_color(80, 80, 80)
    target_label = f"Target: {target_url}" if target_url else "Target: (see scan config)"
    pdf.cell(0, 7, _safe(target_label),
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7,
             f"Date: {datetime.now().strftime('%B %d, %Y')} | "
             "Three-Stage Pipeline: AI Agent Scan + Runtime Verification + Triage Engine",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    _rg_font(pdf, "", 7)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 3.5, _safe(
        "Stage 1 (AI Agent): LLM autonomously tests the target, generates payloads, and reports findings.  |  "
        "Stage 2 (Runtime Verification): Payloads are replayed against the live target without LLM — real HTTP responses confirm or disprove each finding.  |  "
        "Stage 3 (Triage Engine): Deterministic evidence analysis assigns final verdict (True Positive / False Positive / Manual Review) with CVSS severity."
    ), align="C")
    pdf.ln(4)

    # ── Scan Metadata (duration, cost, coverage) ──
    meta = raw.get("metadata", {}) if raw else {}
    summary = raw.get("summary", {}) if raw else {}

    dur_s = meta.get("scan_duration_seconds")
    cost_usd = meta.get("cost_usd")
    total_tokens = meta.get("total_tokens")
    llm_calls = meta.get("llm_calls")
    pages = summary.get("pages_crawled")
    forms = summary.get("forms_found")
    apis = summary.get("api_endpoints_found")
    test_count = len(summary.get("test_log", []))

    scanner_type = meta.get("scanner") or raw.get("scanner", "ai") if raw else "ai"
    scanner_label = "AI Agent"
    ai_fc = meta.get("ai_findings_count")

    pdf.section("Scan Overview")
    overview_items = [
        ("Model:", display),
        ("Scanner:", scanner_label),
        ("Duration:", f"{dur_s/60:.1f} min ({dur_s:.0f}s)" if dur_s else "N/A"),
        ("LLM Cost:", f"${cost_usd:.4f}" if cost_usd is not None else "N/A"),
        ("Total Tokens:", f"{total_tokens:,}" if total_tokens else "N/A"),
        ("LLM Calls:", str(llm_calls) if llm_calls else "N/A"),
        ("Pages Crawled:", str(pages) if pages else "N/A"),
        ("Forms Found:", str(forms) if forms else "N/A"),
        ("API Endpoints:", str(apis) if apis else "N/A"),
        ("Tests Executed:", str(test_count)),
    ]
    if ai_fc is not None:
        overview_items.append(("AI Findings:", str(ai_fc)))
    for lbl, val in overview_items:
        pdf.kv(lbl, val)
    pdf.ln(3)

    # ── Findings Summary ──
    pdf.section("Findings Summary")
    for lbl, val in [
        ("Total Findings:", str(total)),
        ("True Positives:", str(len(tp))),
        ("False Positives:", str(len(fp))),
        ("Manual Review:", str(len(mr))),
        ("Needs Verify:", str(len(nv))),
        ("Not a Finding:", str(len(na))),
        ("Precision:", f"{len(tp)/(len(tp)+len(fp))*100:.0f}%"
         if (len(tp) + len(fp)) else "N/A"),
    ]:
        pdf.kv(lbl, val)
    pdf.ln(2)

    # Severity breakdown for confirmed findings
    _rg_font(pdf, "B", 10)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 6, "Confirmed by CVSS-based Severity:", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        cnt = len([f for f in tp if f["final_severity"] == sev])
        if cnt:
            pdf.set_fill_color(*SEV_COLORS[sev])
            pdf.set_text_color(255, 255, 255)
            _rg_font(pdf, "B", 9)
            pdf.cell(22, 6, _safe(sev), fill=True, align="C")
            pdf.set_text_color(30, 30, 30)
            _rg_font(pdf, "", 10)
            pdf.cell(20, 6, f"  {cnt}")
            pdf.ln(7)

    # Pre-create internal link IDs for every finding (used in tables -> detail jump)
    tp_links = [pdf.add_link() for _ in tp_sorted]
    mr_links = [pdf.add_link() for _ in mr_sorted]
    nv_links = [pdf.add_link() for _ in nv_sorted]
    fp_links = [pdf.add_link() for _ in fp]

    # ── Clickable Summary Table: Confirmed Vulnerabilities ──
    if tp_sorted:
        pdf.add_page()
        pdf.section("Findings Overview - Confirmed Vulnerabilities (click to jump)",
                     (20, 140, 60))
        _rg_font(pdf, "I", 8)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 4, _safe(
            "Click any finding title (blue underline) to jump to full details, "
            "evidence, and reproduction steps."))
        pdf.ln(2)
        _render_summary_table(pdf, tp_sorted, tp_links)

    # ── Clickable Summary Table: Manual Review ──
    if mr_sorted:
        pdf.add_page()
        pdf.section("Findings Overview - Manual Review Required (click to jump)",
                     (217, 119, 6))
        _rg_font(pdf, "I", 8)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 4, _safe(
            "Triage engine could not confidently classify these as TP or FP. "
            "Human review or authenticated re-scan required."))
        pdf.ln(2)
        _render_summary_table(pdf, mr_sorted, mr_links)

    # ── Clickable Summary Table: Needs Verification ──
    if nv_sorted:
        pdf.add_page()
        pdf.section("Findings Overview - Needs Verification (click to jump)",
                     (200, 160, 20))
        _rg_font(pdf, "I", 8)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 4, _safe(
            "These need manual testing. "
            "Click any title to see test steps."))
        pdf.ln(2)
        _render_summary_table(pdf, nv_sorted, nv_links)

    # ── Clickable Summary Table: False Positives ──
    if fp:
        pdf.add_page()
        pdf.section("Findings Overview - False Positives (click to jump)",
                     (200, 40, 40))
        _rg_font(pdf, "I", 8)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 4, _safe(
            "Scanner incorrectly flagged these. Click to see why."))
        pdf.ln(2)
        _render_summary_table(pdf, fp, fp_links)

    # ══════════════════════════════════════════════════════════════
    # DETAIL SECTIONS (set link destinations for clickable table)
    # ══════════════════════════════════════════════════════════════

    # ── Confirmed Vulnerabilities ──
    if tp_sorted:
        pdf.add_page()
        pdf.section(f"Confirmed Vulnerabilities - Details ({len(tp)})",
                     (20, 140, 60))
        _rg_font(pdf, "I", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 5, _safe(
            "Confirmed real issues with CVE/CVSS scores. "
            "Severity is CVSS-based, not scanner-claimed.\n"
            "Each finding shows three stages: (1) AI Agent scan payloads & responses, "
            "(2) Runtime verification replay results, (3) Triage engine final verdict."))
        pdf.ln(2)
        for i, f in enumerate(tp_sorted, 1):
            render(pdf, i, f, link_id=tp_links[i - 1])

    # ── Manual Review ──
    if mr_sorted:
        pdf.add_page()
        pdf.section(f"Manual Review Required - Details ({len(mr)})",
                     (217, 119, 6))
        _rg_font(pdf, "I", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 5, _safe(
            "Insufficient evidence to auto-classify. These need human review "
            "or authenticated re-scan to determine if they are real vulnerabilities."))
        pdf.ln(2)
        for i, f in enumerate(mr_sorted, 1):
            render(pdf, i, f, link_id=mr_links[i - 1])

    # ── Needs Verification ──
    if nv_sorted:
        pdf.add_page()
        pdf.section(f"Needs Verification - Details ({len(nv)})",
                     (200, 160, 20))
        _rg_font(pdf, "I", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 5, _safe(
            "Manual testing needed. "
            "Each finding shows the AI agent's test, verification replay result, and triage reasoning."))
        pdf.ln(2)
        for i, f in enumerate(nv_sorted, 1):
            render(pdf, i, f, link_id=nv_links[i - 1])

    # ── False Positives ──
    if fp:
        pdf.add_page()
        pdf.section(f"False Positives - Details ({len(fp)})", (200, 40, 40))
        _rg_font(pdf, "I", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 5, _safe(
            "Scanner incorrectly flagged these. Red box explains why. "
            "No dev action needed."))
        pdf.ln(2)
        for i, f in enumerate(fp, 1):
            render(pdf, i, f, link_id=fp_links[i - 1])

    # ── Positive Observations ──
    if na:
        pdf.add_page()
        pdf.section(f"Positive Observations ({len(na)})", (120, 120, 120))
        for i, f in enumerate(na, 1):
            _rg_font(pdf, "", 9)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 5, _safe(f"  {i}. {f['title']}"),
                     new_x="LMARGIN", new_y="NEXT")

    os.makedirs(OUT_DIR, exist_ok=True)
    pdf_name = f"report_{scan_id}.pdf" if scan_id else f"scan_{slug}.pdf"
    out = os.path.join(OUT_DIR, pdf_name)
    pdf.output(out)
    return out, total, len(tp), len(fp), len(nv), len(na)


# ==========================================================================
# Main
# ==========================================================================

def main():
    global OUT_DIR

    parser = argparse.ArgumentParser(description="Generate security triage reports from scan results.")
    parser.add_argument("--file", help="Process a single result JSON file")
    parser.add_argument("--raw-dir", default=RAW_DIR, help="Directory with raw scan results")
    parser.add_argument("--out-dir", default=None, help="Output directory for PDF reports")
    args = parser.parse_args()

    if args.out_dir:
        OUT_DIR = args.out_dir

    print("=" * 70)
    print("Security Report Generator - CVE/CVSS, Evidence-Based, Strict Classification")
    print("=" * 70)

    if args.file:
        files = [args.file] if os.path.isabs(args.file) else [os.path.join(BASE, args.file)]
        results = []
        for fp in files:
            for enc in ("utf-8", "utf-8-sig"):
                try:
                    data = json.load(open(fp, encoding=enc))
                    model = data.get("model", "") or data.get("metadata", {}).get("model", "unknown")
                    results.append({"path": fp, "model": model, "encoding": enc, "data": data})
                    break
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
    else:
        results = _discover_results(args.raw_dir)

    if not results:
        print("No scan result files found.")
        return

    print(f"Found {len(results)} result file(s).\n")

    for entry in results:
        raw = entry["data"]
        model_key = entry["model"]
        display = _model_display(model_key)

        findings = raw.get("findings", [])
        test_log = raw.get("summary", {}).get("test_log", [])
        if not findings:
            print(f"  {display}: 0 findings, skipping.")
            continue

        classified = [universal_classify(f, test_log) for f in findings]
        tp = len([c for c in classified if c["verdict"] == "TRUE_POSITIVE"])
        fp = len([c for c in classified if c["verdict"] == "FALSE_POSITIVE"])
        mr = len([c for c in classified if c["verdict"] == "MANUAL_REVIEW"])
        nv = len([c for c in classified if c["verdict"] == "NEEDS_VERIFICATION"])
        na = len([c for c in classified if c["verdict"] == "NOT_A_FINDING"])
        print(f"  {display}: {len(findings)} findings -> {tp} TP, {fp} FP, {mr} MR, {nv} NV, {na} NA")

        result = gen_report(model_key, classified, raw)
        if result:
            path, total, tp_c, fp_c, nv_c, na_c = result
            print(f"  -> {path}")

    print(f"\n{'='*70}\nDone.")


if __name__ == "__main__":
    main()
