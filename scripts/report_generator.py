"""Per-model DAST reports with CVE/CVSS, logical severity, and exploit evidence.

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

SEV_COLORS = {"Critical": (180, 30, 30), "High": (220, 80, 30), "Medium": (220, 160, 30), "Low": (60, 140, 200), "Info": (120, 120, 120)}
VERDICT_COLORS = {"TRUE_POSITIVE": (20, 140, 60), "FALSE_POSITIVE": (200, 40, 40), "NEEDS_VERIFICATION": (200, 160, 20), "NOT_A_FINDING": (120, 120, 120)}
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _safe(text):
    if not text: return ""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")[:2500]


def _build_curl(t):
    req = t.get("request", {})
    m, u = req.get("method", "GET"), req.get("url", "") or req.get("endpoint", "")
    if not u: return ""
    parts = [f"curl -X {m}"]
    for k, v in list(req.get("headers", {}).items())[:4]:
        parts.append(f"  -H '{_safe(str(k))}: {_safe(str(v)[:60])}'")
    body = req.get("body", "")
    if body:
        b = json.dumps(body, default=str) if isinstance(body, (dict, list)) else str(body)
        parts.append(f"  -d '{_safe(b[:250])}'")
    parts.append(f"  '{_safe(u[:200])}'")
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
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(80, 80, 80)
        label = f"DAST Report - {self._model}"
        if self._target:
            label += f" | {self._target}"
        self.cell(0, 7, label, align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | {self._model} | {datetime.now().strftime('%Y-%m-%d')}", align="C")

    def section(self, title, color=(30, 60, 120)):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*color)
        self.cell(0, 10, _safe(title), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*color)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def kv(self, label, value, lc=(80, 80, 80), vc=(30, 30, 30)):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*lc)
        self.cell(32, 5, _safe(label))
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*vc)
        self.multi_cell(0, 5, _safe(value))
        self.ln(0.5)

    def box(self, label, text, bg, border=None, tc=(30, 30, 30)):
        if not text: return
        self.ln(1)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*tc)
        self.cell(0, 5, _safe(label), new_x="LMARGIN", new_y="NEXT")
        x, y, w = self.get_x(), self.get_y(), 190
        self.set_font("Courier", "", 7)
        lines = self.multi_cell(w - 6, 3.5, _safe(text), dry_run=True, output="LINES")
        h = min(max(len(lines) * 3.5 + 6, 10), 110)
        if y + h > 270:
            self.add_page()
            y = self.get_y()
        self.set_fill_color(*bg)
        if border:
            self.set_draw_color(*border)
            self.rect(x, y, w, h, style="DF")
        else:
            self.rect(x, y, w, h, style="F")
        self.set_xy(x + 3, y + 3)
        self.set_text_color(*tc)
        self.multi_cell(w - 6, 3.5, _safe(text[:1200]))
        self.set_y(y + h + 1)

    def badge(self, sev, verdict):
        c = SEV_COLORS.get(sev, (100, 100, 100))
        vc = VERDICT_COLORS.get(verdict, (100, 100, 100))
        self.set_fill_color(*c)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        self.cell(22, 6, _safe(sev), fill=True, align="C")
        self.cell(2, 6, "")
        self.set_fill_color(*vc)
        self.cell(42, 6, _safe(verdict.replace("_", " ")), fill=True, align="C")
        self.ln(8)


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
    """Auto-generate steps to reproduce from finding data."""
    url = f.get("url") or ""
    param = f.get("parameter") or ""
    title = f.get("title") or ""
    curls = f.get("all_curls") or []
    curl = f.get("curl") or ""
    evidence = f.get("scanner_evidence") or ""
    responses = f.get("all_responses") or []
    method = "GET"

    if curls:
        first_curl = curls[0]
        if "-X POST" in first_curl or "-X PUT" in first_curl:
            method = "POST" if "-X POST" in first_curl else "PUT"

    steps = []
    step = 1

    if url:
        steps.append(f"{step}. Open a browser or API client (e.g. Burp Suite, curl, Postman).")
        step += 1

    if curls:
        steps.append(f"{step}. Send the following request to the target:")
        steps.append(f"   {curls[0][:200]}")
        step += 1
    elif curl:
        steps.append(f"{step}. Send the following request to the target:")
        steps.append(f"   {curl[:200]}")
        step += 1
    elif url:
        steps.append(f"{step}. Navigate to: {url}")
        step += 1

    if param:
        steps.append(f"{step}. Locate the parameter/component: {param}")
        step += 1

    if responses:
        resp = responses[0] if isinstance(responses[0], str) else str(responses[0])
        status = ""
        if "Status:" in resp:
            status = resp.split("Status:")[1].split("|")[0].strip()[:10]
        if status:
            steps.append(f"{step}. Observe the server response (HTTP {status}).")
        else:
            steps.append(f"{step}. Observe the server response.")
        step += 1

    title_lower = title.lower()
    if "header" in title_lower or "missing" in title_lower or "cookie" in title_lower:
        steps.append(f"{step}. Inspect the response headers for the missing security control.")
    elif "injection" in title_lower or "sqli" in title_lower or "xss" in title_lower:
        steps.append(f"{step}. Check if the payload is reflected in the response or triggers an error/behavior change.")
    elif "ssrf" in title_lower:
        steps.append(f"{step}. Check if the server made an outbound request to the injected URL.")
    elif "auth" in title_lower or "session" in title_lower or "token" in title_lower:
        steps.append(f"{step}. Verify whether the authentication/session control is enforced.")
    elif "exposure" in title_lower or "sensitive" in title_lower or "pii" in title_lower:
        steps.append(f"{step}. Check the response body for sensitive data that should not be exposed.")
    elif "log" in title_lower or "debug" in title_lower or "error" in title_lower:
        steps.append(f"{step}. Check if debug/error information or internal state is leaked in the response.")
    else:
        steps.append(f"{step}. Verify the vulnerability by examining the response for anomalous behavior.")
    step += 1

    steps.append(f"{step}. Compare with a baseline (normal) request to confirm the difference.")

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

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(30, 30, 30)
    pdf.multi_cell(0, 5, _safe(f"#{idx}  {f['title']}"))
    pdf.ln(1)
    pdf.badge(sev, v)

    if f["scanner_severity"] != sev:
        pdf.kv("Sev Change:", f"{f['scanner_severity']} -> {sev} (corrected per CVSS)", vc=(180, 30, 30))
    if f.get("cvss"):
        pdf.kv("CVSS:", f"{f['cvss']:.1f} ({f.get('cvss_vector', '')})")
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

    # Verdict box
    if v == "TRUE_POSITIVE":
        pdf.box("CONFIRMED:", f["reason"] or "Verified - see evidence below.",
                bg=(220, 245, 220), border=(60, 160, 60))
    elif v == "FALSE_POSITIVE":
        pdf.box("FALSE POSITIVE - NOT A REAL ISSUE:", f["reason"],
                bg=(255, 225, 225), border=(200, 40, 40))
    elif v == "NEEDS_VERIFICATION":
        pdf.box("NEEDS MANUAL VERIFICATION:", f["reason"] or "See steps below.",
                bg=(255, 245, 210), border=(200, 160, 20))

    # Steps to reproduce (auto-generate if not provided)
    steps_text = f.get("steps") or ""
    if not steps_text and v != "NOT_A_FINDING":
        steps_text = _build_repro_steps(f)
    if steps_text and v != "NOT_A_FINDING":
        pdf.box("STEPS TO REPRODUCE:", steps_text,
                bg=(255, 255, 235), border=(180, 140, 40))

    # Scanner evidence
    if f.get("scanner_evidence") and v not in ("NOT_A_FINDING", "FALSE_POSITIVE"):
        eb = (240, 248, 255) if v == "TRUE_POSITIVE" else (248, 248, 248)
        bd = (100, 150, 200) if v == "TRUE_POSITIVE" else (190, 190, 190)
        pdf.box("SCANNER EVIDENCE:", f["scanner_evidence"], bg=eb, border=bd)

    # HTTP requests (all tested payloads)
    all_curls = f.get("all_curls", [])
    if all_curls and v not in ("NOT_A_FINDING",):
        for ci, curl in enumerate(all_curls[:3], 1):
            label = f"TEST PAYLOAD #{ci}:" if len(all_curls) > 1 else "HTTP REQUEST (actual payload tested):"
            pdf.box(label, curl, bg=(245, 248, 255), border=(100, 120, 180))
    elif f.get("curl") and v not in ("NOT_A_FINDING",):
        pdf.box("HTTP REQUEST:", f["curl"], bg=(245, 248, 255), border=(100, 120, 180))

    # Responses (actual app responses)
    all_responses = f.get("all_responses", [])
    if all_responses and v not in ("NOT_A_FINDING",):
        resp_lines = []
        for ri, resp in enumerate(all_responses[:5], 1):
            parts = []
            if resp.get("status"):
                parts.append(f"Status: {resp['status']}")
            if resp.get("reflected"):
                parts.append(f"Reflected: {resp['reflected']}")
            if resp.get("anomaly"):
                parts.append("** ANOMALY DETECTED **")
            if resp.get("accessible") is not None:
                parts.append(f"Accessible: {resp['accessible']}")
            if resp.get("error"):
                parts.append(f"Error: {resp['error']}")
            if resp.get("body"):
                body_preview = str(resp["body"])[:200]
                parts.append(f"Body: {body_preview}")
            resp_lines.append(f"Response #{ri}: " + " | ".join(parts))
        pdf.box("APPLICATION RESPONSES:", "\n".join(resp_lines),
                bg=(255, 252, 245), border=(180, 160, 100))
    elif f.get("response_status") and v not in ("NOT_A_FINDING",):
        pdf.box("HTTP RESPONSE:", f"Status codes: {f['response_status']}",
                bg=(255, 252, 245), border=(180, 160, 100))

    # Dev action
    if f.get("dev_action") and v not in ("NOT_A_FINDING",):
        pdf.box("DEVELOPER ACTION:", f["dev_action"],
                bg=(230, 240, 255), border=(60, 100, 180))

    pdf.ln(2)


def _render_summary_table(pdf, all_findings, link_ids):
    """Render a clickable summary table. Each row links to the detail via link_ids."""
    col_w = [8, 14, 68, 52, 48]  # #, Sev, Finding, Impact, Remediation
    row_h = 5.5
    hdr_h = 7

    def _draw_header():
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_fill_color(30, 60, 120)
        pdf.set_text_color(255, 255, 255)
        for w, label in zip(col_w, ["#", "Sev", "Finding", "Impact", "Remediation"]):
            pdf.cell(w, hdr_h, _safe(label), border=1, fill=True, align="C")
        pdf.ln(hdr_h)

    _draw_header()

    pdf.set_font("Helvetica", "", 6.5)
    for i, f in enumerate(all_findings, 1):
        sev = f["final_severity"]
        sc = SEV_COLORS.get(sev, (100, 100, 100))
        title_short = (f["title"] or "")[:48]
        impact = _impact_oneliner(f)[:42]
        remed = _remediation_oneliner(f)[:38]
        lid = link_ids[i - 1] if i - 1 < len(link_ids) else None

        if pdf.get_y() + row_h > 272:
            pdf.add_page()
            _draw_header()
            pdf.set_font("Helvetica", "", 6.5)

        bg = (245, 248, 255) if i % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*bg)
        pdf.set_text_color(30, 30, 30)

        pdf.cell(col_w[0], row_h, str(i), border="LTB", fill=True, align="C")

        pdf.set_fill_color(*sc)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 6)
        pdf.cell(col_w[1], row_h, _safe(sev[:4]), border="TB", fill=True, align="C")

        pdf.set_fill_color(*bg)
        pdf.set_text_color(30, 60, 180)
        pdf.set_font("Helvetica", "U", 6.5)
        pdf.cell(col_w[2], row_h, _safe(title_short), border="TB", fill=True,
                 link=lid)

        pdf.set_text_color(60, 60, 60)
        pdf.set_font("Helvetica", "", 6)
        pdf.cell(col_w[3], row_h, _safe(impact), border="TB", fill=True)

        pdf.set_text_color(30, 100, 30)
        pdf.set_font("Helvetica", "I", 6)
        pdf.cell(col_w[4], row_h, _safe(remed), border="RTB", fill=True)
        pdf.ln(row_h)


def _enrich_with_all_tests(classified, test_log):
    """Attach full test evidence (all matching payloads + responses) to each finding."""
    for f in classified:
        tests = universal_find_tests(f, test_log, limit=5)
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
                if resp.get("body_snippet"):
                    entry["body"] = str(resp["body_snippet"])[:300]
                if resp.get("reflected"):
                    entry["reflected"] = resp["reflected"]
                if resp.get("anomaly"):
                    entry["anomaly"] = resp["anomaly"]
                if resp.get("error"):
                    entry["error"] = str(resp["error"])[:200]
                if resp.get("accessible") is not None:
                    entry["accessible"] = resp["accessible"]
                for r in resp.get("results", []):
                    if isinstance(r, dict):
                        sub = {}
                        if r.get("status"):
                            sub["status"] = r["status"]
                        if r.get("body_snippet"):
                            sub["body"] = str(r["body_snippet"])[:200]
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


def gen_report(model_key, classified, raw):
    display = _model_display(model_key)
    slug = _model_slug(model_key)

    test_log = raw.get("summary", {}).get("test_log", []) if raw else []
    classified = _enrich_with_all_tests(classified, test_log)

    tp = [f for f in classified if f["verdict"] == "TRUE_POSITIVE"]
    fp = [f for f in classified if f["verdict"] == "FALSE_POSITIVE"]
    nv = [f for f in classified if f["verdict"] == "NEEDS_VERIFICATION"]
    na = [f for f in classified if f["verdict"] == "NOT_A_FINDING"]
    total = len(classified)
    if not total:
        return None

    # Sort TP and NV by severity for consistent ordering
    tp_sorted = sorted(tp, key=lambda x: SEV_ORDER.get(x["final_severity"], 5))
    nv_sorted = sorted(nv, key=lambda x: SEV_ORDER.get(x["final_severity"], 5))

    target_url = raw.get("target", "") if raw else ""
    pdf = Report(display, target=target_url)
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # ── Title ──
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(30, 60, 120)
    pdf.cell(0, 12, _safe(f"Security Report: {display}"), align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(80, 80, 80)
    target_label = f"Target: {target_url}" if target_url else "Target: (see scan config)"
    pdf.cell(0, 7, _safe(target_label),
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7,
             f"Date: {datetime.now().strftime('%B %d, %Y')} | "
             "Methodology: AI-Powered DAST + Evidence Verification",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

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

    pdf.section("Scan Overview")
    for lbl, val in [
        ("Model:", display),
        ("Duration:", f"{dur_s/60:.1f} min ({dur_s:.0f}s)" if dur_s else "N/A"),
        ("LLM Cost:", f"${cost_usd:.4f}" if cost_usd is not None else "N/A"),
        ("Total Tokens:", f"{total_tokens:,}" if total_tokens else "N/A"),
        ("LLM Calls:", str(llm_calls) if llm_calls else "N/A"),
        ("Pages Crawled:", str(pages) if pages else "N/A"),
        ("Forms Found:", str(forms) if forms else "N/A"),
        ("API Endpoints:", str(apis) if apis else "N/A"),
        ("Tests Executed:", str(test_count)),
    ]:
        pdf.kv(lbl, val)
    pdf.ln(3)

    # ── Findings Summary ──
    pdf.section("Findings Summary")
    for lbl, val in [
        ("Total Findings:", str(total)),
        ("True Positives:", str(len(tp))),
        ("False Positives:", str(len(fp))),
        ("Needs Verify:", str(len(nv))),
        ("Not a Finding:", str(len(na))),
        ("Precision:", f"{len(tp)/(len(tp)+len(fp))*100:.0f}%"
         if (len(tp) + len(fp)) else "N/A"),
    ]:
        pdf.kv(lbl, val)
    pdf.ln(2)

    # Severity breakdown for confirmed findings
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 6, "Confirmed by CVSS-based Severity:", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        cnt = len([f for f in tp if f["final_severity"] == sev])
        if cnt:
            pdf.set_fill_color(*SEV_COLORS[sev])
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(22, 6, _safe(sev), fill=True, align="C")
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(20, 6, f"  {cnt}")
            pdf.ln(7)

    # Pre-create internal link IDs for every finding (used in tables -> detail jump)
    tp_links = [pdf.add_link() for _ in tp_sorted]
    nv_links = [pdf.add_link() for _ in nv_sorted]
    fp_links = [pdf.add_link() for _ in fp]

    # ── Clickable Summary Table: Confirmed Vulnerabilities ──
    if tp_sorted:
        pdf.add_page()
        pdf.section("Findings Overview - Confirmed Vulnerabilities (click to jump)",
                     (20, 140, 60))
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 4, _safe(
            "Click any finding title (blue underline) to jump to full details, "
            "evidence, and reproduction steps."))
        pdf.ln(2)
        _render_summary_table(pdf, tp_sorted, tp_links)

    # ── Clickable Summary Table: Needs Verification ──
    if nv_sorted:
        pdf.add_page()
        pdf.section("Findings Overview - Needs Verification (click to jump)",
                     (200, 160, 20))
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 4, _safe(
            "These need manual testing with Burp Suite. "
            "Click any title to see test steps."))
        pdf.ln(2)
        _render_summary_table(pdf, nv_sorted, nv_links)

    # ── Clickable Summary Table: False Positives ──
    if fp:
        pdf.add_page()
        pdf.section("Findings Overview - False Positives (click to jump)",
                     (200, 40, 40))
        pdf.set_font("Helvetica", "I", 8)
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
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 5, _safe(
            "Confirmed real issues with CVE/CVSS scores. "
            "Severity is CVSS-based, not scanner-claimed.\n"
            "Yellow box = steps to reproduce. Blue box = developer fix."))
        pdf.ln(2)
        for i, f in enumerate(tp_sorted, 1):
            render(pdf, i, f, link_id=tp_links[i - 1])

    # ── Needs Verification ──
    if nv_sorted:
        pdf.add_page()
        pdf.section(f"Needs Verification - Details ({len(nv)})",
                     (200, 160, 20))
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 5, _safe(
            "Manual testing with Burp Suite needed. "
            "Yellow box has exact test steps."))
        pdf.ln(2)
        for i, f in enumerate(nv_sorted, 1):
            render(pdf, i, f, link_id=nv_links[i - 1])

    # ── False Positives ──
    if fp:
        pdf.add_page()
        pdf.section(f"False Positives - Details ({len(fp)})", (200, 40, 40))
        pdf.set_font("Helvetica", "I", 9)
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
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 5, _safe(f"  {i}. {f['title']}"),
                     new_x="LMARGIN", new_y="NEXT")

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"DAST_{slug}.pdf")
    pdf.output(out)
    return out, total, len(tp), len(fp), len(nv), len(na)


# ==========================================================================
# Main
# ==========================================================================

def main():
    global OUT_DIR

    parser = argparse.ArgumentParser(description="Generate DAST triage reports from scan results.")
    parser.add_argument("--file", help="Process a single result JSON file")
    parser.add_argument("--raw-dir", default=RAW_DIR, help="Directory with raw scan results")
    parser.add_argument("--out-dir", default=None, help="Output directory for PDF reports")
    args = parser.parse_args()

    if args.out_dir:
        OUT_DIR = args.out_dir

    print("=" * 70)
    print("DAST Report Generator - CVE/CVSS, Evidence-Based, Strict Classification")
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
        nv = len([c for c in classified if c["verdict"] == "NEEDS_VERIFICATION"])
        na = len([c for c in classified if c["verdict"] == "NOT_A_FINDING"])
        print(f"  {display}: {len(findings)} findings -> {tp} TP, {fp} FP, {nv} NV, {na} NA")

        result = gen_report(model_key, classified, raw)
        if result:
            path, total, tp_c, fp_c, nv_c, na_c = result
            print(f"  -> {path}")

    print(f"\n{'='*70}\nDone.")


if __name__ == "__main__":
    main()
