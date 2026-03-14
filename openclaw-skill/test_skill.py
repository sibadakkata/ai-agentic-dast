#!/usr/bin/env python3
"""
End-to-end test for the AI Agentic Scanner OpenClaw skill.

Simulates what the OpenClaw agent does when a user chats naturally.

Usage:
  python test_skill.py list                          # all scans
  python test_skill.py targets                       # unique targets scanned
  python test_skill.py models                        # models used per target
  python test_skill.py find --url norton              # scans matching a URL substring
  python test_skill.py find --model haiku            # scans using a specific model
  python test_skill.py find --url norton --model haiku  # combined filter
  python test_skill.py status <scan_id>              # single scan status
  python test_skill.py results <scan_id>             # findings from a scan
  python test_skill.py report <scan_id>              # generate PDF report
  python test_skill.py latest-report --url norton    # report for latest scan of a target
  python test_skill.py scan --url https://example.com --mode website
  python test_skill.py scan --url https://example.com --wait   # wait for completion
  python test_skill.py stop <scan_id>
"""

import argparse
import base64
import json
import os
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

SCANNER_URL = os.environ.get("SCANNER_URL", "http://18.117.143.222:8080")
SCANNER_USER = os.environ.get("SCANNER_USER", "dast-admin")
SCANNER_PASS = os.environ.get("SCANNER_PASS", "Dk9xMvP2wLz7nQr8")


def _auth_header():
    cred = base64.b64encode(f"{SCANNER_USER}:{SCANNER_PASS}".encode()).decode()
    return f"Basic {cred}"


def _api(method, path, body=None, retries=2, timeout=60):
    url = f"{SCANNER_URL}{path}"
    data = json.dumps(body).encode() if body else None
    for attempt in range(retries + 1):
        req = Request(url, data=data, method=method)
        req.add_header("Authorization", _auth_header())
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw.strip() else {}
        except HTTPError as e:
            print(f"  HTTP {e.code}: {e.read().decode()}")
            sys.exit(1)
        except (URLError, ConnectionResetError, OSError) as e:
            if attempt < retries:
                print(f"  Connection issue, retrying ({attempt+1}/{retries})...")
                time.sleep(2)
                continue
            print(f"  Connection error: {e}")
            print(f"  Is the scanner running at {SCANNER_URL}?")
            sys.exit(1)


def _get_scans():
    data = _api("GET", "/api/scans?per_page=100")
    if isinstance(data, dict) and "items" in data:
        return data["items"]
    return data


def _filter_scans(scans, url_filter=None, model_filter=None):
    result = scans
    if url_filter:
        kw = url_filter.lower()
        result = [s for s in result if kw in (s.get("target") or "").lower()]
    if model_filter:
        kw = model_filter.lower()
        result = [s for s in result if kw in (s.get("model") or "").lower()]
    return result


def _fmt_scan(s):
    sid = (s.get("id") or "")[:28]
    status = s.get("status", "?")
    target = (s.get("target") or "?")[:45]
    model = (s.get("model") or "?")[:30]
    mode = s.get("scan_mode") or "?"
    findings = s.get("findings_count") or 0
    cost = s.get("cost") or 0
    return (f"  {sid:28s}  [{status:10s}] {mode:7s}  {target:45s}\n"
            f"  {'':28s}   Model: {model:30s}  findings={findings}  cost=${cost:.4f}")


# ── Commands ──────────────────────────────────────────────


def cmd_list(_args):
    """List all scans."""
    scans = _get_scans()
    print(f"\n{'='*90}")
    print(f"  All Scans ({len(scans)} total)")
    print(f"{'='*90}")
    for s in scans:
        print(_fmt_scan(s))
    print()


def cmd_targets(_args):
    """Show unique targets that have been scanned."""
    scans = _get_scans()
    targets = {}
    for s in scans:
        t = s.get("target") or "?"
        if t not in targets:
            targets[t] = {"scans": 0, "models": set(), "statuses": set()}
        targets[t]["scans"] += 1
        targets[t]["models"].add(s.get("model") or "?")
        targets[t]["statuses"].add(s.get("status") or "?")

    print(f"\n{'='*80}")
    print(f"  Unique Targets ({len(targets)} targets, {len(scans)} total scans)")
    print(f"{'='*80}")
    for t, info in targets.items():
        print(f"\n  {t}")
        print(f"    Scans  : {info['scans']}")
        print(f"    Models : {', '.join(sorted(info['models']))}")
        print(f"    Status : {', '.join(sorted(info['statuses']))}")
    print()


def cmd_models(_args):
    """Show which models were used for each target."""
    scans = _get_scans()
    by_model = {}
    for s in scans:
        model = s.get("model") or "?"
        if model not in by_model:
            by_model[model] = []
        by_model[model].append(s)

    print(f"\n{'='*80}")
    print(f"  Models Used ({len(by_model)} models)")
    print(f"{'='*80}")
    for model, model_scans in by_model.items():
        targets = set(s.get("target") or "?" for s in model_scans)
        total_cost = sum(s.get("cost") or 0 for s in model_scans)
        total_findings = sum(s.get("findings_count") or 0 for s in model_scans)
        print(f"\n  {model}")
        print(f"    Scans    : {len(model_scans)}")
        print(f"    Targets  : {', '.join(sorted(targets))}")
        print(f"    Findings : {total_findings}")
        print(f"    Cost     : ${total_cost:.4f}")
    print()


def cmd_find(args):
    """Find scans by URL and/or model."""
    scans = _get_scans()
    filtered = _filter_scans(scans, args.url, args.model)

    label = []
    if args.url:
        label.append(f"url~'{args.url}'")
    if args.model:
        label.append(f"model~'{args.model}'")

    print(f"\n{'='*90}")
    print(f"  Scans matching {' AND '.join(label)} ({len(filtered)} of {len(scans)})")
    print(f"{'='*90}")
    for s in filtered:
        print(_fmt_scan(s))
    if not filtered:
        print("  (no matches)")
    print()


def cmd_latest_report(args):
    """Generate report for the latest scan matching URL/model filter."""
    scans = _get_scans()
    filtered = _filter_scans(scans, args.url, args.model)
    completed = [s for s in filtered if s.get("status") == "completed"]

    if not completed:
        print(f"\n  No completed scans found matching url~'{args.url or '*'}' model~'{args.model or '*'}'")
        return

    latest = completed[0]
    sid = latest["id"]
    print(f"\n  Latest match: {sid}")
    print(f"  Target: {latest.get('target')}")
    print(f"  Model : {latest.get('model')}")
    print(f"  Cost  : ${latest.get('cost') or 0:.4f}")

    print(f"\n  Generating PDF report...")
    rpt = _api("POST", f"/api/results/{sid}/report")
    report_url = rpt.get("report_url") or rpt.get("pdf") or ""
    if report_url:
        print(f"  Report: {SCANNER_URL}{report_url}\n")
    else:
        print(f"  Response: {rpt}\n")


def cmd_start(args):
    """Start a new scan."""
    print(f"\n{'='*60}")
    print(f"  AI Agentic Scanner - Start Scan")
    print(f"{'='*60}\n")

    print(f"[1] Testing connectivity to {SCANNER_URL}...")
    health = _api("GET", "/health")
    print(f"    Status: {health.get('status', 'unknown')}")

    print(f"\n[2] Starting {args.mode} scan on {args.url}...")
    scan = _api("POST", "/api/scan", {
        "target_url": args.url,
        "scan_mode": args.mode,
        "model": args.model,
    })
    scan_id = scan.get("scan_id") or scan.get("id") or "unknown"
    print(f"    Scan ID : {scan_id}")
    print(f"    Status  : {scan.get('status', 'unknown')}")

    if not args.wait:
        print(f"\n  Scan launched! Monitor with:")
        print(f"    python test_skill.py status {scan_id}")
        print(f"    python test_skill.py results {scan_id}")
        print(f"    python test_skill.py report {scan_id}")
        return

    print(f"\n[3] Polling progress (Ctrl+C to detach)...")
    last_log_len = 0
    while True:
        time.sleep(15)
        st = _api("GET", f"/api/scan/{scan_id}")
        status = st.get("status", "unknown")
        log = st.get("progress_log") or []

        for entry in log[last_log_len:]:
            ts = entry.get("timestamp", "")[:19]
            msg = entry.get("message", "")
            print(f"    [{ts}] {msg}")
        last_log_len = len(log)

        if status in ("completed", "error", "cancelled"):
            cost = st.get("cost") or 0
            dur = st.get("duration") or 0
            print(f"\n    Final: {status} | {dur}s | ${cost:.4f}")
            break

    print(f"\n[4] Fetching results...")
    results = _api("GET", f"/api/results/{scan_id}")
    findings = results.get("triaged_findings") or []
    tp = [f for f in findings if f.get("verdict") == "TRUE_POSITIVE"]
    fp = [f for f in findings if f.get("verdict") == "FALSE_POSITIVE"]
    nv = [f for f in findings if f.get("verdict") == "NEEDS_VERIFICATION"]

    print(f"\n    Total: {len(findings)} | TP: {len(tp)} | FP: {len(fp)} | NV: {len(nv)}")
    if findings:
        print(f"    Precision: {len(tp)*100/len(findings):.0f}%")

    for f in tp[:10]:
        sev = f.get("final_severity") or f.get("ai_severity") or "?"
        print(f"    [{sev:12s}] {f.get('title','')}")

    print(f"\n[5] Generating PDF report...")
    rpt = _api("POST", f"/api/results/{scan_id}/report")
    report_url = rpt.get("report_url") or rpt.get("pdf") or ""
    if report_url:
        print(f"    Report: {SCANNER_URL}{report_url}")

    print(f"\n{'='*60}\n")


def cmd_status(args):
    """Check scan status."""
    st = _api("GET", f"/api/scan/{args.scan_id}")
    target = st.get("target_url") or st.get("target") or "?"
    cost = st.get("cost") or 0
    dur = st.get("duration") or 0
    print(f"\n  Scan     : {args.scan_id}")
    print(f"  Target   : {target}")
    print(f"  Mode     : {st.get('scan_mode') or '?'}")
    print(f"  Model    : {st.get('model') or '?'}")
    print(f"  Status   : {st.get('status', '?')}")
    print(f"  Cost     : ${cost:.4f}")
    print(f"  Duration : {dur}s")
    phases = st.get("phases_completed") or []
    if phases:
        if isinstance(phases, int):
            print(f"  Phases   : {phases} completed")
        else:
            print(f"  Phases   : {', '.join(str(p) for p in phases)}")
    print()


def cmd_results(args):
    """Get scan findings."""
    results = _api("GET", f"/api/results/{args.scan_id}")
    findings = results.get("triaged_findings") or results.get("findings") or []
    ai_findings = results.get("ai_findings") or []
    meta = results.get("metadata") or {}
    sev_bd = results.get("severity_breakdown") or {}

    print(f"\n  {'='*60}")
    print(f"  RESULTS: {meta.get('target', args.scan_id)}")
    print(f"  {'='*60}")
    print(f"  AI findings (raw)  : {len(ai_findings)}")
    print(f"  Triaged findings   : {len(findings)}")
    if sev_bd:
        print(f"  Severity breakdown : {json.dumps(sev_bd)}")

    tp = [f for f in findings if f.get("verdict") == "TRUE_POSITIVE"]
    fp = [f for f in findings if f.get("verdict") == "FALSE_POSITIVE"]
    nv = [f for f in findings if f.get("verdict") == "NEEDS_VERIFICATION"]

    print(f"\n  True Positives   : {len(tp)}")
    print(f"  False Positives  : {len(fp)}")
    print(f"  Needs Verify     : {len(nv)}")
    if findings:
        print(f"  Precision        : {len(tp)*100/len(findings):.0f}%")

    if tp:
        print(f"\n  --- TRUE POSITIVES ---")
        for f in tp:
            sev = f.get("final_severity") or f.get("ai_severity") or "?"
            print(f"  [{sev:12s}] {f.get('title','')}")
            print(f"                URL: {f.get('url','')[:80]}")
            if f.get("reason"):
                print(f"                Reason: {f['reason'][:100]}")
            print()

    if nv:
        print(f"  --- NEEDS VERIFICATION ---")
        for f in nv:
            sev = f.get("final_severity") or f.get("ai_severity") or "?"
            print(f"  [{sev:12s}] {f.get('title','')}")
            print(f"                URL: {f.get('url','')[:80]}")
            print()

    if fp and len(fp) <= 15:
        print(f"  --- FALSE POSITIVES ({len(fp)}) ---")
        for f in fp:
            sev = f.get("final_severity") or f.get("ai_severity") or "?"
            print(f"  [{sev:12s}] {f.get('title','')} [FP]")
    elif fp:
        print(f"  --- FALSE POSITIVES: {len(fp)} (not shown) ---")
    print()


def cmd_report(args):
    """Generate PDF report."""
    rpt = _api("POST", f"/api/results/{args.scan_id}/report")
    report_url = rpt.get("report_url") or rpt.get("pdf") or ""
    if report_url:
        print(f"\n  Report: {SCANNER_URL}{report_url}\n")
    else:
        print(f"\n  Response: {rpt}\n")


def cmd_stop(args):
    """Stop a running scan."""
    resp = _api("POST", f"/api/scan/{args.scan_id}/stop")
    print(f"\n  Stop response: {resp}\n")


def main():
    parser = argparse.ArgumentParser(
        description="AI Agentic Scanner - OpenClaw Skill Test CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list                                   List all scans
  %(prog)s targets                                Show unique targets
  %(prog)s models                                 Show models used per target
  %(prog)s find --url norton                      Find scans for norton
  %(prog)s find --model haiku                     Find scans using Haiku
  %(prog)s find --url norton --model haiku        Combined filter
  %(prog)s latest-report --url norton             Report for latest norton scan
  %(prog)s latest-report --url norton --model ministral
  %(prog)s status <scan_id>                       Check scan status
  %(prog)s results <scan_id>                      Get findings
  %(prog)s report <scan_id>                       Generate PDF
  %(prog)s scan --url https://example.com         Start website scan
  %(prog)s scan --url https://api.example.com --mode api --wait
  %(prog)s stop <scan_id>                         Stop running scan
""")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="List all scans")
    sub.add_parser("targets", help="Show unique targets scanned")
    sub.add_parser("models", help="Show models used and their stats")

    p_find = sub.add_parser("find", help="Find scans by URL and/or model")
    p_find.add_argument("--url", help="Filter by target URL substring")
    p_find.add_argument("--model", help="Filter by model name substring")

    p_lr = sub.add_parser("latest-report", help="Report for latest scan matching filters")
    p_lr.add_argument("--url", help="Filter by target URL substring")
    p_lr.add_argument("--model", help="Filter by model name substring")

    p_scan = sub.add_parser("scan", help="Start a new scan")
    p_scan.add_argument("--url", required=True, help="Target URL")
    p_scan.add_argument("--mode", default="website",
                        choices=["website", "api", "both"])
    p_scan.add_argument("--model",
                        default="bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0")
    p_scan.add_argument("--wait", action="store_true",
                        help="Wait for completion and show results")

    p_status = sub.add_parser("status", help="Check scan status")
    p_status.add_argument("scan_id")

    p_results = sub.add_parser("results", help="Get scan findings")
    p_results.add_argument("scan_id")

    p_report = sub.add_parser("report", help="Generate PDF report")
    p_report.add_argument("scan_id")

    p_stop = sub.add_parser("stop", help="Stop a running scan")
    p_stop.add_argument("scan_id")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    cmds = {
        "list": cmd_list, "targets": cmd_targets, "models": cmd_models,
        "find": cmd_find, "latest-report": cmd_latest_report,
        "scan": cmd_start, "status": cmd_status, "results": cmd_results,
        "report": cmd_report, "stop": cmd_stop,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()
