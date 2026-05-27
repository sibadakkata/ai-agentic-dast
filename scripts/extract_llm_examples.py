#!/usr/bin/env python3
"""Extract 2 example findings per LLM test category for manual verification."""
import json, requests

# Find latest completed scan
r = requests.get("http://localhost:80/api/scans", timeout=10)
scans = r.json().get("items", [])
latest = None
for s in scans:
    if s.get("status") == "completed":
        latest = s
        break

if not latest:
    print("No completed scans found")
    exit()

sid = latest.get("id") or latest.get("scan_id")
print(f"Scan: {sid}")
print(f"Target: {latest.get('target', '')}")
print()

# Get full results (triaged)
r2 = requests.get(f"http://localhost:80/api/results/{sid}", timeout=30)
data = r2.json()
findings = data.get("triaged_findings", [])
print(f"Total triaged findings: {len(findings)}")

# Filter LLM-related findings
llm_findings = []
for f in findings:
    title = (f.get("title") or "").lower()
    owasp = (f.get("owasp_category") or "").lower()
    phase = (f.get("phase") or "").lower()
    det_label = (f.get("detection_label") or "").lower()
    if any(x in title for x in ["llm", "garak", "jailbreak", "prompt inject", "toxicity", "excessive agency", "data exfil"]):
        llm_findings.append(f)
    elif any(x in owasp for x in ["llm"]):
        llm_findings.append(f)
    elif "llm" in phase or "garak" in phase:
        llm_findings.append(f)
    elif "garak" in det_label or "llm" in det_label:
        llm_findings.append(f)

print(f"LLM-related findings: {len(llm_findings)}")
print()

# Group by OWASP LLM category
by_owasp = {}
for f in llm_findings:
    owasp = f.get("owasp_category") or "Other"
    if owasp not in by_owasp:
        by_owasp[owasp] = []
    if len(by_owasp[owasp]) < 2:
        by_owasp[owasp].append(f)

for owasp, examples in sorted(by_owasp.items()):
    print(f"{'='*70}")
    print(f"OWASP CATEGORY: {owasp}")
    print(f"{'='*70}")
    for i, f in enumerate(examples):
        print(f"\n  Example {i+1}:")
        print(f"    Title:      {f.get('title', '')}")
        print(f"    Severity:   {f.get('severity', '')} (AI said: {f.get('ai_severity', '')})")
        print(f"    Verdict:    {f.get('verdict', '')}")
        print(f"    Tier:       {f.get('exploitation_tier', '')}")
        print(f"    Label:      {f.get('detection_label', '')}")
        print(f"    URL:        {f.get('url', '')}")
        print(f"    Payload:    {(f.get('payload') or '')[:200]}")
        print(f"    Evidence:   {(f.get('evidence') or '')[:250]}")

        # Show exploit_evidence if available
        ee = f.get("exploit_evidence", "")
        if ee:
            print(f"    Exploit Evidence:")
            for line in ee.split("\n")[:6]:
                print(f"      {line[:200]}")

        # Show request/response
        rr = f.get("request_response") or []
        if rr:
            for rri, entry in enumerate(rr[:1]):
                req = entry.get("request", {})
                resp = entry.get("response", {})
                print(f"    Request:    POST {entry.get('url', '')}")
                print(f"    Req Body:   {(req.get('body') or '')[:200]}")
                print(f"    Response:   {(resp.get('body') or '')[:300]}")

        # Show triage narrative
        narr = f.get("triage_narrative", {})
        ai = narr.get("ai_tested", [])
        tri = narr.get("triage_validated", [])
        if ai:
            print(f"    Triage (AI tested):")
            items = ai if isinstance(ai, list) else ai.split("\n")
            for s in items[:4]:
                print(f"      {s.strip()[:150]}")
        if tri:
            print(f"    Triage (validated):")
            items = tri if isinstance(tri, list) else tri.split("\n")
            for s in items[:3]:
                print(f"      {s.strip()[:150]}")
    print()
