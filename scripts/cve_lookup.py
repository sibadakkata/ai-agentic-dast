"""Dynamic CVE/CVSS lookup via NVD API + OSV.dev API.
Replaces hand-typed CVE dictionaries with authoritative data.

Usage:
    from cve_lookup import lookup_cve, lookup_library_cves, get_cwe_info

    # Look up a specific CVE
    info = lookup_cve("CVE-2020-11022")
    # -> {"cve": "CVE-2020-11022", "cvss": 6.9, "vector": "CVSS:3.1/...", "severity": "MEDIUM", ...}

    # Look up all CVEs for a library version
    vulns = lookup_library_cves("bootstrap", "3.3.7")
    # -> [{"cve": "CVE-2019-8331", "cvss": 6.1, ...}, ...]

    # Get CWE info for generic weakness categories
    cwe = get_cwe_info("CWE-79")
    # -> {"id": "CWE-79", "name": "Cross-site Scripting", ...}

Caching: All API results are cached to disk (results/cache/nvd_cache.json, osv_cache.json)
so repeated runs don't make redundant API calls.
"""

import json
import os
import re
import time
import requests
import sys

sys.stdout.reconfigure(encoding="utf-8")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(BASE, "results", "cache")
os.makedirs(CACHE_DIR, exist_ok=True)

NVD_CACHE_FILE = os.path.join(CACHE_DIR, "nvd_cache.json")
OSV_CACHE_FILE = os.path.join(CACHE_DIR, "osv_cache.json")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/query"

NVD_RATE_LIMIT_DELAY = 6  # NVD allows 5 requests/30s without API key


def _load_cache(path):
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    return {}


def _save_cache(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


# ── NVD API: look up a specific CVE ID ──────────────────────────────

_nvd_cache = _load_cache(NVD_CACHE_FILE)
_nvd_last_call = 0


def lookup_cve(cve_id: str) -> dict:
    """Look up a single CVE from NVD. Returns dict with cvss, vector, severity, description."""
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        return {}

    if cve_id in _nvd_cache:
        return _nvd_cache[cve_id]

    global _nvd_last_call
    elapsed = time.time() - _nvd_last_call
    if elapsed < NVD_RATE_LIMIT_DELAY:
        time.sleep(NVD_RATE_LIMIT_DELAY - elapsed)

    try:
        r = requests.get(NVD_API, params={"cveId": cve_id}, timeout=20)
        _nvd_last_call = time.time()

        if r.status_code == 403:
            print(f"  [NVD] Rate limited on {cve_id}, waiting 30s...")
            time.sleep(30)
            r = requests.get(NVD_API, params={"cveId": cve_id}, timeout=20)
            _nvd_last_call = time.time()

        if r.status_code != 200:
            print(f"  [NVD] HTTP {r.status_code} for {cve_id}")
            return {}

        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            _nvd_cache[cve_id] = {}
            return {}

        cve_data = vulns[0]["cve"]
        metrics = cve_data.get("metrics", {})

        # Try CVSS 3.1 first, then 3.0, then 2.0
        cvss_score = None
        cvss_vector = ""
        cvss_severity = ""

        for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
            entries = metrics.get(metric_key, [])
            if entries:
                cd = entries[0]["cvssData"]
                cvss_score = cd["baseScore"]
                cvss_vector = cd["vectorString"]
                cvss_severity = cd.get("baseSeverity", "")
                break

        if cvss_score is None:
            v2 = metrics.get("cvssMetricV2", [])
            if v2:
                cvss_score = v2[0]["cvssData"]["baseScore"]
                cvss_vector = v2[0]["cvssData"]["vectorString"]
                cvss_severity = v2[0].get("baseSeverity", "")

        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d["value"]
                break

        cwes = []
        for wd in cve_data.get("weaknesses", []):
            for dd in wd.get("description", []):
                cwe_val = dd.get("value", "")
                if cwe_val.startswith("CWE-"):
                    cwes.append(cwe_val)

        result = {
            "cve": cve_id,
            "cvss": cvss_score,
            "vector": cvss_vector,
            "severity": cvss_severity,
            "description": desc[:300],
            "cwes": cwes,
            "source": "NVD",
        }

        _nvd_cache[cve_id] = result
        _save_cache(NVD_CACHE_FILE, _nvd_cache)
        return result

    except Exception as e:
        print(f"  [NVD] Error looking up {cve_id}: {e}")
        return {}


def lookup_cves_batch(cve_ids: list) -> dict:
    """Look up multiple CVEs. Returns {cve_id: info_dict}."""
    results = {}
    for cve_id in cve_ids:
        info = lookup_cve(cve_id)
        if info:
            results[cve_id] = info
    return results


# ── OSV API: look up CVEs for a library version ─────────────────────

_osv_cache = _load_cache(OSV_CACHE_FILE)


def lookup_library_cves(package_name: str, version: str,
                        ecosystem: str = "npm") -> list:
    """Query OSV.dev for known vulnerabilities in a specific library version.
    Returns list of dicts with cve, cvss, severity, summary."""
    cache_key = f"{ecosystem}:{package_name}:{version}"

    if cache_key in _osv_cache:
        return _osv_cache[cache_key]

    try:
        r = requests.post(OSV_API, json={
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version,
        }, timeout=15)

        if r.status_code != 200:
            print(f"  [OSV] HTTP {r.status_code} for {package_name}@{version}")
            return []

        vulns_raw = r.json().get("vulns", [])
        results = []

        for v in vulns_raw:
            cve_aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            severity_data = v.get("severity", [])

            cvss_score = None
            cvss_vector = ""
            for sd in severity_data:
                if sd.get("type") == "CVSS_V3":
                    cvss_vector = sd.get("score", "")
                    # Extract base score from vector
                    match = re.search(r"CVSS:3\.[01]/", cvss_vector)
                    if match:
                        # We'll get the real score from NVD for the CVE
                        pass

            entry = {
                "osv_id": v.get("id", ""),
                "cves": cve_aliases,
                "summary": v.get("summary", "")[:200],
                "details": v.get("details", "")[:300],
                "severity": v.get("database_specific", {}).get("severity", ""),
                "cvss_vector": cvss_vector,
                "published": v.get("published", ""),
                "source": "OSV",
            }
            results.append(entry)

        _osv_cache[cache_key] = results
        _save_cache(OSV_CACHE_FILE, _osv_cache)
        return results

    except Exception as e:
        print(f"  [OSV] Error querying {package_name}@{version}: {e}")
        return []


def enrich_library_finding(package_name: str, version: str,
                           ecosystem: str = "npm") -> dict:
    """Full lookup: OSV for CVE list, then NVD for CVSS scores.
    Returns consolidated info for a library finding."""
    osv_vulns = lookup_library_cves(package_name, version, ecosystem)

    if not osv_vulns:
        return {
            "has_cves": False,
            "cve_count": 0,
            "cves": [],
            "max_cvss": 0.0,
            "max_severity": "NONE",
            "summary": f"No known CVEs for {package_name}@{version} per OSV.dev",
        }

    all_cve_ids = []
    for v in osv_vulns:
        all_cve_ids.extend(v.get("cves", []))
    all_cve_ids = list(set(all_cve_ids))

    print(f"  [ENRICH] {package_name}@{version}: {len(osv_vulns)} OSV entries, "
          f"{len(all_cve_ids)} unique CVEs. Looking up CVSS from NVD...")

    enriched_cves = []
    max_cvss = 0.0
    max_severity = "NONE"

    for cve_id in all_cve_ids:
        nvd = lookup_cve(cve_id)
        score = nvd.get("cvss") or 0.0
        sev = nvd.get("severity", "")
        desc = nvd.get("description", "")
        cwes = nvd.get("cwes", [])

        osv_match = next((v for v in osv_vulns if cve_id in v.get("cves", [])), {})

        enriched_cves.append({
            "cve": cve_id,
            "cvss": score,
            "vector": nvd.get("vector", ""),
            "severity": sev,
            "description": desc,
            "cwes": cwes,
            "osv_summary": osv_match.get("summary", ""),
        })

        if score and score > max_cvss:
            max_cvss = score
            max_severity = sev

    enriched_cves.sort(key=lambda x: x.get("cvss", 0), reverse=True)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    if max_severity:
        final_sev = max_severity.capitalize()
    elif max_cvss >= 9.0:
        final_sev = "Critical"
    elif max_cvss >= 7.0:
        final_sev = "High"
    elif max_cvss >= 4.0:
        final_sev = "Medium"
    elif max_cvss > 0:
        final_sev = "Low"
    else:
        final_sev = "Info"

    cve_summary = "; ".join(
        f"{c['cve']} (CVSS {c['cvss']:.1f})" for c in enriched_cves[:5]
    )

    return {
        "has_cves": True,
        "cve_count": len(enriched_cves),
        "cves": enriched_cves,
        "max_cvss": max_cvss,
        "max_severity": final_sev,
        "cve_summary": cve_summary,
        "summary": f"{len(enriched_cves)} CVEs found for {package_name}@{version}. "
                   f"Highest: CVSS {max_cvss:.1f} ({final_sev}). {cve_summary}",
    }


# ── CWE database for generic findings (no CVE, just weakness class) ──

CWE_DB = {
    "CWE-16":   {"name": "Configuration", "desc": "Incorrect configuration of software."},
    "CWE-20":   {"name": "Improper Input Validation", "desc": "Input not properly validated."},
    "CWE-79":   {"name": "Cross-site Scripting (XSS)", "desc": "Improper neutralization of user input in web page output."},
    "CWE-200":  {"name": "Exposure of Sensitive Information", "desc": "Information exposure through error messages or other channels."},
    "CWE-208":  {"name": "Observable Timing Discrepancy", "desc": "Timing differences reveal information."},
    "CWE-209":  {"name": "Error Message Information Exposure", "desc": "Detailed errors reveal internal state."},
    "CWE-285":  {"name": "Improper Authorization", "desc": "Access control not properly enforced."},
    "CWE-287":  {"name": "Improper Authentication", "desc": "Authentication can be bypassed or is weak."},
    "CWE-307":  {"name": "Improper Restriction of Excessive Auth Attempts", "desc": "No rate limiting on authentication."},
    "CWE-319":  {"name": "Cleartext Transmission of Sensitive Info", "desc": "Data sent without encryption."},
    "CWE-352":  {"name": "Cross-Site Request Forgery (CSRF)", "desc": "Unauthorized commands from trusted user."},
    "CWE-353":  {"name": "Missing Support for Integrity Check", "desc": "No integrity verification (e.g. SRI)."},
    "CWE-384":  {"name": "Session Fixation", "desc": "Session ID not regenerated after auth."},
    "CWE-391":  {"name": "Unchecked Error Condition", "desc": "Error conditions not properly handled."},
    "CWE-489":  {"name": "Active Debug Code", "desc": "Debug/staging code left in production."},
    "CWE-601":  {"name": "URL Redirection to Untrusted Site", "desc": "Open redirect allows phishing."},
    "CWE-693":  {"name": "Protection Mechanism Failure", "desc": "Security mechanism missing or bypassed."},
    "CWE-770":  {"name": "Allocation of Resources Without Limits", "desc": "No limits on resource consumption."},
    "CWE-778":  {"name": "Insufficient Logging", "desc": "Security events not logged."},
    "CWE-829":  {"name": "Inclusion of Untrusted Functionality", "desc": "External code included without verification."},
    "CWE-942":  {"name": "Permissive Cross-domain Policy", "desc": "CORS or other cross-domain policy too permissive."},
    "CWE-1021": {"name": "Improper Restriction of Rendered UI Layers", "desc": "Clickjacking via iframe."},
    "CWE-1104": {"name": "Use of Unmaintained Third-Party Components", "desc": "Outdated libraries with known issues."},
    "CWE-1321": {"name": "Improperly Controlled Modification of Object Prototype", "desc": "Prototype pollution in JS."},
}


def get_cwe_info(cwe_id: str) -> dict:
    """Get CWE name and description."""
    return CWE_DB.get(cwe_id, {"name": cwe_id, "desc": ""})


# ── Helper: extract library name + version from finding evidence ──────

_LIB_PATTERNS = [
    (r"jquery[^\d]*?(\d+\.\d+\.\d+)", "jquery"),
    (r"bootstrap[^\d]*?v?(\d+\.\d+\.\d+)", "bootstrap"),
    (r"react[^\d]*?(\d+\.\d+\.\d+)", "react"),
    (r"angular[^\d]*?(\d+\.\d+\.\d+)", "angular"),
    (r"vue[^\d]*?(\d+\.\d+\.\d+)", "vue"),
    (r"lodash[^\d]*?(\d+\.\d+\.\d+)", "lodash"),
    (r"moment[^\d]*?(\d+\.\d+\.\d+)", "moment"),
    (r"axios[^\d]*?(\d+\.\d+\.\d+)", "axios"),
    (r"express[^\d]*?(\d+\.\d+\.\d+)", "express"),
]


def extract_libraries(finding: dict) -> list:
    """Extract library name + version from a finding's title and evidence.
    Returns list of (name, version) tuples."""
    text = (
        str(finding.get("title", "")) + " " +
        str(finding.get("evidence", ""))
    ).lower()

    found = []
    for pattern, lib_name in _LIB_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for ver in matches:
            if (lib_name, ver) not in found:
                found.append((lib_name, ver))

    return found


# ── Main: test all lookups ────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("CVE Lookup - Testing NVD + OSV Integration")
    print("=" * 60)

    print("\n1. NVD: CVE-2020-11022 (jQuery XSS)")
    info = lookup_cve("CVE-2020-11022")
    print(f"   CVSS: {info.get('cvss')}  Vector: {info.get('vector')}")
    print(f"   Severity: {info.get('severity')}  CWEs: {info.get('cwes')}")
    print(f"   Desc: {info.get('description', '')[:100]}")

    print("\n2. OSV: bootstrap@3.3.7")
    result = enrich_library_finding("bootstrap", "3.3.7")
    print(f"   CVE count: {result['cve_count']}")
    print(f"   Max CVSS: {result['max_cvss']} ({result['max_severity']})")
    for c in result["cves"][:3]:
        print(f"   {c['cve']}: CVSS {c['cvss']:.1f} - {c['description'][:80]}")

    print("\n3. OSV: jquery@3.5.1 (should be PATCHED)")
    result2 = enrich_library_finding("jquery", "3.5.1")
    print(f"   CVE count: {result2['cve_count']}")
    print(f"   Has CVEs: {result2['has_cves']}")
    print(f"   Summary: {result2['summary']}")

    print("\n4. OSV: react@16.14.0")
    result3 = enrich_library_finding("react", "16.14.0")
    print(f"   CVE count: {result3['cve_count']}")
    print(f"   Summary: {result3['summary']}")

    print("\n5. OSV: react-dom@16.14.0")
    result4 = enrich_library_finding("react-dom", "16.14.0")
    print(f"   CVE count: {result4['cve_count']}")
    print(f"   Summary: {result4['summary']}")

    print(f"\n{'='*60}")
    print("Cache saved. Subsequent runs will be instant for these lookups.")
