"""Garak (NVIDIA) orchestration -- optional subprocess-based LLM probe battery.

Generates a temporary YAML config pointing at the target's chat endpoint,
runs ``python -m garak`` as a subprocess, parses the JSONL report, and
normalises hits into the scanner's standard finding dict format.

Garak is an **optional** dependency.  If it is not installed the runner
logs a warning and returns an empty list -- ``llm_baseline.py`` still
provides coverage with zero external dependencies.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 300  # 5 min
_DEFAULT_PROBE_TAGS = ["owasp:llm01", "owasp:llm02", "owasp:llm06", "owasp:llm07"]

# Mapping from Garak probe family prefixes to OWASP LLM categories
_PROBE_TO_OWASP: dict[str, str] = {
    "promptinject": "LLM01",
    "dan":          "LLM01",
    "gcg":          "LLM01",
    "encoding":     "LLM01",
    "jailbreak":    "LLM01",
    "leakreplay":   "LLM02",
    "knownbadsign": "LLM02",
    "lmrc":         "LLM02",
    "xss":          "LLM05",
    "tooluse":      "LLM06",
    "snowball":     "LLM09",
    "continuation": "LLM07",
}

_OWASP_SEVERITY: dict[str, str] = {
    "LLM01": "High",
    "LLM02": "High",
    "LLM05": "Medium",
    "LLM06": "High",
    "LLM07": "Medium",
    "LLM09": "Low",
    "LLM10": "Medium",
}

_OWASP_CWE: dict[str, str] = {
    "LLM01": "CWE-77",
    "LLM02": "CWE-200",
    "LLM05": "CWE-79",
    "LLM06": "CWE-269",
    "LLM07": "CWE-200",
    "LLM09": "CWE-1188",
    "LLM10": "CWE-400",
}


def is_garak_available() -> bool:
    """Check if Garak is installed and importable."""
    return shutil.which("garak") is not None or _try_import()


def _try_import() -> bool:
    try:
        import importlib
        importlib.import_module("garak")
        return True
    except ImportError:
        return False


def _generate_config(
    endpoint: str,
    request_template: dict | None = None,
    headers: dict | None = None,
    probe_tags: list[str] | None = None,
) -> str:
    """Generate a Garak YAML config string targeting a REST endpoint."""
    import yaml

    tags = probe_tags or _DEFAULT_PROBE_TAGS

    req_template = request_template or {
        "messages": [{"role": "user", "content": "$INPUT"}]
    }

    config: dict[str, Any] = {
        "plugins": {
            "generators": {
                "rest": {
                    "RestGenerator": {
                        "name": "target-llm",
                        "uri": endpoint,
                        "method": "post",
                        "headers": headers or {},
                        "req_template_json_object": req_template,
                        "response_json": True,
                        "response_json_field": "$.choices[0].message.content",
                        "request_timeout": 30,
                    }
                }
            }
        },
        "run": {
            "probe_tags": tags,
            "generations": 1,
        },
    }

    return yaml.dump(config, default_flow_style=False)


def _find_report_file(garak_runs_dir: str | Path) -> Path | None:
    """Find the most recent Garak .report.jsonl in the runs directory."""
    runs = Path(garak_runs_dir)
    if not runs.exists():
        return None
    reports = sorted(runs.glob("**/*.report.jsonl"), key=os.path.getmtime, reverse=True)
    return reports[0] if reports else None


def _classify_probe(probe_name: str) -> str:
    """Map a Garak probe module name to an OWASP LLM category."""
    probe_lower = probe_name.lower()
    for prefix, owasp in _PROBE_TO_OWASP.items():
        if prefix in probe_lower:
            return owasp
    return "LLM01"  # default to prompt injection


def _normalise_finding(
    entry: dict,
    endpoint: str,
) -> dict | None:
    """Convert a single Garak JSONL hit into the scanner's finding format."""
    status = entry.get("status", "")
    if status != "fail":
        return None

    probe = entry.get("probe", "unknown")
    detector = entry.get("detector", "unknown")
    owasp = _classify_probe(probe)

    prompt_text = entry.get("prompt", "")
    output_text = entry.get("output", "")
    if isinstance(prompt_text, list):
        prompt_text = " | ".join(str(p) for p in prompt_text)
    if isinstance(output_text, list):
        output_text = " | ".join(str(o) for o in output_text)

    probe_short = probe.rsplit(".", 1)[-1] if "." in probe else probe
    title = f"{probe_short} ({owasp})"

    return {
        "title": title,
        "severity": _OWASP_SEVERITY.get(owasp, "Medium"),
        "category": f"OWASP {owasp}",
        "owasp_category": owasp,
        "owasp_llm": owasp,
        "cwe": _OWASP_CWE.get(owasp, "CWE-77"),
        "url": endpoint,
        "parameter": "(chat prompt)",
        "payload": str(prompt_text)[:300],
        "evidence": (
            f"Garak probe {probe} (detector: {detector}) flagged a failure. "
            f"Response snippet: {str(output_text)[:300]}"
        ),
        "response_snippet": str(output_text)[:500],
        "remediation": f"Review {owasp} controls. See OWASP Top 10 for LLM Applications.",
        "phase": "LLM Security (Garak)",
        "tool": f"garak.{probe}",
        "_finding_source": "garak",
        "_garak_probe": probe,
        "_garak_detector": detector,
    }


async def run_garak(
    target_endpoint: str,
    request_template: dict | None = None,
    headers: dict | None = None,
    probe_tags: list[str] | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
    on_progress: Any | None = None,
) -> list[dict]:
    """Run Garak against an LLM endpoint and return normalised findings.

    Returns an empty list if Garak is not installed or the run fails.
    """
    _cb = on_progress or (lambda *a, **k: None)

    if not is_garak_available():
        logger.warning(
            "Garak is not installed -- skipping LLM probe battery. "
            "Install with: pip install garak"
        )
        _cb("garak_skip", {"reason": "not_installed"})
        return []

    findings: list[dict] = []
    tmpdir = tempfile.mkdtemp(prefix="garak_run_")

    try:
        config_yaml = _generate_config(
            target_endpoint, request_template, headers, probe_tags,
        )
        config_path = os.path.join(tmpdir, "garak_config.yaml")
        with open(config_path, "w") as f:
            f.write(config_yaml)

        logger.info("Starting Garak run against %s (timeout=%ds)", target_endpoint, timeout)
        _cb("garak_start", {"endpoint": target_endpoint, "timeout": timeout})

        env = os.environ.copy()
        env["GARAK_RUN_DIR"] = tmpdir

        python = sys.executable
        cmd = [python, "-m", "garak", "--config", config_path]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=tmpdir,
            env=env,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning("Garak timed out after %ds", timeout)
            _cb("garak_timeout", {"timeout": timeout})
            return []

        exit_code = proc.returncode
        if exit_code != 0:
            logger.warning(
                "Garak exited with code %d: %s",
                exit_code, (stderr or b"").decode(errors="replace")[:500],
            )

        # Parse results from JSONL report
        report = _find_report_file(tmpdir)
        if not report:
            home_garak = Path.home() / ".local" / "share" / "garak"
            report = _find_report_file(home_garak)

        if report and report.exists():
            _cb("garak_parsing", {"report": str(report)})
            with open(report, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        finding = _normalise_finding(entry, target_endpoint)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue

            logger.info("Garak produced %d findings from %s", len(findings), report)
        else:
            logger.warning("No Garak report file found in %s", tmpdir)

        _cb("garak_done", {"findings_count": len(findings)})

    except Exception as e:
        logger.exception("Garak runner failed: %s", e)
        _cb("garak_error", {"error": str(e)[:300]})
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass

    return findings
