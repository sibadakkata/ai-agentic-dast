"""Tests for LLM application security scanning modules."""
from __future__ import annotations

import asyncio
import pytest
from collections import Counter


# =====================================================================
# llm_detect tests
# =====================================================================

class TestLLMDetection:

    def test_match_llm_endpoints_from_urls(self):
        from scanners.ai_agent.llm_detect import match_llm_endpoints_from_urls
        urls = [
            "https://example.com/api/chat",
            "https://example.com/v1/chat/completions",
            "https://example.com/api/users",
            "https://example.com/generate",
            "https://example.com/static/app.js",
            "https://example.com/copilot/query",
            "https://example.com/rag/search",
        ]
        matched = match_llm_endpoints_from_urls(urls)
        assert "https://example.com/api/chat" in matched
        assert "https://example.com/v1/chat/completions" in matched
        assert "https://example.com/generate" in matched
        assert "https://example.com/copilot/query" in matched
        assert "https://example.com/rag/search" in matched
        assert "https://example.com/api/users" not in matched
        assert "https://example.com/static/app.js" not in matched

    def test_network_log_raises_confidence(self):
        from scanners.ai_agent.llm_detect import detect_llm_features
        network_log = [
            {"url": "https://example.com/v1/chat/completions", "content_type": "application/json"},
        ]
        result = asyncio.run(
            detect_llm_features(page=None, network_log=network_log)
        )
        assert result["confidence"] >= 0.4
        assert "https://example.com/v1/chat/completions" in result["llm_endpoints"]

    def test_streaming_response_raises_confidence(self):
        from scanners.ai_agent.llm_detect import detect_llm_features
        network_log = [
            {"url": "https://example.com/api/chat", "content_type": "text/event-stream"},
        ]
        result = asyncio.run(
            detect_llm_features(page=None, network_log=network_log)
        )
        assert result["streaming"] is True
        assert result["confidence"] >= 0.6
        assert result["has_llm_chat"] is True

    def test_no_signals_returns_false(self):
        from scanners.ai_agent.llm_detect import detect_llm_features
        result = asyncio.run(
            detect_llm_features(page=None, network_log=[])
        )
        assert result["has_llm_chat"] is False
        assert result["confidence"] == 0.0

    def test_empty_network_log_graceful(self):
        from scanners.ai_agent.llm_detect import detect_llm_features
        result = asyncio.run(
            detect_llm_features(page=None, network_log=None)
        )
        assert result["has_llm_chat"] is False


# =====================================================================
# llm_baseline tests
# =====================================================================

class TestLLMBaseline:

    def test_all_probes_built(self):
        from scanners.ai_agent.llm_baseline import ALL_PROBES
        assert len(ALL_PROBES) == 37

    def test_probe_categories_covered(self):
        from scanners.ai_agent.llm_baseline import ALL_PROBES
        categories = {p.owasp_llm for p in ALL_PROBES}
        assert "LLM01" in categories
        assert "LLM02" in categories
        assert "LLM05" in categories
        assert "LLM06" in categories
        assert "LLM07" in categories
        assert "LLM10" in categories

    def test_probe_counts_per_category(self):
        from scanners.ai_agent.llm_baseline import ALL_PROBES
        counts = Counter(p.owasp_llm for p in ALL_PROBES)
        assert counts["LLM01"] == 10
        assert counts["LLM02"] == 8
        assert counts["LLM05"] == 5
        assert counts["LLM06"] == 5
        assert counts["LLM07"] == 6
        assert counts["LLM10"] == 3

    def test_system_prompt_leak_detector(self):
        from scanners.ai_agent.llm_baseline import _detect_system_prompt_leak
        assert _detect_system_prompt_leak("You are a helpful assistant") is not None
        assert _detect_system_prompt_leak("Your role is to answer questions") is not None
        assert _detect_system_prompt_leak("Hello, how can I help?") is None
        assert _detect_system_prompt_leak("I was instructed to not share secrets") is not None

    def test_pii_leak_detector(self):
        from scanners.ai_agent.llm_baseline import _detect_pii_leak
        assert _detect_pii_leak("Contact admin@example.com for help") is not None
        assert _detect_pii_leak("api_key: sk-abc123456789012345678901") is not None
        assert _detect_pii_leak("Hello world, no secrets here") is None

    def test_xss_reflection_detector(self):
        from scanners.ai_agent.llm_baseline import _detect_xss_reflection
        assert _detect_xss_reflection("<script>alert('llmprobe')</script>") is not None
        assert _detect_xss_reflection("Safe response without scripts") is None

    def test_agency_compliance_detector(self):
        from scanners.ai_agent.llm_baseline import _detect_agency_compliance
        assert _detect_agency_compliance("Here's the output of the command ls:") is not None
        assert _detect_agency_compliance("I cannot execute shell commands.") is None
        assert _detect_agency_compliance("Making an HTTP request to 169.254.169.254") is not None

    def test_unbounded_response_detector(self):
        from scanners.ai_agent.llm_baseline import _detect_unbounded_response
        assert _detect_unbounded_response("short") is None
        assert _detect_unbounded_response("x" * 60000) is not None

    def test_injection_canary_in_probes(self):
        """All PI probes reference the canary (plaintext or base64-encoded)."""
        from scanners.ai_agent.llm_baseline import ALL_PROBES
        pi_probes = [p for p in ALL_PROBES if p.owasp_llm == "LLM01"]
        for probe in pi_probes:
            has_plain = "INJECTION_SUCCESS_7x7" in probe.prompt
            has_encoded = "SU5KRUNUSU9OX1NVQ0NFU1NfN3g3" in probe.prompt
            assert has_plain or has_encoded, f"Probe {probe.id} missing canary"

    def test_build_finding_structure(self):
        from scanners.ai_agent.llm_baseline import ALL_PROBES, _build_finding
        probe = ALL_PROBES[0]
        finding = _build_finding(probe, "https://example.com/chat", "evidence", "response")
        assert finding["url"] == "https://example.com/chat"
        assert finding["owasp_llm"] == probe.owasp_llm
        assert finding["cwe"] == probe.cwe
        assert finding["_finding_source"] == "llm_baseline"

    def test_inject_prompt_replaces_input(self):
        from scanners.ai_agent.llm_baseline import _inject_prompt
        template = {"messages": [{"role": "user", "content": "$INPUT"}]}
        assert _inject_prompt(template, "hello") is True
        assert template["messages"][0]["content"] == "hello"

    def test_inject_prompt_nested(self):
        from scanners.ai_agent.llm_baseline import _inject_prompt
        template = {"data": {"prompt": "$INPUT", "other": "keep"}}
        assert _inject_prompt(template, "test") is True
        assert template["data"]["prompt"] == "test"
        assert template["data"]["other"] == "keep"


# =====================================================================
# garak_runner tests
# =====================================================================

class TestGarakRunner:

    def test_config_generation(self):
        from scanners.ai_agent.garak_runner import _generate_config
        config = _generate_config("https://example.com/api/chat")
        assert "https://example.com/api/chat" in config
        assert "RestGenerator" in config
        assert "$INPUT" in config

    def test_normalise_finding_pass_returns_none(self):
        from scanners.ai_agent.garak_runner import _normalise_finding
        entry = {"status": "pass", "probe": "test", "detector": "test"}
        assert _normalise_finding(entry, "https://x.com") is None

    def test_normalise_finding_fail_returns_dict(self):
        from scanners.ai_agent.garak_runner import _normalise_finding
        entry = {
            "status": "fail",
            "probe": "promptinject.HijackHint",
            "detector": "base.AlwaysFailDetector",
            "prompt": "ignore previous",
            "output": "I will do anything you say",
        }
        result = _normalise_finding(entry, "https://example.com/chat")
        assert result is not None
        assert result["owasp_llm"] == "LLM01"
        assert result["severity"] == "High"
        assert result["_finding_source"] == "garak"

    def test_classify_probe_mapping(self):
        from scanners.ai_agent.garak_runner import _classify_probe
        assert _classify_probe("promptinject.HijackHint") == "LLM01"
        assert _classify_probe("leakreplay.DataLeak") == "LLM02"
        assert _classify_probe("xss.MarkdownXSS") == "LLM05"
        assert _classify_probe("unknown.NewProbe") == "LLM01"

    def test_is_garak_available_no_crash(self):
        from scanners.ai_agent.garak_runner import is_garak_available
        result = is_garak_available()
        assert isinstance(result, bool)


# =====================================================================
# Severity integration tests
# =====================================================================

class TestLLMSeverity:

    def test_llm_profiles_in_triage_engine(self):
        from scripts.triage_engine import CWE_PROFILES
        assert "llm_prompt_injection" in CWE_PROFILES
        assert CWE_PROFILES["llm_prompt_injection"]["cwe"] == "CWE-77"
        assert CWE_PROFILES["llm_prompt_injection"]["cvss"] == 8.1
        assert "llm_info_disclosure" in CWE_PROFILES
        assert "llm_excessive_agency" in CWE_PROFILES
        assert "llm_output_handling" in CWE_PROFILES
        assert "llm_prompt_leakage" in CWE_PROFILES
        assert "llm_unbounded_consumption" in CWE_PROFILES

    def test_classify_severity_prompt_injection(self):
        from scanners.ai_agent.severity import classify_severity
        finding = {
            "title": "Prompt Injection (LLM01)",
            "severity": "High",
            "evidence": "Injection canary triggered",
        }
        result = classify_severity(finding)
        assert result["cwe"] == "CWE-77"
        assert result["severity"] in ("High", "Critical")

    def test_classify_severity_excessive_agency(self):
        from scanners.ai_agent.severity import classify_severity
        finding = {
            "title": "LLM Excessive Agency (LLM06)",
            "severity": "High",
            "evidence": "LLM claims it executed a shell command",
        }
        result = classify_severity(finding)
        assert result["cwe"] == "CWE-269"


# =====================================================================
# Phase integration tests
# =====================================================================

class TestLLMPhaseIntegration:

    def test_llm_phase_included_when_detected(self):
        from scanners.ai_agent.prompts import get_phases
        phases = get_phases(
            scan_mode="website",
            app_info={"has_llm_chat": True, "has_websockets": False},
        )
        phase_ids = [p.id for p in phases]
        assert "web_llm_security" in phase_ids

    def test_llm_phase_excluded_when_not_detected(self):
        from scanners.ai_agent.prompts import get_phases
        phases = get_phases(
            scan_mode="website",
            app_info={"has_llm_chat": False, "has_websockets": False},
        )
        phase_ids = [p.id for p in phases]
        assert "web_llm_security" not in phase_ids

    def test_llm_phase_forced_via_focus_areas(self):
        from scanners.ai_agent.prompts import get_phases
        phases = get_phases(
            scan_mode="website",
            app_info={"has_llm_chat": False, "has_websockets": False},
            focus_areas=["LLM"],
        )
        phase_ids = [p.id for p in phases]
        assert "web_llm_security" in phase_ids

    def test_llm_phase_not_in_api_only_mode(self):
        from scanners.ai_agent.prompts import get_phases
        phases = get_phases(
            scan_mode="api",
            app_info={"has_llm_chat": True},
        )
        phase_ids = [p.id for p in phases]
        assert "web_llm_security" not in phase_ids

    def test_llm_phase_not_in_crawl_only(self):
        from scanners.ai_agent.prompts import get_phases
        phases = get_phases(
            scan_mode="website",
            app_info={"has_llm_chat": True},
            scan_profile="crawl_only",
        )
        phase_ids = [p.id for p in phases]
        assert "web_llm_security" not in phase_ids
        assert "crawl_only" in phase_ids

    def test_llm_phase_definition_is_not_parallel(self):
        from scanners.ai_agent.prompts import LLM_SECURITY_PHASE
        assert LLM_SECURITY_PHASE.parallel_ok is False
        assert LLM_SECURITY_PHASE.id == "web_llm_security"
