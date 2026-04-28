"""Regression tests: post-phase ``_RETRY_PROMPTS`` block in ``agent.py`` keeps key guidance.

The prompts live inside ``run_scan`` as literals (not importable). We slice the source
between ``_RETRY_PROMPTS = {`` and ``_PHASE_TO_PROMPT_KEY`` so each assertion is scoped
to the retry dictionary only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_AGENT_PATH = _REPO_ROOT / "scanners" / "ai_agent" / "agent.py"


@pytest.fixture(scope="module")
def retry_prompts_block() -> str:
    src = _AGENT_PATH.read_text(encoding="utf-8")
    start = src.index("_RETRY_PROMPTS = {")
    end = src.index("_PHASE_TO_PROMPT_KEY = {", start)
    return src[start:end]


def test_access_control_business_logic_surfaces(retry_prompts_block: str) -> None:
    ac = retry_prompts_block.split('"sqli":', 1)[0]
    assert "AUTHENTICATED BUSINESS-LOGIC SURFACE" in ac
    assert "/api/licenses/generate" in ac
    assert "/api/sessions" in ac
    assert "Cross-Tenant License Generation" in ac
    assert "STATE-MUTATION INVARIANTS" in ac


def test_sqli_order_by_and_date_export(retry_prompts_block: str) -> None:
    sq = retry_prompts_block.split('"sqli":', 1)[1].split('"xss":', 1)[0]
    assert "ORDER BY / GROUP BY / column-name injection" in sq
    assert "pg_sleep(3)" in sq
    assert "date_trunc" in sq.lower()
    assert "POST /api/export" in sq or "/api/export" in sq
    assert "PARAMETER-NAME PERMUTATION" in sq


def test_injection_ssti_deser_verbose(retry_prompts_block: str) -> None:
    inj = retry_prompts_block.split('"injection":', 1)[1].split('"ssrf":', 1)[0]
    assert "PER-ENGINE SSTI PAYLOAD SWEEP" in inj
    assert "{{7*7}}" in inj
    assert "application/x-yaml" in inj or "application/yaml" in inj
    assert "VERBOSE-ERROR / STACK-TRACE HARNESS" in inj
    assert "BinaryFormatter" in inj or "pickle" in inj.lower()


def test_ssrf_and_file_upload_keys_present(retry_prompts_block: str) -> None:
    assert '"ssrf":' in retry_prompts_block
    assert '"file_upload":' in retry_prompts_block
    assert "169.254.169.254" in retry_prompts_block
