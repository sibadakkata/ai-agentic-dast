"""Unit tests for scanners.ai_agent.js_registry.

Tests cover:
* Adding/deduping URLs across multiple source phases.
* Identity-key normalisation (cache-busted variants collapse).
* Non-JS URLs are silently dropped.
* Host-scope filtering (exact + sub-domain).
* Diagnostic stats.
"""
from __future__ import annotations

import pytest

from scanners.ai_agent.js_registry import JSAsset, JSUrlRegistry, _identity_key, _looks_like_js


# ── _looks_like_js ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("url, expected", [
    ("https://cdn.example.com/main.js", True),
    ("https://cdn.example.com/main.mjs", True),
    ("https://cdn.example.com/main.js?v=1.2.3", True),
    ("https://cdn.example.com/styles.css", False),
    ("https://cdn.example.com/image.png", False),
    ("https://cdn.example.com/", False),
    ("", False),
    (None, False),
    ("not-a-url", False),
])
def test_looks_like_js(url, expected):
    assert _looks_like_js(url) is expected


# ── _identity_key ──────────────────────────────────────────────────────────

def test_identity_key_collapses_query_strings():
    a = "https://cdn.example.com/main.js?v=1234"
    b = "https://cdn.example.com/main.js?build=abcd"
    assert _identity_key(a) == _identity_key(b) == "cdn.example.com/main.js"


def test_identity_key_distinct_paths():
    a = "https://cdn.example.com/a.js"
    b = "https://cdn.example.com/b.js"
    assert _identity_key(a) != _identity_key(b)


def test_identity_key_distinct_hosts():
    a = "https://a.example.com/main.js"
    b = "https://b.example.com/main.js"
    assert _identity_key(a) != _identity_key(b)


# ── Add / dedup ────────────────────────────────────────────────────────────

def test_add_first_returns_true_then_false():
    reg = JSUrlRegistry()
    assert reg.add("https://example.com/a.js", "auth") is True
    assert reg.add("https://example.com/a.js", "spa_crawl") is False
    assert len(reg) == 1


def test_add_collapses_cache_busted_variants():
    reg = JSUrlRegistry()
    reg.add("https://cdn.example.com/main.js?v=1", "auth")
    reg.add("https://cdn.example.com/main.js?v=2", "spa_crawl")
    reg.add("https://cdn.example.com/main.js?build=xyz", "llm_tool")
    assert len(reg) == 1
    # First observation wins for source_phase
    asset = reg.all_assets()[0]
    assert asset.source_phase == "auth"


def test_add_rejects_non_js():
    reg = JSUrlRegistry()
    assert reg.add("https://example.com/style.css", "auth") is False
    assert reg.add("https://example.com/image.png", "auth") is False
    assert reg.add("https://example.com/api/users", "auth") is False
    assert len(reg) == 0


def test_add_rejects_malformed():
    reg = JSUrlRegistry()
    assert reg.add("", "auth") is False
    assert reg.add("not-a-url", "auth") is False
    # Missing hostname
    assert reg.add("file:///local.js", "auth") is False
    assert len(reg) == 0


def test_add_many_returns_new_count():
    reg = JSUrlRegistry()
    urls = [
        "https://example.com/a.js",
        "https://example.com/b.js",
        "https://example.com/a.js?v=2",  # duplicate of a.js
        "https://example.com/styles.css",  # not JS
    ]
    added = reg.add_many(urls, "auth")
    assert added == 2
    assert len(reg) == 2


# ── Host filtering ─────────────────────────────────────────────────────────

def test_in_scope_urls_exact_host():
    reg = JSUrlRegistry()
    reg.add("https://app.example.com/main.js", "auth")
    reg.add("https://other.com/main.js", "auth")
    in_scope = reg.in_scope_urls(["app.example.com"])
    assert in_scope == ["https://app.example.com/main.js"]


def test_in_scope_urls_subdomain_match():
    reg = JSUrlRegistry()
    reg.add("https://login.example.com/sso.js", "auth")
    reg.add("https://app.example.com/main.js", "spa_crawl")
    reg.add("https://cdn.evil.com/x.js", "spa_crawl")
    in_scope = reg.in_scope_urls(["example.com"])
    assert sorted(in_scope) == sorted([
        "https://login.example.com/sso.js",
        "https://app.example.com/main.js",
    ])


def test_in_scope_urls_no_filter_returns_all():
    reg = JSUrlRegistry()
    reg.add("https://a.com/x.js", "auth")
    reg.add("https://b.com/y.js", "auth")
    assert sorted(reg.in_scope_urls([])) == sorted([
        "https://a.com/x.js",
        "https://b.com/y.js",
    ])


# ── Aggregations ──────────────────────────────────────────────────────────

def test_hosts_returns_unique_hosts():
    reg = JSUrlRegistry()
    reg.add("https://a.com/x.js", "auth")
    reg.add("https://a.com/y.js", "auth")
    reg.add("https://b.com/z.js", "auth")
    assert reg.hosts() == {"a.com", "b.com"}


def test_by_host_groups_correctly():
    reg = JSUrlRegistry()
    reg.add("https://a.com/x.js", "auth")
    reg.add("https://a.com/y.js", "auth")
    reg.add("https://b.com/z.js", "auth")
    grouped = reg.by_host()
    assert sorted(grouped["a.com"]) == ["https://a.com/x.js", "https://a.com/y.js"]
    assert grouped["b.com"] == ["https://b.com/z.js"]


def test_stats_reports_per_source_counts():
    reg = JSUrlRegistry()
    reg.add("https://a.com/x.js", "auth")
    reg.add("https://a.com/x.js", "spa_crawl")  # dup, but source still counted
    reg.add("https://a.com/y.js", "auth")
    s = reg.stats()
    assert s["unique_urls"] == 2
    assert s["unique_hosts"] == 1
    assert s["by_source"]["auth"] == 2
    assert s["by_source"]["spa_crawl"] == 1
