"""Unit tests for JS library extraction in scanners.ai_agent.passive_recon.

Tests cover:

* Curated catalog hits across the **extended** library list (Bootstrap,
  Next.js, MUI, Monaco, CodeMirror, Crypto-JS, etc.).
* The Norton SSO bundle's actual content header (Bootstrap 3.3.7 +
  jQuery 3.5.1 + Sizzle 2.3.5) is correctly parsed.
* Heuristic extractor catches libraries NOT in the curated catalog
  (cdnjs path layouts, filename layouts, and bundle banners).
* Heuristic denylist filters out junk names (vendor.js, main-1.2.3.js, etc.).
"""
from __future__ import annotations

import pytest

from scanners.ai_agent.passive_recon import (
    _extract_js_library,
    _heuristic_extract_library,
)


# ── Catalog: existing entries (regression) ──────────────────────────────────

def test_catalog_jquery_url():
    res = _extract_js_library("https://cdn.example.com/jquery/3.5.1/jquery.min.js")
    assert ("jquery", "jquery", "npm", "3.5.1") in res


def test_catalog_jquery_filename():
    res = _extract_js_library("https://cdn.example.com/static/jquery-3.5.1.min.js")
    assert ("jquery", "jquery", "npm", "3.5.1") in res


def test_catalog_bootstrap_url():
    res = _extract_js_library("https://cdn.example.com/bootstrap/3.3.7/bootstrap.min.js")
    assert ("bootstrap", "bootstrap", "npm", "3.3.7") in res


def test_catalog_bootstrap_content():
    """Real Norton SSO bundle header — Bootstrap version inside content."""
    content = """/*
 jQuery JavaScript Library v3.5.1
 ...
 Bootstrap v3.3.7
 ...
*/"""
    res = _extract_js_library("https://login-int.norton.com/sso/x.js", content)
    libs = {(name, version) for name, _, _, version in res}
    assert ("bootstrap", "3.3.7") in libs
    assert ("jquery", "3.5.1") in libs


def test_catalog_angularjs_url():
    res = _extract_js_library("https://ajax.googleapis.com/ajax/libs/angularjs/1.7.9/angular.min.js")
    assert ("angular", "angular", "npm", "1.7.9") in res


# ── Catalog: extended entries (new) ─────────────────────────────────────────

def test_catalog_nextjs_path():
    res = _extract_js_library(
        "https://example.com/_next/static/chunks/next-14.2.3-abc.js",
    )
    libs = {(n, v) for n, _, _, v in res}
    assert ("next.js", "14.2.3") in libs


def test_catalog_mui_path():
    res = _extract_js_library(
        "https://cdn.jsdelivr.net/npm/@mui/material/5.15.10/index.js",
    )
    libs = {(n, v) for n, _, _, v in res}
    assert ("mui-material", "5.15.10") in libs


def test_catalog_monaco_filename():
    res = _extract_js_library(
        "https://cdn.example.com/vs/monaco-editor.0.45.0.min.js",
    )
    libs = {(n, v) for n, _, _, v in res}
    assert ("monaco-editor", "0.45.0") in libs


def test_catalog_codemirror_content():
    content = """// CodeMirror, copyright (c) by Marijn Haverbeke and others
CodeMirror.version = "5.65.16";"""
    res = _extract_js_library("https://example.com/cm.js", content)
    libs = {(n, v) for n, _, _, v in res}
    assert ("codemirror", "5.65.16") in libs


def test_catalog_chartjs_url():
    res = _extract_js_library("https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.min.js")
    libs = {(n, v) for n, _, _, v in res}
    assert ("chart.js", "4.4.1") in libs


def test_catalog_cryptojs_url():
    res = _extract_js_library(
        "https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"
    )
    libs = {(n, v) for n, _, _, v in res}
    assert ("crypto-js", "4.2.0") in libs


def test_catalog_swagger_ui():
    res = _extract_js_library(
        "https://cdn.jsdelivr.net/npm/swagger-ui/4.18.0/swagger-ui-bundle.js"
    )
    libs = {(n, v) for n, _, _, v in res}
    assert ("swagger-ui", "4.18.0") in libs


def test_catalog_pdfjs_url():
    res = _extract_js_library(
        "https://cdn.example.com/pdf.js/3.10.111/pdf.min.js"
    )
    libs = {(n, v) for n, _, _, v in res}
    assert ("pdfjs", "3.10.111") in libs


# ── Heuristic: URL-pattern fallback (libs NOT in catalog) ───────────────────

def test_heuristic_cdn_path_for_unknown_lib():
    """Path /<libname>/<version>/ — generic cdnjs/jsdelivr/unpkg layout."""
    res = _heuristic_extract_library(
        "https://cdn.example.com/some-unknown-lib/1.2.3/dist.min.js",
    )
    libs = {(n, v) for n, _, _, v in res}
    assert ("some-unknown-lib", "1.2.3") in libs


def test_heuristic_filename_for_unknown_lib():
    res = _heuristic_extract_library(
        "https://cdn.example.com/scripts/cool-widget-2.4.1.min.js",
    )
    libs = {(n, v) for n, _, _, v in res}
    assert ("cool-widget", "2.4.1") in libs


def test_heuristic_drops_denylisted_names():
    """vendor.js, main.js, runtime.js etc. should NOT be extracted as libs."""
    for url in [
        "https://example.com/static/vendor-1.2.3.js",
        "https://example.com/static/main-2.0.0.js",
        "https://example.com/static/runtime-7.1.0.js",
        "https://example.com/static/polyfills-3.4.5.js",
        "https://example.com/static/chunk-9.8.7.min.js",
    ]:
        res = _heuristic_extract_library(url)
        assert res == [], f"Expected empty for {url}, got {res}"


def test_heuristic_drops_too_short_or_numeric():
    res = _heuristic_extract_library("https://example.com/static/x-1.2.3.js")
    assert res == []
    res = _heuristic_extract_library("https://example.com/static/123-1.2.3.js")
    assert res == []


def test_heuristic_partial_semver_normalised():
    """X.Y is coerced to X.Y.0 (rare but happens with @v1.2 query strings)."""
    res = _heuristic_extract_library(
        "https://cdn.example.com/some-lib/2.5/main.js"
    )
    libs = {(n, v) for n, _, _, v in res}
    # With version "2.5" → normalized to "2.5.0"
    assert ("some-lib", "2.5.0") in libs


def test_heuristic_banner_extraction():
    content = """/*! my-cool-lib v1.4.7 (c) Copyright Owner — MIT License */
(function(global, factory) { /* ... */ })(this, function() { /* lib code */ });"""
    res = _heuristic_extract_library("", content)
    libs = {(n, v) for n, _, _, v in res}
    assert ("my-cool-lib", "1.4.7") in libs


def test_heuristic_pkg_json_meta_extraction():
    content = """!function(){"use strict";var a={"name":"super-utility","version":"3.2.1"};}();"""
    res = _heuristic_extract_library("", content)
    libs = {(n, v) for n, _, _, v in res}
    assert ("super-utility", "3.2.1") in libs


def test_heuristic_pkg_meta_skips_denylisted_in_metadata():
    """Bundles often have metadata like {"name":"main","version":"1.0.0"} —
    we must NOT extract those as libraries."""
    for bad in ["main", "vendor", "app", "bundle", "runtime", "index"]:
        content = f'{{"name":"{bad}","version":"1.0.0"}}'
        res = _heuristic_extract_library("", content)
        assert res == [], f"Expected empty for name={bad}, got {res}"


def test_heuristic_no_false_positive_on_random_text():
    """Random JS code should not produce library findings."""
    content = "function foo(x) { return x * 2; } var y = 1.2.3.4;"  # 1.2.3 inside but no banner
    res = _heuristic_extract_library("", content)
    assert res == []


def test_heuristic_dedups_within_call():
    """If URL + content both report the same (name, version), only emit once."""
    content = "/*! my-lib v1.2.3 */"
    res = _heuristic_extract_library(
        "https://cdn.example.com/my-lib/1.2.3/dist.js",
        content,
    )
    libs = [(n, v) for n, _, _, v in res]
    assert libs.count(("my-lib", "1.2.3")) == 1


# ── Norton SSO bundle integration test ──────────────────────────────────────

def test_norton_sso_header_detects_three_libraries():
    """Real Norton SSO bundle header (Bootstrap inside).

    This is the exact case Acunetix flagged but our scanner missed —
    making sure the catalog catches it deterministically."""
    norton_header = """/*
 jQuery JavaScript Library v3.5.1
 https://jquery.com/

 Includes Sizzle.js
 https://sizzlejs.com/

 Copyright JS Foundation and other contributors
 Released under the MIT license
 https://jquery.org/license

 Date: 2020-05-04T22:49Z
 Sizzle CSS Selector Engine v2.3.5
 https://sizzlejs.com/

 Copyright JS Foundation and other contributors
 Released under the MIT license
 https://js.foundation/

 Date: 2020-03-14
*/

/*! Bootstrap v3.3.7 (http://getbootstrap.com) */
"""
    res = _extract_js_library(
        "https://login-int.norton.com/sso/static/version/build/js/sso-default-2026-04-21-11-05-25.js",
        norton_header,
    )
    libs = {(name, version) for name, _, _, version in res}
    assert ("jquery", "3.5.1") in libs, f"jQuery 3.5.1 should be detected. Got: {libs}"
    assert ("bootstrap", "3.3.7") in libs, f"Bootstrap 3.3.7 should be detected. Got: {libs}"
