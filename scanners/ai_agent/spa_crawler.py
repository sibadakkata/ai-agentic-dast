"""SPA (Single-Page Application) crawler.

Classic link-following crawlers fail on Angular/React/Vue apps because:

  1. The initial HTML has no <a href> links - it's a JS shell.
  2. API calls fire via fetch()/XMLHttpRequest only when the user
     interacts (clicks a tab, opens a modal, navigates a route).
  3. Those XHRs frequently target sibling hosts (e.g. my-int.norton.com's
     SPA calls webapps-int.norton.com/api/...), which link-crawling never
     reaches.

This module attaches a network-level listener via Playwright, then
actively clicks non-destructive UI elements, harvesting every XHR/fetch
request the SPA emits. Cross-origin requests are captured regardless of
target host; whether to test them is controlled by the caller's
allow-list.

Micro-frontend (MFE) aware:
  - Shadow DOM: recursive traversal through shadowRoot so buttons inside
    web components (Angular Elements, Lit, Stencil) are clickable.
  - Cross-origin iframes: per-frame enumeration via page.frames(); each
    allowed frame gets its own scroll + click loop.
  - Lazy-loaded widgets: full-page scroll before enumeration forces
    IntersectionObserver-based mounts to fire.
  - Depth-2 interaction: after each top-level click, re-enumerate and
    click newly-appeared elements (modal buttons, expanded panels).

Safety-first:
  - Buttons whose text/aria-label looks destructive (logout, delete,
    deactivate, reset, etc.) are skipped.
  - Time budget + click cap are enforced hard.
  - Failures on individual clicks never abort the crawl.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from .api_import import APIEndpoint, STATIC_ASSET_EXTENSIONS

logger = logging.getLogger(__name__)


DESTRUCTIVE_PATTERN = re.compile(
    r"\b("
    r"log\s?out|sign\s?out|log\s?off|"
    r"delete|remove|deactivate|disable|"
    r"cancel|unsubscribe|purge|"
    r"reset|terminate|revoke|expire|"
    r"close\s+account|factory\s*reset"
    r")\b",
    re.IGNORECASE,
)

INTERESTING_RESOURCE_TYPES = frozenset({"xhr", "fetch", "document"})
IGNORED_RESOURCE_TYPES = frozenset({
    "image", "font", "stylesheet", "media", "manifest", "texttrack",
    "websocket", "eventsource",
})

CLICKABLE_SELECTORS = [
    "button:not([disabled])",
    "[role='button']:not([aria-disabled='true'])",
    "[role='tab']",
    "[role='menuitem']",
    "a[href='#']",
    "a[href^='javascript:']",
    "[data-testid]",
    "li[role='option']",
    ".btn, .button",
]


# Shadow-DOM-aware clickable enumerator. Descends into every element's
# shadowRoot (if any) so web-component widgets become visible.
_COLLECT_JS = r"""
(selectors) => {
    const results = [];
    const seen = new WeakSet();
    const seenRoots = new WeakSet();

    const isVisible = (n) => {
        try {
            const rect = n.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) return false;
            const style = (n.ownerDocument && n.ownerDocument.defaultView || window)
                .getComputedStyle(n);
            if (!style) return true;
            if (style.visibility === 'hidden' || style.display === 'none') return false;
        } catch (e) { return false; }
        return true;
    };

    const record = (n) => {
        if (seen.has(n)) return;
        seen.add(n);
        if (!isVisible(n)) return;
        const text = (n.textContent || '').trim().slice(0, 80);
        const aria = (n.getAttribute && (n.getAttribute('aria-label') || '') || '').trim().slice(0, 80);
        const tid = (n.getAttribute && n.getAttribute('data-testid')) || '';
        const role = (n.getAttribute && n.getAttribute('role')) || '';
        const tag = (n.tagName || '').toLowerCase();
        results.push({text, aria, tid, role, tag});
    };

    const walk = (root) => {
        if (!root || seenRoots.has(root)) return;
        seenRoots.add(root);
        for (const sel of selectors) {
            let nodes;
            try { nodes = root.querySelectorAll(sel); } catch (e) { continue; }
            for (const n of nodes) record(n);
        }
        // Descend into shadow roots of all descendants.
        let all;
        try { all = root.querySelectorAll('*'); } catch (e) { return; }
        for (const el of all) {
            if (el.shadowRoot) walk(el.shadowRoot);
        }
    };

    walk(document);
    return results;
}
"""


# Viewport-stepping scroll: triggers IntersectionObserver-based lazy
# mounts that only render when the widget scrolls into view.
_SCROLL_JS = r"""
async () => {
    const origY = window.scrollY;
    const h = Math.max(
        document.body ? document.body.scrollHeight : 0,
        document.documentElement ? document.documentElement.scrollHeight : 0
    );
    const step = Math.max(300, Math.floor(window.innerHeight * 0.75));
    for (let y = 0; y < h; y += step) {
        window.scrollTo(0, y);
        await new Promise(r => setTimeout(r, 200));
    }
    window.scrollTo(0, 0);
    await new Promise(r => setTimeout(r, 150));
    window.scrollTo(0, origY);
}
"""


class _RequestRecord:
    __slots__ = ("method", "url", "headers", "body", "resource_type", "timestamp")

    def __init__(self, method: str, url: str, headers: dict,
                 body, resource_type: str, ts: float) -> None:
        self.method = method.upper()
        self.url = url
        self.headers = headers
        self.body = body
        self.resource_type = resource_type
        self.timestamp = ts


def _is_static_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    for ext in STATIC_ASSET_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


def _host_allowed(host: str, allowed_hosts: set) -> bool:
    if not host:
        return False
    host = host.lower()
    if host in allowed_hosts:
        return True
    for allowed in allowed_hosts:
        if host.endswith("." + allowed) or allowed.endswith("." + host):
            return True
    return False


def _dedup_key(method: str, url: str) -> str:
    parsed = urlparse(url)
    return f"{method.upper()}|{parsed.scheme}://{parsed.netloc}|{parsed.path}"


def _element_key(el: dict) -> str:
    """Stable identifier used to detect newly-appeared elements on re-enumeration."""
    label = (el.get("text") or el.get("aria") or el.get("tid") or "").strip().lower()
    return f"{el.get('tag','')}|{el.get('role','')}|{label}"


def _record_to_endpoint(rec: _RequestRecord) -> APIEndpoint:
    parsed = urlparse(rec.url)
    path = parsed.path or "/"
    query_params: dict = {}
    if parsed.query:
        for k, v_list in parse_qs(parsed.query, keep_blank_values=True).items():
            query_params[k] = v_list[0] if v_list else ""

    content_type = ""
    for k, v in (rec.headers or {}).items():
        if k.lower() == "content-type":
            content_type = str(v).lower()
            break

    body_type = "raw"
    if rec.body:
        if "json" in content_type:
            body_type = "json"
        elif "x-www-form-urlencoded" in content_type:
            body_type = "form"
        elif "xml" in content_type:
            body_type = "xml"
        elif "graphql" in content_type:
            body_type = "graphql"

    auth_type = "none"
    auth_value = None
    for k, v in (rec.headers or {}).items():
        if k.lower() == "authorization" and isinstance(v, str):
            if v.lower().startswith("bearer "):
                auth_type = "bearer"
                auth_value = v[7:].strip()
            elif v.lower().startswith("basic "):
                auth_type = "basic"
                auth_value = v[6:].strip()
            break

    return APIEndpoint(
        method=rec.method,
        url=rec.url,
        path=path,
        headers=dict(rec.headers or {}),
        query_params=query_params,
        body=rec.body,
        body_type=body_type,
        auth_type=auth_type,
        auth_value=auth_value,
        tags=["spa-crawl", rec.resource_type],
        variables={},
        original_name=f"{rec.method} {path}",
    )


async def _scroll_context(ctx) -> None:
    """Trigger viewport-based lazy loading in a page or frame."""
    try:
        await ctx.evaluate(_SCROLL_JS)
    except Exception as e:
        logger.debug("Scroll trigger failed: %s", e)


async def _collect_clickables(ctx, limit: int) -> list:
    """Enumerate clickable elements in a page or frame, including shadow DOM."""
    try:
        elements = await ctx.evaluate(_COLLECT_JS, CLICKABLE_SELECTORS)
    except Exception as e:
        logger.debug("Failed to enumerate clickables: %s", e)
        return []

    collected = []
    seen_keys = set()
    for el in elements:
        label = (el.get("text") or el.get("aria") or el.get("tid") or "").strip()
        if not label:
            continue
        key = _element_key(el)
        if key in seen_keys:
            continue
        full_label = f"{el.get('text','')} {el.get('aria','')} {el.get('tid','')}"
        if DESTRUCTIVE_PATTERN.search(full_label):
            logger.debug("Skipping destructive element: %s", label[:40])
            continue
        seen_keys.add(key)
        collected.append({
            "label": label,
            "text": el.get("text", ""),
            "aria": el.get("aria", ""),
            "tid": el.get("tid", ""),
            "role": el.get("role", ""),
            "tag": el.get("tag", ""),
            "key": key,
        })
        if len(collected) >= limit:
            break
    return collected


async def _click_element(ctx, el: dict, timeout_ms: int = 2500) -> bool:
    """Click within a given context (page or frame)."""
    try:
        if el.get("tid"):
            loc = ctx.locator(f"[data-testid='{el['tid']}']").first
        elif el.get("aria"):
            loc = ctx.get_by_label(el["aria"], exact=False).first
        elif el.get("text"):
            loc = ctx.get_by_text(el["text"][:60], exact=False).first
        else:
            return False
        await loc.click(timeout=timeout_ms, no_wait_after=True)
        return True
    except Exception as e:
        logger.debug("Click failed on %s: %s", el.get("label", "?")[:30], e)
        return False


async def _settle(ctx, post_click_settle_s: float) -> None:
    """Wait for network quiescence and any post-click animations."""
    try:
        await ctx.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass
    await asyncio.sleep(post_click_settle_s)


async def _interact_context(
    ctx,
    ctx_label: str,
    clicked_keys: set,
    click_budget,  # mutable list [remaining]
    deadline: float,
    captured_ref,  # list we observe length of for delta logging
    oos_ref,       # list we observe length of for delta logging
    max_clicks_per_context: int,
    post_click_settle_s: float,
    recursion_depth: int = 2,
) -> int:
    """Run scroll + enumerate + click (with depth-2 recursion) inside one
    context (main page or frame). Returns number of clicks performed here.
    """
    if click_budget[0] <= 0 or time.time() >= deadline:
        return 0

    # Upgrade 3: scroll to trigger lazy-loaded widgets before enumerating.
    await _scroll_context(ctx)
    try:
        await ctx.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass
    await asyncio.sleep(0.5)

    # Upgrade 1: shadow-DOM-aware enumeration.
    clickables = await _collect_clickables(ctx, limit=max_clicks_per_context * 2)
    if not clickables:
        return 0

    print(f"  [SPA] [{ctx_label}] Found {len(clickables)} clickable candidates")
    local_clicks = 0

    for el in clickables:
        if click_budget[0] <= 0 or time.time() >= deadline:
            break
        if local_clicks >= max_clicks_per_context:
            break
        if el["key"] in clicked_keys:
            continue

        pre_in = len(captured_ref)
        pre_oos = len(oos_ref)

        if await _click_element(ctx, el):
            clicked_keys.add(el["key"])
            click_budget[0] -= 1
            local_clicks += 1
            await _settle(ctx, post_click_settle_s)

            new_in = len(captured_ref) - pre_in
            new_oos = len(oos_ref) - pre_oos
            if new_in or new_oos:
                print(f"    [SPA] [{ctx_label}] Click '{el['label'][:40]}' "
                      f"-> +{new_in} in-scope, +{new_oos} out-of-scope")

            # Upgrade 4: depth-2 recursion. After this click, a modal/panel
            # may have appeared with its own buttons. Re-enumerate and click
            # at most a few truly new elements.
            if recursion_depth > 1 and click_budget[0] > 0 and time.time() < deadline:
                try:
                    new_elements = await _collect_clickables(
                        ctx, limit=max_clicks_per_context,
                    )
                except Exception:
                    new_elements = []

                nested_budget = min(3, click_budget[0])
                nested_clicks = 0
                for ne in new_elements:
                    if nested_clicks >= nested_budget:
                        break
                    if ne["key"] in clicked_keys:
                        continue
                    if time.time() >= deadline:
                        break
                    pre_in2 = len(captured_ref)
                    pre_oos2 = len(oos_ref)
                    if await _click_element(ctx, ne):
                        clicked_keys.add(ne["key"])
                        click_budget[0] -= 1
                        local_clicks += 1
                        nested_clicks += 1
                        await _settle(ctx, post_click_settle_s)
                        new_in2 = len(captured_ref) - pre_in2
                        new_oos2 = len(oos_ref) - pre_oos2
                        if new_in2 or new_oos2:
                            print(f"      [SPA] [{ctx_label}] Nested '{ne['label'][:36]}' "
                                  f"-> +{new_in2} in-scope, +{new_oos2} out-of-scope")

    return local_clicks


_ROUTE_EXTRACT_JS = r"""() => {
    const routes = new Set();
    const addRoute = (path) => {
        if (!path || typeof path !== 'string') return;
        path = path.trim();
        if (path.startsWith('/') && !path.startsWith('//') &&
            path.length < 200 && !/\.(js|css|png|jpg|svg|ico|woff|map)$/i.test(path) &&
            !/[:*{]/.test(path)) {
            routes.add(path);
        }
    };

    // Next.js
    try {
        const nd = window.__NEXT_DATA__;
        if (nd && nd.props && nd.props.pageProps) {
            Object.keys(nd.page ? {[nd.page]: 1} : {}).forEach(addRoute);
        }
        if (nd && nd.buildManifest && nd.buildManifest.sortedPages) {
            nd.buildManifest.sortedPages.forEach(addRoute);
        }
        if (window.__BUILD_MANIFEST) {
            Object.keys(window.__BUILD_MANIFEST).forEach(addRoute);
        }
    } catch {}

    // Nuxt
    try {
        const nuxt = window.__NUXT__ || window.$nuxt;
        if (nuxt && nuxt.$options && nuxt.$options.router) {
            const r = nuxt.$options.router;
            (r.options && r.options.routes || []).forEach(rt => addRoute(rt.path));
        }
    } catch {}

    // Vue Router (standalone)
    try {
        const app = document.querySelector('#app');
        if (app && app.__vue_app__) {
            const router = app.__vue_app__.config.globalProperties.$router;
            if (router) {
                router.getRoutes().forEach(rt => addRoute(rt.path));
            }
        }
    } catch {}

    // Angular
    try {
        const ng = window.ng;
        if (ng) {
            const roots = document.querySelectorAll('[ng-version]');
            roots.forEach(root => {
                try {
                    const injector = ng.getComponent(root);
                    if (injector && injector.router) {
                        injector.router.config.forEach(rt => addRoute('/' + (rt.path || '')));
                    }
                } catch {}
            });
        }
    } catch {}

    // React Router (data in window.__remixManifest or inline script)
    try {
        if (window.__remixManifest && window.__remixManifest.routes) {
            Object.values(window.__remixManifest.routes).forEach(rt => addRoute(rt.path));
        }
    } catch {}

    // Generic: parse <a href> that look like SPA routes
    try {
        document.querySelectorAll('a[href^="/"]').forEach(a => {
            const h = a.getAttribute('href');
            if (h && !h.startsWith('//')) addRoute(h.split('?')[0].split('#')[0]);
        });
    } catch {}

    // Sidebar / nav links often have data-href or routerLink
    try {
        document.querySelectorAll('[routerLink], [data-href], [ng-reflect-router-link]').forEach(el => {
            const v = el.getAttribute('routerLink') ||
                      el.getAttribute('data-href') ||
                      el.getAttribute('ng-reflect-router-link') || '';
            addRoute(v);
        });
    } catch {}

    return [...routes];
}"""


async def _walk_spa_routes(
    page, target_url: str, allowed_hosts: set, deadline: float,
    captured_ref: list, seen_keys: set,
    on_progress,
) -> list[str]:
    """Extract SPA routes from framework globals and navigate to each.

    The existing network listener on the page captures XHRs fired by
    each route, expanding endpoint coverage without extra clicks.
    """
    try:
        routes = await page.evaluate(_ROUTE_EXTRACT_JS)
    except Exception as e:
        logger.debug("SPA route extraction failed: %s", e)
        return []

    if not routes:
        return []

    parsed_target = urlparse(target_url)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"
    visited: list[str] = []

    # Deduplicate against already-seen URLs
    existing_paths = set()
    for key in seen_keys:
        parts = key.split("|")
        if len(parts) >= 3:
            existing_paths.add(urlparse(parts[2]).path)

    routes = [r for r in routes if r not in existing_paths]
    routes = routes[:20]  # cap to avoid burning budget

    on_progress("spa_routes_found", {"count": len(routes)})
    print(f"  [SPA] Route walker found {len(routes)} candidate routes")

    for route in routes:
        if time.time() >= deadline:
            break
        full_url = base + route
        host = (urlparse(full_url).hostname or "").lower()
        if not _host_allowed(host, allowed_hosts):
            continue

        pre_count = len(captured_ref)
        try:
            await page.goto(full_url, wait_until="domcontentloaded", timeout=10000)
            await asyncio.sleep(1.5)
        except Exception as e:
            logger.debug("Route walk failed for %s: %s", route, e)
            continue

        new_captures = len(captured_ref) - pre_count
        visited.append(route)
        if new_captures:
            print(f"    [SPA] Route {route} -> +{new_captures} endpoints")

    return visited


async def run_spa_crawl(
    page,
    target_url: str,
    target_host: str,
    extra_domains=None,
    on_progress=None,
    on_out_of_scope=None,
    max_clicks: int = 40,
    time_budget_s: int = 240,
    post_click_settle_s: float = 1.5,
    max_clicks_per_frame: int = 15,
):
    """Actively interact with a SPA (including micro-frontends) to harvest
    API endpoints.

    Returns (endpoints, out_of_scope_records).
    """
    _progress = on_progress or (lambda *a, **k: None)
    _oos = on_out_of_scope or (lambda *a, **k: None)

    extra_domains = extra_domains or []
    allowed_hosts = {target_host.lower()}
    for d in extra_domains:
        if d:
            allowed_hosts.add(d.lower())

    captured = []
    seen_keys = set()
    oos_records = []
    oos_keys = set()

    def _on_request(request):
        try:
            url = request.url
            if not url or not url.startswith(("http://", "https://")):
                return
            rtype = request.resource_type
            if rtype in IGNORED_RESOURCE_TYPES:
                return
            if rtype not in INTERESTING_RESOURCE_TYPES:
                return
            if _is_static_asset(url):
                return
            method = request.method.upper()
            host = (urlparse(url).hostname or "").lower()
            clean_url = url.split("#", 1)[0]
            key = _dedup_key(method, clean_url)

            if _host_allowed(host, allowed_hosts):
                if key in seen_keys:
                    return
                seen_keys.add(key)
                try:
                    body = request.post_data
                except Exception:
                    body = None
                try:
                    headers = dict(request.headers or {})
                except Exception:
                    headers = {}
                captured.append(_RequestRecord(
                    method=method, url=clean_url, headers=headers,
                    body=body, resource_type=rtype, ts=time.time(),
                ))
            else:
                if key in oos_keys:
                    return
                oos_keys.add(key)
                oos_records.append({
                    "method": method, "url": clean_url, "host": host,
                    "resource_type": rtype, "context": "spa-crawl",
                })
                try:
                    _oos({
                        "method": method, "url": clean_url, "host": host,
                        "reason": "host not in scan scope",
                    })
                except Exception:
                    pass
        except Exception as e:
            logger.debug("SPA request listener error: %s", e)

    page.on("request", _on_request)
    t_start = time.time()
    deadline = t_start + time_budget_s
    click_budget = [max_clicks]      # mutable box shared across contexts
    clicked_keys: set = set()        # dedup across main page + frames + depths
    total_clicks = 0

    try:
        _progress("spa_landing", {"target": target_url})
        print(f"  [SPA] Landing capture on {target_url}")
        try:
            cur_host = urlparse(page.url or "").hostname
            if cur_host != target_host:
                await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_load_state("networkidle", timeout=15000)
        except Exception as e:
            logger.debug("SPA landing wait error: %s", e)
        await asyncio.sleep(2.0)
        landed = len(captured)
        print(f"  [SPA] Captured {landed} landing XHRs ({len(oos_records)} out-of-scope)")

        # Interact with main page first (shadow-DOM-aware + scroll + depth-2).
        main_clicks = await _interact_context(
            ctx=page,
            ctx_label="main",
            clicked_keys=clicked_keys,
            click_budget=click_budget,
            deadline=deadline,
            captured_ref=captured,
            oos_ref=oos_records,
            max_clicks_per_context=max_clicks_per_frame,
            post_click_settle_s=post_click_settle_s,
            recursion_depth=2,
        )
        total_clicks += main_clicks
        _progress("spa_main_done", {"clicks": main_clicks})

        # Upgrade 2: per-frame walk. Iterate cross-origin iframes (common in
        # micro-frontend architectures) and run the same flow inside each
        # allowed frame. Shared network listener on the page catches all
        # XHRs regardless of which frame fired them.
        try:
            frames = list(page.frames)
        except Exception:
            frames = []

        processed_frames = 0
        for frame in frames:
            if click_budget[0] <= 0 or time.time() >= deadline:
                break
            try:
                furl = frame.url or ""
            except Exception:
                continue
            if not furl.startswith(("http://", "https://")):
                continue
            # Skip main frame (already processed).
            try:
                if frame == page.main_frame:
                    continue
            except Exception:
                pass
            fhost = (urlparse(furl).hostname or "").lower()
            if not _host_allowed(fhost, allowed_hosts):
                logger.debug("Skipping out-of-scope frame: %s", fhost)
                continue

            processed_frames += 1
            label = f"frame:{fhost}"
            print(f"  [SPA] Entering frame {furl[:80]}")
            try:
                fc = await _interact_context(
                    ctx=frame,
                    ctx_label=label,
                    clicked_keys=clicked_keys,
                    click_budget=click_budget,
                    deadline=deadline,
                    captured_ref=captured,
                    oos_ref=oos_records,
                    max_clicks_per_context=max_clicks_per_frame,
                    post_click_settle_s=post_click_settle_s,
                    recursion_depth=2,
                )
                total_clicks += fc
            except Exception as e:
                logger.debug("Frame interaction failed for %s: %s", furl, e)

        if processed_frames:
            print(f"  [SPA] Processed {processed_frames} in-scope frames")

        # ── SPA route walker: extract routes from framework globals ──
        if time.time() < deadline and click_budget[0] > 0:
            route_urls = await _walk_spa_routes(
                page, target_url, allowed_hosts, deadline, captured, seen_keys,
                _progress,
            )
            if route_urls:
                print(f"  [SPA] Route walker visited {len(route_urls)} SPA routes")

        try:
            await page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        await asyncio.sleep(1.0)

    finally:
        try:
            page.remove_listener("request", _on_request)
        except Exception:
            pass

    endpoints = [_record_to_endpoint(r) for r in captured]
    elapsed = int(time.time() - t_start)
    print(f"  [SPA] Done in {elapsed}s: {len(endpoints)} in-scope endpoints, "
          f"{len(oos_records)} out-of-scope discoveries, {total_clicks} clicks")
    _progress("spa_done", {
        "elapsed_s": elapsed,
        "in_scope": len(endpoints),
        "out_of_scope": len(oos_records),
        "clicks": total_clicks,
    })
    return endpoints, oos_records
