"""Browser-based LLM chatbot bridge.

Provides two capabilities:
1. ``send_chat_message(page, prompt)`` -- type a prompt into any detected
   chatbot UI, submit it, and return the chatbot's response text.
2. ``run_bridge_server(page, ...)`` -- spin up a local HTTP server that
   translates REST POST requests into browser chatbot interactions, so
   external tools like Garak can test chatbots that require auth.

Works generically across custom chat UIs, known widgets (Intercom, Drift,
Zendesk, etc.), and standard textarea+button patterns.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any

logger = logging.getLogger(__name__)

_SEND_BUTTON_SELECTORS = [
    "button[aria-label*='send' i]",
    "button[aria-label*='Send' i]",
    "button[data-testid*='send' i]",
    "button[class*='send' i]",
    "button[type='submit']",
    "[role='button'][aria-label*='send' i]",
]

_MESSAGE_SELECTORS = [
    "[class*='message' i]",
    "[class*='Message' i]",
    "[data-testid*='message' i]",
    "[class*='chat-bubble' i]",
    "[class*='chatBubble' i]",
    "[class*='response' i]",
    "[class*='reply' i]",
    "[class*='bot-message' i]",
    "[class*='assistant' i]",
    "[role='log'] > *",
]

_CHAT_INPUT_SELECTORS = [
    "textarea[class*='chat' i]",
    "textarea[aria-label*='chat' i]",
    "textarea[aria-label*='message' i]",
    "textarea[placeholder*='message' i]",
    "textarea[placeholder*='ask' i]",
    "textarea[placeholder*='type' i]",
    "input[type='text'][class*='chat' i]",
    "input[type='text'][aria-label*='message' i]",
    "input[type='text'][placeholder*='message' i]",
    "[contenteditable='true'][class*='chat' i]",
    "[contenteditable='true'][aria-label*='message' i]",
    "[contenteditable='true'][role='textbox']",
    "textarea",
    "input[type='text']",
    "[contenteditable='true']",
]

_CHAT_URL_KEYWORDS = [
    "chat", "message", "send", "agent", "ask", "converse",
    "completions", "generate", "neoclaw",
]
_CHAT_URL_EXCLUDE = [
    "status", "health", "events", "cron", "scheduler", "config",
    "refresh", "files/list", "query", "schema", "client-events",
    "invoke", "jobs",
]


async def _find_chat_container(ctx, input_el):
    """Walk up from the chat input to find the scrollable message area."""
    try:
        container = await input_el.evaluate_handle("""el => {
            let cur = el.parentElement;
            for (let i = 0; i < 15; i++) {
                if (!cur) break;
                const s = window.getComputedStyle(cur);
                const scrollable = (cur.scrollHeight > cur.clientHeight + 20) ||
                    s.overflowY === 'auto' || s.overflowY === 'scroll' ||
                    s.overflow === 'auto' || s.overflow === 'scroll';
                if (scrollable && cur.clientHeight > 100) return cur;
                cur = cur.parentElement;
            }
            // fallback: 3 levels up from input
            return el.parentElement?.parentElement?.parentElement || el.parentElement;
        }""")
        return container
    except Exception:
        return None


async def _get_container_text(container):
    """Get the visible text content from a container element."""
    if not container:
        return ""
    try:
        return await container.evaluate("el => el.innerText || ''")
    except Exception:
        return ""


_WIDGET_IFRAME_SELECTORS = {
    "intercom": "iframe[name='intercom-messenger-frame']",
    "drift": "#drift-frame-controller iframe",
    "zendesk": "iframe#webWidget",
    "tidio": "#tidio-chat-iframe",
    "hubspot": "#hubspot-messages-iframe-container iframe",
    "freshchat": "#fc_frame iframe",
    "crisp": "#crisp-chatbox iframe",
}


async def _find_chat_input(ctx, chat_input_selector=None):
    """Locate the chat input element. Tries pre-detected selector first,
    then falls back to heuristic search."""
    if chat_input_selector:
        try:
            el = await ctx.query_selector(chat_input_selector)
            if el and await el.is_visible():
                return el, chat_input_selector
        except Exception:
            pass

    for sel in _CHAT_INPUT_SELECTORS:
        try:
            el = await ctx.query_selector(sel)
            if el and await el.is_visible():
                return el, sel
        except Exception:
            continue
    return None, None


async def _find_send_button(ctx):
    """Find a send/submit button near the chat input."""
    for sel in _SEND_BUTTON_SELECTORS:
        try:
            el = await ctx.query_selector(sel)
            if el and await el.is_visible():
                return el
        except Exception:
            continue
    return None


async def _count_messages(ctx):
    """Count visible message elements in the chat area."""
    for sel in _MESSAGE_SELECTORS:
        try:
            els = await ctx.query_selector_all(sel)
            count = 0
            for el in els:
                try:
                    if await el.is_visible():
                        count += 1
                except Exception:
                    pass
            if count >= 1:
                return count
        except Exception:
            continue
    return 0


async def _get_last_message_text(ctx, min_index=0):
    """Extract text from the last message element after min_index."""
    for sel in _MESSAGE_SELECTORS:
        try:
            els = await ctx.query_selector_all(sel)
            visible = []
            for el in els:
                try:
                    if await el.is_visible():
                        visible.append(el)
                except Exception:
                    pass
            if len(visible) > min_index:
                last = visible[-1]
                text = await last.inner_text()
                if text and text.strip():
                    return text.strip()
        except Exception:
            continue
    return ""


async def _enter_iframe_if_widget(page, widget_type):
    """If chatbot is inside a known widget iframe, return the frame."""
    if not widget_type or widget_type in ("none", "custom"):
        return page
    iframe_sel = _WIDGET_IFRAME_SELECTORS.get(widget_type)
    if not iframe_sel:
        return page
    try:
        iframe_el = await page.query_selector(iframe_sel)
        if iframe_el:
            frame = await iframe_el.content_frame()
            if frame:
                logger.info("Entered %s widget iframe", widget_type)
                return frame
    except Exception as e:
        logger.debug("Failed to enter %s iframe: %s", widget_type, e)
    return page


def _parse_network_response(body, prompt):
    """Extract chatbot response text from a captured network response.
    Handles JSON, SSE streams, and plain text."""
    if "event:" in body or "data: {" in body:
        parts = []
        for line in body.split("\n"):
            if not line.startswith("data: "):
                continue
            try:
                d = json.loads(line[6:])
                msg = d.get("message", {})
                if isinstance(msg, dict) and msg.get("role") == "user":
                    continue
                c = msg.get("content", "") if isinstance(msg, dict) else ""
                if isinstance(c, list):
                    for item in c:
                        if isinstance(item, dict) and item.get("type") == "text":
                            t = item.get("text", "").strip()
                            if t:
                                parts.append(t)
                elif isinstance(c, str) and c.strip():
                    parts.append(c.strip())
            except Exception:
                continue
        if parts:
            return " ".join(parts)

    try:
        d = json.loads(body)
        for key in ("response", "message", "answer", "text",
                     "content", "reply", "output"):
            if key in d:
                val = d[key]
                if isinstance(val, str) and val.strip() and val.strip() != prompt:
                    return val.strip()
                if isinstance(val, dict):
                    for sub in ("content", "text", "message"):
                        if sub in val and isinstance(val[sub], str):
                            return val[sub].strip()
        choices = d.get("choices", [])
        if choices and isinstance(choices[0], dict):
            msg = choices[0].get("message", {})
            if isinstance(msg, dict) and msg.get("content"):
                return msg["content"].strip()
    except (json.JSONDecodeError, KeyError, IndexError):
        pass

    clean = body.strip()
    if clean and len(clean) < 5000 and clean != prompt:
        return clean
    return ""


async def send_chat_message(
    page,
    prompt,
    *,
    chat_input_selector=None,
    widget_type=None,
    timeout=30.0,
    target_url=None,
):
    """Type a prompt into the chatbot UI and return the response.

    Returns dict with keys: success, response, method, elapsed_ms.
    """
    start = time.monotonic()
    ctx = await _enter_iframe_if_widget(page, widget_type)

    input_el, used_sel = await _find_chat_input(ctx, chat_input_selector)
    if not input_el:
        for _retry in range(3):
            await asyncio.sleep(1.5)
            try:
                for _chat_btn_sel in [
                    "button:has-text('Chat')", "a:has-text('Chat')",
                    "[class*='chat' i]", "button:has-text('Superparent')",
                    "a:has-text('Superparent')",
                ]:
                    btn = await page.query_selector(_chat_btn_sel)
                    if btn and await btn.is_visible():
                        await btn.click()
                        await asyncio.sleep(2)
                        break
            except Exception:
                pass
            ctx = await _enter_iframe_if_widget(page, widget_type)
            input_el, used_sel = await _find_chat_input(ctx, chat_input_selector)
            if input_el:
                break
    if not input_el:
        logger.warning("No chat input found (selector=%s, url=%s)", chat_input_selector, page.url)
        print(f"  [BRIDGE] No chat input found on {page.url} (selector={chat_input_selector})")
        return {
            "success": False,
            "response": "",
            "method": "no_input_found",
            "elapsed_ms": int((time.monotonic() - start) * 1000),
        }

    chat_container = await _find_chat_container(ctx, input_el)
    text_before = await _get_container_text(chat_container)
    msg_count_before = await _count_messages(ctx)

    _network_responses = []

    async def _capture(response):
        try:
            url = response.url.lower()
            if any(ex in url for ex in _CHAT_URL_EXCLUDE):
                return
            ct = response.headers.get("content-type", "")
            if response.request.method == "POST" and (
                "json" in ct or "event-stream" in ct or "text/plain" in ct
            ):
                if any(kw in url for kw in _CHAT_URL_KEYWORDS):
                    body = await response.text()
                    if body and len(body) > 5:
                        _network_responses.append(body)
        except Exception:
            pass

    page.on("response", _capture)

    try:
        try:
            await input_el.click()
            await asyncio.sleep(0.2)
            await page.keyboard.press("Control+A")
            await page.keyboard.press("Backspace")
            await asyncio.sleep(0.1)
        except Exception:
            pass

        await input_el.fill(prompt)
        await asyncio.sleep(0.3)
        await page.keyboard.press("Enter")
        await asyncio.sleep(0.5)

        input_val = ""
        try:
            input_val = await input_el.input_value()
        except Exception:
            pass
        if input_val and input_val.strip() == prompt.strip():
            send_btn = await _find_send_button(ctx)
            if send_btn:
                await send_btn.click()
                await asyncio.sleep(0.5)

        response_text = ""
        deadline = time.monotonic() + timeout
        method = "timeout"

        while time.monotonic() < deadline:
            await asyncio.sleep(1.5)

            # Strategy 1: container text diff (works for any chat UI)
            if chat_container:
                text_now = await _get_container_text(chat_container)
                if len(text_now) > len(text_before) + 5:
                    new_text = text_now[len(text_before):].strip()
                    if new_text and new_text != prompt and len(new_text) > 3:
                        await asyncio.sleep(2.0)
                        text_final = await _get_container_text(chat_container)
                        response_text = text_final[len(text_before):].strip()
                        if prompt in response_text:
                            after_prompt = response_text.split(prompt, 1)[-1].strip()
                            if after_prompt:
                                response_text = after_prompt
                        method = "container_diff"
                        break

            # Strategy 2: classic message element counting
            msg_count_now = await _count_messages(ctx)
            if msg_count_now > msg_count_before + 1:
                candidate = await _get_last_message_text(ctx, msg_count_before)
                if candidate and candidate != prompt:
                    await asyncio.sleep(2.0)
                    response_text = await _get_last_message_text(
                        ctx, msg_count_before)
                    method = "dom"
                    break
            if msg_count_now > msg_count_before:
                candidate = await _get_last_message_text(
                    ctx, max(0, msg_count_before - 1))
                if candidate and candidate != prompt:
                    await asyncio.sleep(2.0)
                    response_text = await _get_last_message_text(
                        ctx, max(0, msg_count_before - 1))
                    method = "dom"
                    break

        # Strategy 3: filtered network capture (chat URLs only)
        if not response_text and _network_responses:
            for nr in reversed(_network_responses):
                parsed = _parse_network_response(nr, prompt)
                if parsed:
                    response_text = parsed
                    method = "network"
                    break

        return {
            "success": bool(response_text),
            "response": response_text[:2000],
            "method": method,
            "elapsed_ms": int((time.monotonic() - start) * 1000),
        }
    finally:
        try:
            page.remove_listener("response", _capture)
        except Exception:
            pass


# -- Bridge HTTP Server for Garak ------------------------------------

def _find_free_port(start=9919, attempts=20):
    """Find an available TCP port starting from *start*."""
    import socket
    for p in range(start, start + attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", p))
                return p
        except OSError:
            continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def run_bridge_server(
    page,
    *,
    host="127.0.0.1",
    port=0,
    chat_input_selector=None,
    widget_type=None,
    target_url=None,
):
    """Start the bridge HTTP server. Returns (runner, endpoint_url).

    Garak POSTs a prompt to this server; the server types it into the
    browser chatbot and returns the chatbot's response as plain text.
    Port is auto-detected to avoid conflicts.
    """
    from aiohttp import web

    if port == 0:
        port = _find_free_port()

    _lock = asyncio.Lock()

    async def handle_post(request):
        try:
            body = await request.json()
        except Exception:
            body = {"prompt": await request.text()}

        prompt = (
            body.get("prompt")
            or body.get("message")
            or body.get("text")
            or body.get("input")
            or str(body)
        )
        if isinstance(prompt, list):
            prompt = prompt[0] if prompt else ""
        if isinstance(prompt, dict):
            prompt = (prompt.get("content", "")
                      or prompt.get("text", "")
                      or str(prompt))

        async with _lock:
            if target_url:
                current = page.url
                if target_url not in current:
                    try:
                        await page.goto(
                            target_url,
                            wait_until="domcontentloaded",
                            timeout=15000,
                        )
                        await asyncio.sleep(2)
                    except Exception:
                        pass

            result = await send_chat_message(
                page,
                str(prompt),
                chat_input_selector=chat_input_selector,
                widget_type=widget_type,
                timeout=30.0,
                target_url=target_url,
            )

        resp_text = result["response"] or "(no response)"
        print(f"  [BRIDGE] prompt={str(prompt)[:80]!r} -> method={result['method']} elapsed={result['elapsed_ms']}ms resp={resp_text[:120]!r}")
        return web.Response(
            text=json.dumps({"response": resp_text}),
            content_type="application/json",
        )

    async def handle_health(request):
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_post("/generate", handle_post)
    app.router.add_post("/chat", handle_post)
    app.router.add_post("/", handle_post)
    app.router.add_get("/health", handle_health)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    endpoint = f"http://{host}:{port}/generate"
    logger.info("Browser LLM bridge listening on %s", endpoint)
    print(f"  [BRIDGE] Browser LLM bridge started on {endpoint}")

    # Preflight: send a harmless test message to verify round-trip works.
    # If the chatbot doesn't respond, there's no point running 600+ probes.
    print("  [BRIDGE] Preflight: sending test message to verify chatbot responds...")
    preflight = await send_chat_message(
        page, "Hello",
        chat_input_selector=chat_input_selector,
        widget_type=widget_type,
        timeout=45.0,
        target_url=target_url,
    )
    pf_ok = preflight["success"] and preflight["method"] != "no_input_found"
    print(
        f"  [BRIDGE] Preflight result: success={preflight['success']} "
        f"method={preflight['method']} elapsed={preflight['elapsed_ms']}ms "
        f"resp={preflight['response'][:150]!r}"
    )
    if not pf_ok:
        print("  [BRIDGE] Preflight FAILED — chatbot not responding. Skipping browser bridge.")
        logger.warning("Bridge preflight failed: method=%s", preflight["method"])
        await runner.cleanup()
        return None, None
    print("  [BRIDGE] Preflight OK — chatbot is responding. Proceeding with probes.")

    return runner, endpoint
