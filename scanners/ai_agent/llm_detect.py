"""LLM application detection -- heuristic identification of chatbot/AI features.

Scans the live DOM, network log, and JS bundles to determine whether the
target application exposes an LLM-powered interface (chatbot, AI assistant,
RAG search, etc.).  Detection is entirely deterministic -- no LLM calls.

Signals are scored and summed; when the cumulative score exceeds the
confidence threshold the application is flagged for LLM-specific security
testing via ``llm_baseline`` and optionally ``garak_runner``.
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_CONFIDENCE_THRESHOLD = 0.6

# CSS selectors for chat-like DOM containers
_CHAT_CONTAINER_SELECTORS = [
    "[class*='chat']",
    "[class*='Chat']",
    "[id*='chat']",
    "[class*='messenger']",
    "[class*='chatbot']",
    "[class*='ai-assist']",
    "[class*='copilot']",
    "[data-testid*='chat']",
    "[aria-label*='chat']",
    "[aria-label*='Chat']",
    "[role='log']",
]

_WIDGET_FINGERPRINTS: dict[str, list[str]] = {
    "intercom":  ["#intercom-container", "iframe[name='intercom-messenger-frame']"],
    "drift":     ["#drift-widget", "#drift-frame-controller"],
    "zendesk":   ["iframe#webWidget", "[data-garden-id='modals.modal']"],
    "crisp":     ["#crisp-chatbox", ".crisp-client"],
    "tidio":     ["#tidio-chat", "#tidio-chat-iframe"],
    "hubspot":   ["#hubspot-messages-iframe-container"],
    "freshchat": ["#fc_frame", ".fc-widget-small"],
}

_LLM_ENDPOINT_PATTERNS: list[re.Pattern] = [
    re.compile(r"/v\d+/chat/completions", re.I),
    re.compile(r"/api/chat(?:/|$)", re.I),
    re.compile(r"/api/v\d+/chat", re.I),
    re.compile(r"/completions(?:/|$)", re.I),
    re.compile(r"/generate(?:/|$)", re.I),
    re.compile(r"/ask(?:/|$)", re.I),
    re.compile(r"/converse(?:/|$)", re.I),
    re.compile(r"/ai/(?:query|prompt|message)", re.I),
    re.compile(r"/copilot/", re.I),
    re.compile(r"/llm/", re.I),
    re.compile(r"/rag/", re.I),
    re.compile(r"/chat/message", re.I),
    re.compile(r"/chat/sessions", re.I),
    re.compile(r"/agent/sessions", re.I),
    re.compile(r"/neoclaw", re.I),
    re.compile(r"/neoclaw-agent/chat", re.I),
    re.compile(r"/tools/invoke", re.I),
]

_JS_SDK_FINGERPRINTS = [
    "openai", "anthropic", "langchain", "llamaindex",
    "llama_index", "bedrock-runtime", "cohere", "huggingface",
    "text-generation-inference", "ChatCompletionMessage",
    "streamingResponse", "EventSource",
]

# JS evaluated in the browser to detect chat UI patterns.
# The selector list is baked in to avoid template interpolation issues.
_DOM_DETECT_JS = """() => {
    const out = {
        hasChatContainer: false,
        hasChatInput: false,
        hasMessageList: false,
        chatInputSelector: null,
    };

    const chatSels = [
        "[class*='chat']", "[class*='Chat']", "[id*='chat']",
        "[class*='messenger']", "[class*='chatbot']",
        "[class*='ai-assist']", "[class*='copilot']",
        "[data-testid*='chat']", "[aria-label*='chat']",
        "[aria-label*='Chat']", "[role='log']"
    ];
    for (const sel of chatSels) {
        try { if (document.querySelector(sel)) { out.hasChatContainer = true; break; } } catch {}
    }

    const inputs = document.querySelectorAll(
        'textarea, input[type="text"], [contenteditable="true"]'
    );
    for (const inp of inputs) {
        const ctx = (inp.closest('[class*="chat"]') ||
                     inp.closest('[class*="Chat"]') ||
                     inp.closest('[class*="messenger"]') ||
                     inp.closest('[class*="copilot"]') ||
                     inp.closest('[role="log"]'));
        if (ctx) {
            out.hasChatInput = true;
            if (inp.id) out.chatInputSelector = '#' + inp.id;
            else if (inp.name) out.chatInputSelector = '[name="' + inp.name + '"]';
            else out.chatInputSelector = inp.tagName.toLowerCase();
            break;
        }
    }

    const msgs = document.querySelectorAll(
        '[class*="message"], [class*="Message"], ' +
        '[data-testid*="message"], [role="log"]'
    );
    if (msgs.length >= 2) out.hasMessageList = true;

    return out;
}"""

_JS_FINGERPRINT_SCRIPT = """() => {
    const scripts = [...document.querySelectorAll('script')];
    let text = '';
    for (const s of scripts) {
        if (s.textContent) text += s.textContent + '\\n';
    }
    return text.substring(0, 200000);
}"""


async def detect_llm_features(
    page: Any | None,
    http_client: Any | None = None,
    network_log: list[dict] | None = None,
) -> dict[str, Any]:
    """Detect LLM-powered features in the target application.

    Returns a dict with:
        has_llm_chat (bool):  True when confidence >= threshold
        confidence (float):   0.0-1.0 cumulative score
        llm_endpoints (list): discovered chat/LLM API URLs
        chat_input_selector (str|None): CSS selector for the chat input
        chat_widget_type (str): "custom"|"intercom"|"drift"|...
        streaming (bool):     uses SSE / text/event-stream
    """
    result: dict[str, Any] = {
        "has_llm_chat": False,
        "confidence": 0.0,
        "llm_endpoints": [],
        "chat_input_selector": None,
        "chat_widget_type": "none",
        "streaming": False,
    }
    score = 0.0

    # ---- 1. DOM-based chat UI detection --------------------------------
    if page is not None:
        try:
            dom_info = await page.evaluate(_DOM_DETECT_JS)

            if dom_info.get("hasChatContainer") or dom_info.get("hasChatInput"):
                score += 0.3
            if dom_info.get("hasMessageList"):
                score += 0.1
            if dom_info.get("chatInputSelector"):
                result["chat_input_selector"] = dom_info["chatInputSelector"]
        except Exception as e:
            logger.debug("LLM detect DOM evaluation failed: %s", e)

        # ---- 2. Known widget fingerprints ------------------------------
        for widget_name, selectors in _WIDGET_FINGERPRINTS.items():
            try:
                for sel in selectors:
                    el = await page.query_selector(sel)
                    if el:
                        result["chat_widget_type"] = widget_name
                        score += 0.5
                        break
                if result["chat_widget_type"] != "none":
                    break
            except Exception:
                continue

        # ---- 3. JS bundle fingerprints ---------------------------------
        try:
            js_content = await page.evaluate(_JS_FINGERPRINT_SCRIPT)
            if js_content:
                js_lower = js_content.lower()
                for fp in _JS_SDK_FINGERPRINTS:
                    if fp.lower() in js_lower:
                        score += 0.3
                        break
        except Exception as e:
            logger.debug("LLM detect JS fingerprint failed: %s", e)

    # ---- 4. Network log analysis ---------------------------------------
    llm_endpoints: list[str] = []
    has_streaming = False

    for entry in (network_log or []):
        url = entry.get("url", "")
        content_type = str(
            entry.get("content_type", "")
            or entry.get("response_content_type", "")
            or ""
        )

        for pat in _LLM_ENDPOINT_PATTERNS:
            if pat.search(url):
                if url not in llm_endpoints:
                    llm_endpoints.append(url)
                break

        if "text/event-stream" in content_type:
            has_streaming = True

    if llm_endpoints:
        score += 0.4
        result["llm_endpoints"] = llm_endpoints
    if has_streaming:
        score += 0.2
        result["streaming"] = True

    # ---- 5. Final confidence -------------------------------------------
    result["confidence"] = min(score, 1.0)
    result["has_llm_chat"] = score >= _CONFIDENCE_THRESHOLD

    if result["has_llm_chat"]:
        logger.info(
            "LLM features detected (confidence=%.2f): endpoints=%s, widget=%s",
            result["confidence"], llm_endpoints, result["chat_widget_type"],
        )
    else:
        logger.debug("No LLM features detected (confidence=%.2f)", result["confidence"])

    return result


def match_llm_endpoints_from_urls(urls: list[str]) -> list[str]:
    """Filter a list of URLs to those matching LLM endpoint patterns."""
    matched = []
    for url in urls:
        for pat in _LLM_ENDPOINT_PATTERNS:
            if pat.search(url):
                matched.append(url)
                break
    return matched
