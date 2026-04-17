"""Out-of-Band (OOB) callback manager for blind vulnerability detection.

Generates unique callback URLs and tracks which ones were triggered by
the target application. Used for blind SSRF, blind XXE, blind command
injection, and any vulnerability where the application makes an
outbound request without reflecting the result.

Two modes:
  1. Self-hosted: Uses the scanner's own FastAPI /oob/{token} endpoint
  2. External: Uses a configurable OOB_SERVER_URL (Interactsh, webhook.site, etc.)
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock

logger = logging.getLogger(__name__)


@dataclass
class OOBCallback:
    token: str
    source_ip: str
    method: str
    path: str
    headers: dict
    body: str
    timestamp: float


class OOBManager:
    """Per-scan OOB callback tracker."""

    def __init__(self, scanner_base_url: str | None = None):
        self._tokens: dict[str, dict] = {}
        self._callbacks: dict[str, list[OOBCallback]] = defaultdict(list)
        self._lock = Lock()

        external = os.environ.get("OOB_SERVER_URL", "").strip()
        if external:
            self._base_url = external.rstrip("/")
            self._mode = "external"
        elif scanner_base_url:
            self._base_url = scanner_base_url.rstrip("/")
            self._mode = "self-hosted"
        else:
            self._base_url = ""
            self._mode = "disabled"

    @property
    def enabled(self) -> bool:
        return bool(self._base_url)

    def generate_url(self, label: str = "", protocol: str = "http") -> dict:
        """Generate a unique OOB callback URL for use in blind payloads.

        Args:
            label: Optional label describing what this URL is testing
            protocol: 'http', 'https', or 'dns'

        Returns:
            dict with token, url, dns_hostname (if applicable)
        """
        if not self.enabled:
            return {"error": "OOB callbacks not configured. Set OOB_SERVER_URL or scanner_base_url."}

        token = uuid.uuid4().hex[:16]
        with self._lock:
            self._tokens[token] = {
                "label": label,
                "created_at": time.time(),
                "protocol": protocol,
            }

        if self._mode == "external":
            url = f"{self._base_url}/{token}"
        else:
            url = f"{self._base_url}/oob/{token}"

        result = {
            "token": token,
            "url": url,
            "label": label,
            "mode": self._mode,
        }

        parsed_host = self._base_url.split("://")[-1].split("/")[0].split(":")[0]
        if protocol == "dns" or protocol == "all":
            result["dns_hostname"] = f"{token}.{parsed_host}"

        return result

    def record_callback(self, token: str, source_ip: str, method: str,
                        path: str, headers: dict, body: str) -> bool:
        """Record an incoming OOB callback. Called by the FastAPI endpoint."""
        with self._lock:
            if token not in self._tokens:
                return False
            self._callbacks[token].append(OOBCallback(
                token=token,
                source_ip=source_ip,
                method=method,
                path=path,
                headers=headers,
                body=body[:2000],
                timestamp=time.time(),
            ))
        logger.info("OOB callback received for token %s from %s", token, source_ip)
        return True

    def check_callbacks(self, token: str | None = None) -> dict:
        """Check if any OOB callbacks have been received.

        If token is given, check that specific token.
        If token is None, check all tokens for this scan.
        """
        with self._lock:
            if token:
                cbs = self._callbacks.get(token, [])
                meta = self._tokens.get(token, {})
                return {
                    "token": token,
                    "label": meta.get("label", ""),
                    "triggered": len(cbs) > 0,
                    "callback_count": len(cbs),
                    "callbacks": [
                        {
                            "source_ip": cb.source_ip,
                            "method": cb.method,
                            "path": cb.path,
                            "timestamp": cb.timestamp,
                            "body_snippet": cb.body[:500],
                        }
                        for cb in cbs
                    ],
                }

            results = []
            for t, meta in self._tokens.items():
                cbs = self._callbacks.get(t, [])
                results.append({
                    "token": t,
                    "label": meta.get("label", ""),
                    "triggered": len(cbs) > 0,
                    "callback_count": len(cbs),
                })

            triggered = [r for r in results if r["triggered"]]
            return {
                "total_tokens": len(results),
                "triggered_count": len(triggered),
                "tokens": results,
                "triggered": triggered,
            }

    def reset(self):
        """Clear all tokens and callbacks (call between scans)."""
        with self._lock:
            self._tokens.clear()
            self._callbacks.clear()


_global_oob: OOBManager | None = None


def get_oob_manager() -> OOBManager | None:
    return _global_oob


def init_oob_manager(scanner_base_url: str | None = None) -> OOBManager:
    global _global_oob
    _global_oob = OOBManager(scanner_base_url=scanner_base_url)
    return _global_oob
