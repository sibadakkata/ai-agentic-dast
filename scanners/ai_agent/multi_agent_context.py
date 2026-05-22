"""Shared context store for multi-agent scanning.

All specialist agents read from and write to a single SharedScanContext
instance.  The orchestrator creates it, passes it to each specialist,
and the verifier reads all findings at the end.

Thread-safety: all mutations go through asyncio-safe methods so
concurrent specialist agents don't corrupt state.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EndpointInfo:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    body_params: list[str] = field(default_factory=list)
    content_type: str = ""
    auth_required: bool = False
    tech_stack: str = ""
    notes: str = ""


@dataclass
class SharedScanContext:
    """Central memory shared across all specialist agents."""

    target_url: str = ""
    hosts: list[str] = field(default_factory=list)
    scan_id: str = ""

    # %% Recon results (populated by orchestrator / recon phase) %%%%%%%%
    endpoints: list[EndpointInfo] = field(default_factory=list)
    crawled_urls: list[str] = field(default_factory=list)
    discovered_params: dict[str, set[str]] = field(default_factory=dict)
    forms: list[dict] = field(default_factory=list)
    tech_stack: dict[str, Any] = field(default_factory=dict)
    cookies: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    js_files: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)

    # %% Auth state (shared across all agents) %%%%%%%%%%%%%%%%%%%%%%%%%
    auth_token: str = ""
    auth_cookies: dict[str, str] = field(default_factory=dict)
    auth_headers: dict[str, str] = field(default_factory=dict)
    identities: dict[str, dict] = field(default_factory=dict)

    # %% Findings from all agents %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    _findings: list[dict] = field(default_factory=list)
    _findings_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    # %% Inter-agent messages (one agent can flag something for another)
    _messages: list[dict] = field(default_factory=list)
    _messages_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    # %% Dedup: tested (url, param, payload_class) combos %%%%%%%%%%%%%%
    _tested: set[tuple[str, str, str]] = field(default_factory=set)
    _tested_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    # %% Metrics %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    agent_metrics: dict[str, dict] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)

    # %% Methods %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    async def add_finding(self, finding: dict, agent_name: str = "") -> None:
        """Thread-safe finding submission from any agent."""
        async with self._findings_lock:
            finding["_source_agent"] = agent_name
            finding["_timestamp"] = time.time()
            self._findings.append(finding)

    async def get_findings(self, agent_filter: str = "") -> list[dict]:
        """Read findings, optionally filtered by source agent."""
        async with self._findings_lock:
            if agent_filter:
                return [f for f in self._findings
                        if f.get("_source_agent") == agent_filter]
            return list(self._findings)

    async def send_message(self, from_agent: str, to_agent: str,
                           msg_type: str, data: dict) -> None:
        """Inter-agent messaging: flag endpoints, share discoveries."""
        async with self._messages_lock:
            self._messages.append({
                "from": from_agent,
                "to": to_agent,
                "type": msg_type,
                "data": data,
                "time": time.time(),
            })

    async def get_messages(self, for_agent: str) -> list[dict]:
        """Read messages addressed to a specific agent."""
        async with self._messages_lock:
            return [m for m in self._messages if m["to"] == for_agent]

    async def mark_tested(self, url: str, param: str,
                          payload_class: str) -> bool:
        """Mark a (url, param, payload_class) as tested.
        Returns True if it was already tested (skip), False if new."""
        key = (url, param, payload_class)
        async with self._tested_lock:
            if key in self._tested:
                return True
            self._tested.add(key)
            return False

    def add_endpoint(self, endpoint: EndpointInfo) -> None:
        """Add a discovered endpoint (called from recon, non-async)."""
        for existing in self.endpoints:
            if existing.url == endpoint.url and existing.method == endpoint.method:
                existing.params = list(set(existing.params + endpoint.params))
                existing.body_params = list(set(existing.body_params + endpoint.body_params))
                return
        self.endpoints.append(endpoint)

    def add_params(self, url: str, params: set[str]) -> None:
        """Register discovered params for a URL."""
        if url not in self.discovered_params:
            self.discovered_params[url] = set()
        self.discovered_params[url].update(params)

    def get_all_params(self) -> dict[str, set[str]]:
        """Get all discovered params across all URLs."""
        return dict(self.discovered_params)

    def update_metrics(self, agent_name: str, **kwargs) -> None:
        """Update per-agent metrics."""
        if agent_name not in self.agent_metrics:
            self.agent_metrics[agent_name] = {
                "findings": 0, "tool_calls": 0,
                "start_time": time.time(), "status": "running",
            }
        self.agent_metrics[agent_name].update(kwargs)

    @property
    def finding_count(self) -> int:
        return len(self._findings)

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time
