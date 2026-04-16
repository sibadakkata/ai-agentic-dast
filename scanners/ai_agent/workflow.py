"""Business Logic Workflow — record, store, replay, and adapt user workflows.

Supports two modes (hybrid):
  1. Natural-language description → LLM autonomously navigates the flow
  2. Recorded browser steps → deterministic replay with LLM-driven adaptation

Workflows are stored as JSON files in the workflows/ directory.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

WORKFLOWS_DIR = Path(__file__).resolve().parent.parent.parent / "workflows"
WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)

MAX_STEP_RETRIES = 2
STEP_TIMEOUT_MS = 15000
NAV_WAIT = "domcontentloaded"


# ── Data Model ──────────────────────────────────────────────────────────

@dataclass
class WorkflowStep:
    """A single recorded browser interaction."""
    action: str                     # navigate | click | fill | select | scroll | keypress | wait | assert_text
    selector: str = ""              # CSS selector, text:, role:, placeholder:, label:
    value: str = ""                 # text to type, URL to navigate to, key to press
    description: str = ""           # human-readable description (auto-generated or user-provided)
    url_at_step: str = ""           # page URL when this step was recorded
    timestamp_ms: int = 0           # recording timestamp (epoch ms)
    screenshot_b64: str = ""        # optional screenshot at this step (JPEG, small)
    wait_after_ms: int = 500        # wait after action (ms)
    is_test_point: bool = False     # mark this step as a security test point

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("screenshot_b64", None)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> WorkflowStep:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Workflow:
    """A complete business logic workflow — recorded steps + NL description."""
    id: str = ""
    name: str = "Untitled Workflow"
    description: str = ""           # natural-language description of the flow
    target_url: str = ""            # base URL this workflow applies to
    steps: list[WorkflowStep] = field(default_factory=list)
    test_points: list[str] = field(default_factory=list)  # named points where security testing should focus
    variables: dict[str, str] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "target_url": self.target_url,
            "steps": [s.to_dict() for s in self.steps],
            "test_points": self.test_points,
            "variables": self.variables,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Workflow:
        steps = [WorkflowStep.from_dict(s) for s in d.get("steps", [])]
        return cls(
            id=d.get("id", ""),
            name=d.get("name", "Untitled Workflow"),
            description=d.get("description", ""),
            target_url=d.get("target_url", ""),
            steps=steps,
            test_points=d.get("test_points", []),
            variables=d.get("variables", {}),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
            tags=d.get("tags", []),
        )


# ── Storage ─────────────────────────────────────────────────────────────

def save_workflow(wf: Workflow) -> str:
    if not wf.id:
        wf.id = str(uuid.uuid4())[:8]
    if not wf.created_at:
        from datetime import datetime
        wf.created_at = datetime.now().isoformat()
    from datetime import datetime
    wf.updated_at = datetime.now().isoformat()
    path = WORKFLOWS_DIR / f"{wf.id}.json"
    path.write_text(json.dumps(wf.to_dict(), indent=2, default=str), encoding="utf-8")
    logger.info("Saved workflow %s (%s) → %s", wf.id, wf.name, path)
    return wf.id


def load_workflow(workflow_id: str) -> Workflow | None:
    path = WORKFLOWS_DIR / f"{workflow_id}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return Workflow.from_dict(data)
    except Exception as e:
        logger.error("Failed to load workflow %s: %s", workflow_id, e)
        return None


def list_workflows() -> list[dict]:
    results = []
    for p in sorted(WORKFLOWS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            results.append({
                "id": data.get("id", p.stem),
                "name": data.get("name", ""),
                "description": data.get("description", "")[:200],
                "target_url": data.get("target_url", ""),
                "steps_count": len(data.get("steps", [])),
                "test_points": data.get("test_points", []),
                "created_at": data.get("created_at", ""),
                "updated_at": data.get("updated_at", ""),
                "tags": data.get("tags", []),
            })
        except Exception:
            pass
    return results


def delete_workflow(workflow_id: str) -> bool:
    path = WORKFLOWS_DIR / f"{workflow_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False


# ── Replay Engine ───────────────────────────────────────────────────────

@dataclass
class ReplayResult:
    success: bool
    steps_completed: int
    steps_total: int
    failed_step: int | None = None
    error: str = ""
    adapted_steps: list[int] = field(default_factory=list)
    captured_state: dict = field(default_factory=dict)


async def replay_workflow(
    page: Any,
    workflow: Workflow,
    variables: dict[str, str] | None = None,
    on_step: Callable | None = None,
    llm_adapter: Callable | None = None,
) -> ReplayResult:
    """Replay recorded workflow steps on a Playwright page.

    Args:
        page: Playwright page object.
        workflow: The workflow to replay.
        variables: Variable substitutions (e.g. {{username}} → actual value).
        on_step: Callback(step_idx, step, status) for progress reporting.
        llm_adapter: async fn(page, step, error) → adapted WorkflowStep or None.
            Called when a step fails, allowing the LLM to find an alternative.
    """
    vars_ = {**(workflow.variables or {}), **(variables or {})}
    _cb = on_step or (lambda *a: None)
    result = ReplayResult(success=True, steps_completed=0, steps_total=len(workflow.steps))

    for idx, step in enumerate(workflow.steps):
        resolved = _resolve_step_vars(step, vars_)
        _cb(idx, resolved, "starting")

        success = False
        for attempt in range(1 + MAX_STEP_RETRIES):
            try:
                await _execute_step(page, resolved)
                success = True
                break
            except Exception as e:
                logger.warning("Step %d (%s) attempt %d failed: %s",
                               idx, resolved.action, attempt + 1, e)
                if attempt < MAX_STEP_RETRIES and llm_adapter:
                    try:
                        adapted = await llm_adapter(page, resolved, str(e))
                        if adapted:
                            logger.info("Step %d adapted by LLM: %s → %s",
                                        idx, resolved.selector, adapted.selector)
                            resolved = adapted
                            result.adapted_steps.append(idx)
                            continue
                    except Exception as adapt_err:
                        logger.warning("LLM adaptation failed: %s", adapt_err)

        if success:
            result.steps_completed += 1
            _cb(idx, resolved, "completed")
            if resolved.wait_after_ms > 0:
                await asyncio.sleep(resolved.wait_after_ms / 1000)
        else:
            result.success = False
            result.failed_step = idx
            result.error = f"Step {idx} ({resolved.action} {resolved.selector}) failed after {MAX_STEP_RETRIES + 1} attempts"
            _cb(idx, resolved, "failed")
            logger.error("Workflow replay failed at step %d: %s", idx, result.error)
            break

    result.captured_state = {
        "final_url": page.url or "",
        "cookies_count": len(await page.context.cookies()),
    }
    return result


async def _execute_step(page: Any, step: WorkflowStep) -> None:
    """Execute a single workflow step on the Playwright page."""
    action = step.action.lower()

    if action == "navigate":
        url = step.value
        if not url:
            raise ValueError("navigate step requires a URL in 'value'")
        resp = await page.goto(url, wait_until=NAV_WAIT, timeout=STEP_TIMEOUT_MS)
        if resp and resp.status >= 400:
            logger.warning("Navigation to %s returned %d", url, resp.status)

    elif action == "click":
        locator = _resolve_locator(page, step.selector)
        await locator.wait_for(state="visible", timeout=STEP_TIMEOUT_MS)
        await locator.click(timeout=STEP_TIMEOUT_MS)

    elif action == "fill":
        locator = _resolve_locator(page, step.selector)
        await locator.wait_for(state="visible", timeout=STEP_TIMEOUT_MS)
        await locator.fill(step.value, timeout=STEP_TIMEOUT_MS)

    elif action == "select":
        locator = _resolve_locator(page, step.selector)
        await locator.select_option(step.value, timeout=STEP_TIMEOUT_MS)

    elif action == "keypress":
        await page.keyboard.press(step.value)

    elif action == "scroll":
        delta_y = int(step.value) if step.value else 300
        await page.mouse.wheel(0, delta_y)

    elif action == "wait":
        ms = int(step.value) if step.value else 1000
        await asyncio.sleep(ms / 1000)

    elif action == "assert_text":
        text = step.value
        content = await page.content()
        if text.lower() not in content.lower():
            raise AssertionError(f"Expected text '{text}' not found on page")

    elif action == "screenshot":
        pass  # no-op during replay, used for documentation

    else:
        raise ValueError(f"Unknown action: {action}")


def _resolve_locator(page: Any, selector: str):
    """Resolve a selector to a Playwright locator, supporting text:, role:, placeholder:, label: prefixes."""
    sel = selector.strip()
    if sel.startswith("text:"):
        return page.get_by_text(sel[5:].strip(), exact=False)
    if sel.startswith("role:"):
        parts = sel[5:].strip()
        if "[" in parts and parts.endswith("]"):
            role = parts[:parts.index("[")]
            name = parts[parts.index("[") + 1:-1]
            return page.get_by_role(role, name=name)
        return page.get_by_role(parts)
    if sel.startswith("placeholder:"):
        return page.get_by_placeholder(sel[12:].strip())
    if sel.startswith("label:"):
        return page.get_by_label(sel[6:].strip())
    return page.locator(sel)


def _resolve_step_vars(step: WorkflowStep, variables: dict) -> WorkflowStep:
    """Replace {{variable}} placeholders in step value and selector."""
    def _sub(text: str) -> str:
        for k, v in variables.items():
            text = text.replace(f"{{{{{k}}}}}", str(v))
        return text

    return WorkflowStep(
        action=step.action,
        selector=_sub(step.selector),
        value=_sub(step.value),
        description=step.description,
        url_at_step=step.url_at_step,
        timestamp_ms=step.timestamp_ms,
        wait_after_ms=step.wait_after_ms,
        is_test_point=step.is_test_point,
    )


# ── Recording Helper ────────────────────────────────────────────────────

class WorkflowRecorder:
    """Captures browser events into workflow steps during a recording session.

    Used by the WebSocket recorder endpoint — receives raw browser events
    (click, type, navigate, etc.) and converts them into WorkflowStep objects.
    """

    def __init__(self, target_url: str, name: str = ""):
        self.workflow = Workflow(
            id=str(uuid.uuid4())[:8],
            name=name or "Recorded Workflow",
            target_url=target_url,
        )
        self._last_fill_selector: str = ""
        self._last_fill_buffer: str = ""
        self._start_time = time.time()

    def record_event(self, evt: dict, page_url: str = "") -> WorkflowStep | None:
        """Process a raw browser event and optionally append a workflow step."""
        etype = evt.get("type", "")
        now_ms = int(time.time() * 1000)

        if etype == "navigate":
            step = WorkflowStep(
                action="navigate",
                value=evt.get("url", ""),
                url_at_step=page_url,
                timestamp_ms=now_ms,
                description=f"Navigate to {evt.get('url', '')}",
            )
            self._flush_fill()
            self.workflow.steps.append(step)
            return step

        if etype == "click":
            self._flush_fill()
            selector = evt.get("selector", "")
            text = evt.get("text", "")[:50]
            step = WorkflowStep(
                action="click",
                selector=selector,
                url_at_step=page_url,
                timestamp_ms=now_ms,
                description=f"Click {text or selector}",
            )
            self.workflow.steps.append(step)
            return step

        if etype == "fill" or etype == "type":
            selector = evt.get("selector", "")
            value = evt.get("value", "") or evt.get("text", "")
            if selector == self._last_fill_selector and self._last_fill_buffer:
                self._last_fill_buffer = value
                if self.workflow.steps and self.workflow.steps[-1].action == "fill":
                    self.workflow.steps[-1].value = value
                return None
            else:
                self._flush_fill()
                self._last_fill_selector = selector
                self._last_fill_buffer = value
                step = WorkflowStep(
                    action="fill",
                    selector=selector,
                    value=value,
                    url_at_step=page_url,
                    timestamp_ms=now_ms,
                    description=f"Fill {selector}",
                )
                self.workflow.steps.append(step)
                return step

        if etype == "select":
            self._flush_fill()
            step = WorkflowStep(
                action="select",
                selector=evt.get("selector", ""),
                value=evt.get("value", ""),
                url_at_step=page_url,
                timestamp_ms=now_ms,
                description=f"Select {evt.get('value', '')} in {evt.get('selector', '')}",
            )
            self.workflow.steps.append(step)
            return step

        if etype == "keypress":
            key = evt.get("key", "")
            if key in ("Enter", "Tab", "Escape"):
                self._flush_fill()
                step = WorkflowStep(
                    action="keypress",
                    value=key,
                    url_at_step=page_url,
                    timestamp_ms=now_ms,
                    description=f"Press {key}",
                )
                self.workflow.steps.append(step)
                return step

        if etype == "mark_test_point":
            name = evt.get("name", f"test_point_{len(self.workflow.test_points)}")
            self.workflow.test_points.append(name)
            if self.workflow.steps:
                self.workflow.steps[-1].is_test_point = True
            return None

        return None

    def _flush_fill(self):
        self._last_fill_selector = ""
        self._last_fill_buffer = ""

    def finish(self, description: str = "") -> Workflow:
        self._flush_fill()
        if description:
            self.workflow.description = description
        return self.workflow


# ── LLM Workflow Context Builder ────────────────────────────────────────

def build_workflow_prompt(workflow: Workflow) -> str:
    """Build a system prompt section describing the workflow for the LLM agent."""
    lines = [
        "## Business Logic Workflow",
        f"**Name**: {workflow.name}",
    ]

    if workflow.description:
        lines.append(f"**Description**: {workflow.description}")
        lines.append("")
        lines.append("Follow this workflow to reach the target application state, "
                      "then test for security vulnerabilities at each step.")

    if workflow.steps:
        lines.append("")
        lines.append(f"### Recorded Steps ({len(workflow.steps)} steps)")
        lines.append("Replay these steps to navigate the application flow. "
                      "If a step fails (element not found, page changed), "
                      "adapt by finding the equivalent element or action.")
        lines.append("")
        for i, step in enumerate(workflow.steps):
            marker = " **[TEST POINT]**" if step.is_test_point else ""
            desc = step.description or f"{step.action} {step.selector or step.value}"
            lines.append(f"  {i + 1}. {desc}{marker}")

    if workflow.test_points:
        lines.append("")
        lines.append("### Security Test Points")
        lines.append("Focus security testing at these points in the workflow:")
        for tp in workflow.test_points:
            lines.append(f"  - {tp}")

    lines.append("")
    lines.append("### Testing Instructions")
    lines.append("At each test point and at the end of the workflow:")
    lines.append("- Test parameter tampering (modify IDs, roles, hidden fields, numeric values)")
    lines.append("- Test step skipping (skip required steps, access later steps directly)")
    lines.append("- Test privilege escalation (use another user's IDs/tokens in current session)")
    lines.append("- Test race conditions (replay the same action concurrently)")
    lines.append("- Test boundary/negative cases (empty values, overflows, special chars)")
    lines.append("- Test authorization bypass (access resources without completing required flow)")
    lines.append("- Fuzz all input parameters at each step")

    return "\n".join(lines)
