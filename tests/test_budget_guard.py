"""Tests for scan budget guard."""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scanners.ai_agent.budget import BudgetGuard


def test_record_accumulates_cost():
    scans = {"s1": {"progress": [], "budget_status": "ok"}}
    pause = threading.Event()
    guard = BudgetGuard("s1", 10.0, "user-1", scans, pause)
    guard.record(1.25)
    guard.record(0.75)
    assert guard.current_total_usd == 2.0
    assert scans["s1"]["budget_total_usd"] == 2.0


def test_exceed_sets_pause_and_status():
    scans = {"s1": {"progress": [], "budget_status": "ok", "status": "running"}}
    pause = threading.Event()
    guard = BudgetGuard("s1", 1.0, "user-1", scans, pause, owner_label="alice")
    guard.record(0.5)
    assert not guard.is_exceeded()
    assert not pause.is_set()
    guard.record(0.6)
    assert guard.is_exceeded()
    assert pause.is_set()
    assert scans["s1"]["budget_status"] == "awaiting_approval"
    assert any("Budget cap" in p for p in scans["s1"]["progress"])


def test_exceed_is_idempotent():
    scans = {"s1": {"progress": [], "budget_status": "ok"}}
    pause = threading.Event()
    guard = BudgetGuard("s1", 1.0, "user-1", scans, pause)
    guard.record(2.0)
    msgs = len(scans["s1"]["progress"])
    guard.record(3.0)
    assert len(scans["s1"]["progress"]) == msgs


def test_no_negative_record():
    scans = {"s1": {}}
    guard = BudgetGuard("s1", 5.0, None, scans, threading.Event())
    guard.record(-1.0)
    guard.record(0.0)
    assert guard.current_total_usd == 0.0


def test_unlimited_cap_never_exceeds():
    scans = {"s1": {}}
    guard = BudgetGuard("s1", None, None, scans, threading.Event())
    guard.record(100.0)
    assert not guard.is_exceeded()
