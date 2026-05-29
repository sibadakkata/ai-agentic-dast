"""SSE live events (Gate 8)."""
from unittest import mock
from web import live_events

def test_publish_pg(monkeypatch):
    monkeypatch.setenv("LIVE_EVENTS_REDIS", "0")
    live_events.LIVE_EVENTS_REDIS = False
    with mock.patch.object(live_events.pgdb, "save_live_event_returning_id", return_value=1):
        assert live_events.publish_event("s", "e", {}) == 1
