"""Live scan events: durable PG + optional Redis (Gate 8)."""
from __future__ import annotations
import json, logging, os, threading
from typing import Iterator
from web import db_pg as pgdb
log = logging.getLogger(__name__)
LIVE_EVENTS_REDIS = os.environ.get("LIVE_EVENTS_REDIS", "0").strip() == "1"
_REDIS_URL = os.environ.get("REDIS_URL", "").strip()
_redis_client = None
_redis_lock = threading.Lock()

def _channel(scan_id: str) -> str:
    return f"scan-events:{scan_id}"

def _get_redis():
    global _redis_client
    if not LIVE_EVENTS_REDIS or not _REDIS_URL:
        return None
    with _redis_lock:
        if _redis_client is None:
            import redis
            _redis_client = redis.from_url(_REDIS_URL, decode_responses=True)
        return _redis_client

def publish_event(scan_id: str, event_type: str, payload: dict | None = None) -> int | None:
    payload = payload or {}
    event_id = pgdb.save_live_event_returning_id(scan_id, event_type, payload)
    r = _get_redis()
    if r is not None:
        try:
            r.publish(_channel(scan_id), json.dumps({"id": event_id, "event_type": event_type, "payload": payload}, default=str))
        except Exception as exc:
            log.warning("Redis publish failed: %s", exc)
    return event_id

def replay_events(scan_id: str, after_id: int = 0, limit: int = 500) -> list[dict]:
    return pgdb.list_live_events(scan_id, after_id=after_id, limit=limit)

def subscribe_redis(scan_id: str) -> Iterator[dict]:
    r = _get_redis()
    if r is None:
        return iter(())
    pubsub = r.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe(_channel(scan_id))
    try:
        for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            data = message.get("data")
            if isinstance(data, str):
                try:
                    yield json.loads(data)
                except json.JSONDecodeError:
                    pass
    finally:
        try:
            pubsub.close()
        except Exception:
            pass
