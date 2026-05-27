"""Write Gate 7-9 Python modules as UTF-8 (avoids editor UTF-16 corruption)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def w(rel: str, text: str) -> None:
    p = ROOT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")
    assert b"\x00" not in p.read_bytes(), rel


w(
    "web/live_events.py",
    '''"""Live scan events: durable PG + optional Redis (Gate 8)."""
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
''',
)

w(
    "web/scan_launcher.py",
    '''"""Launch scanner workers: Docker or Fargate (Gates 7-9)."""
from __future__ import annotations
import json, logging, os, subprocess
from typing import Any
log = logging.getLogger(__name__)
SCAN_LAUNCHER = os.environ.get("SCAN_LAUNCHER", "in-process").strip().lower()
SCANNER_IMAGE = os.environ.get("SCANNER_IMAGE", "").strip()
SPAWN_SCANNER_CONTAINER = os.environ.get("SPAWN_SCANNER_CONTAINER", "0").strip() == "1"
ECS_CLUSTER = os.environ.get("ECS_CLUSTER", "dast-scanner")
ECS_TASK_DEFINITION = os.environ.get("ECS_TASK_DEFINITION", "")
ECS_SUBNETS = [s.strip() for s in os.environ.get("ECS_SUBNETS", "").split(",") if s.strip()]
ECS_SECURITY_GROUPS = [s.strip() for s in os.environ.get("ECS_SECURITY_GROUPS", "").split(",") if s.strip()]

def build_job_env(scan_id: str, config: dict[str, Any]) -> dict[str, str]:
    env = {"SCAN_ID": scan_id, "SCAN_JOB_JSON": json.dumps(config, default=str), "DUAL_WRITE_PG": "1"}
    for key in ("DATABASE_URL", "REDIS_URL", "LIVE_EVENTS_REDIS", "AWS_REGION"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env

def launch_local_docker(scan_id: str, config: dict[str, Any]) -> str:
    if not SCANNER_IMAGE:
        raise RuntimeError("SCANNER_IMAGE not set")
    env_args = []
    for k, v in build_job_env(scan_id, config).items():
        env_args.extend(["-e", f"{k}={v}"])
    cmd = ["docker", "run", "-d", "--rm", "--network", "host", *env_args, SCANNER_IMAGE, "--scan-id", scan_id]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout)
    return proc.stdout.strip()

def launch_fargate(scan_id: str, config: dict[str, Any]) -> str:
    import time
    import boto3
    from botocore.exceptions import ClientError
    task_def = os.environ.get("ECS_TASK_DEFINITION", "").strip()
    subnets = [s.strip() for s in os.environ.get("ECS_SUBNETS", "").split(",") if s.strip()]
    if not task_def or not subnets:
        raise RuntimeError("ECS config missing")
    job_env = build_job_env(scan_id, config)
    overrides = [{"name": k, "value": v} for k, v in job_env.items()]
    client = boto3.client("ecs", region_name=os.environ.get("AWS_REGION", "us-east-2"))
    last_err = None
    for attempt in range(4):
        try:
            resp = client.run_task(
                cluster=os.environ.get("ECS_CLUSTER", "dast-scanner"), taskDefinition=task_def, launchType="FARGATE",
                networkConfiguration={"awsvpcConfiguration": {"subnets": subnets, "securityGroups": ECS_SECURITY_GROUPS, "assignPublicIp": "ENABLED"}},
                overrides={"containerOverrides": [{"name": "scanner-runner", "environment": overrides}]},
            )
            if resp.get("failures"):
                raise RuntimeError(resp["failures"])
            return resp["tasks"][0]["taskArn"]
        except ClientError as exc:
            last_err = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException") or attempt >= 3:
                raise
            time.sleep(2 ** attempt)
    raise last_err or RuntimeError("ECS RunTask failed")

def launch_scan_worker(scan_id: str, config: dict[str, Any]) -> str:
    if SCAN_LAUNCHER == "fargate":
        return launch_fargate(scan_id, config)
    if SCAN_LAUNCHER in ("local-docker", "docker") or SPAWN_SCANNER_CONTAINER:
        return launch_local_docker(scan_id, config)
    raise RuntimeError(SCAN_LAUNCHER)
''',
)

w(
    "scanners/runner/main.py",
    '''#!/usr/bin/env python3
from __future__ import annotations
import argparse, asyncio, json, logging, os, sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scanner-runner")

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--scan-id", required=True)
    args = p.parse_args()
    if not os.environ.get("SCAN_JOB_JSON") or not os.environ.get("DATABASE_URL"):
        return 1
    os.environ["DUAL_WRITE_PG"] = "1"
    from web.scan_job import execute_scan_job
    asyncio.run(execute_scan_job(args.scan_id, json.loads(os.environ["SCAN_JOB_JSON"])))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
''',
)

w("scanners/runner/__init__.py", '"""Scanner runner (Gate 7)."""\n')

w(
    "tests/test_sse_stream.py",
    '''"""SSE live events (Gate 8)."""
from unittest import mock
from web import live_events

def test_publish_pg(monkeypatch):
    monkeypatch.setenv("LIVE_EVENTS_REDIS", "0")
    live_events.LIVE_EVENTS_REDIS = False
    with mock.patch.object(live_events.pgdb, "save_live_event_returning_id", return_value=1):
        assert live_events.publish_event("s", "e", {}) == 1
''',
)

w(
    "tests/test_fargate_launcher.py",
    '''"""Fargate launcher (Gate 9)."""
from unittest import mock
import pytest
from web import scan_launcher

def test_fargate_ok(monkeypatch):
    monkeypatch.setenv("ECS_TASK_DEFINITION", "t:1")
    monkeypatch.setenv("ECS_SUBNETS", "sub")
    fake = mock.MagicMock()
    fake.run_task.return_value = {"tasks": [{"taskArn": "arn:task/x"}], "failures": []}
    with mock.patch("boto3.client", return_value=fake):
        assert "task/" in scan_launcher.launch_fargate("s", {"target_url": "http://x", "model": "m"})

def test_fargate_fail(monkeypatch):
    monkeypatch.setenv("ECS_TASK_DEFINITION", "t:1")
    monkeypatch.setenv("ECS_SUBNETS", "sub")
    fake = mock.MagicMock()
    fake.run_task.return_value = {"tasks": [], "failures": [{}]}
    with mock.patch("boto3.client", return_value=fake):
        with pytest.raises(RuntimeError):
            scan_launcher.launch_fargate("s", {"target_url": "http://x", "model": "m"})

def test_fargate_throttle_retry(monkeypatch):
    monkeypatch.setenv("ECS_TASK_DEFINITION", "t:1")
    monkeypatch.setenv("ECS_SUBNETS", "sub")
    fake = mock.MagicMock()
    err = __import__("botocore.exceptions", fromlist=["ClientError"]).ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "slow down"}}, "RunTask"
    )
    fake.run_task.side_effect = [err, {"tasks": [{"taskArn": "arn:task/y"}], "failures": []}]
    with mock.patch("boto3.client", return_value=fake):
        with mock.patch("time.sleep"):
            arn = scan_launcher.launch_fargate("s", {"target_url": "http://x", "model": "m"})
    assert "task/" in arn
    assert fake.run_task.call_count == 2
''',
)

w(
    "web/scan_job.py",
    '''"""Standalone scan execution (PG-only). Gate 7."""
from __future__ import annotations
import asyncio, json, logging, os, time
from datetime import datetime
from pathlib import Path
import httpx
from scanners.ai_agent.agent import run_scan, save_results, ScanCancelled
from scanners.ai_agent.auth import load_targets_from_dict
from scanners.ai_agent.llm_config import LLMRouter
from web import db_pg as pgdb
from web.live_events import publish_event
log = logging.getLogger(__name__)
BASE = Path(__file__).resolve().parent.parent

async def execute_scan_job(scan_id: str, config: dict) -> None:
    os.environ["DUAL_WRITE_PG"] = "1"
    target_url = config["target_url"]
    model = config["model"]
    state = {"target_url": target_url, "model": model, "status": "running", "started": datetime.now().isoformat()}
    pgdb.upsert_scan(scan_id, state)
    publish_event(scan_id, "runner_start", {})
    try:
        async with httpx.AsyncClient(verify=False, timeout=20.0, follow_redirects=True) as c:
            await c.get(target_url)
    except Exception as exc:
        state.update({"status": "error", "error": str(exc)})
        pgdb.upsert_scan(scan_id, state)
        return
    router = LLMRouter(models=[model])
    td = {"id": scan_id.split("_")[-1], "url": target_url, "scan_mode": config.get("scan_mode", "both"),
          "auth": {"type": config.get("auth_type", "auto"), "username": config.get("username", ""), "password": config.get("password", "")},
          "scan_scope": config.get("scan_scope", "directory"), "scan_intensity": config.get("scan_intensity", "light"),
          "scan_profile": config.get("scan_profile", "crawl_only")}
    target = load_targets_from_dict(td)
    findings = []

    def on_progress(event, data):
        if event == "finding":
            pgdb.save_finding(scan_id, dict(data))
            publish_event(scan_id, "finding", data)
        else:
            publish_event(scan_id, event, data if isinstance(data, dict) else {"data": data})

    start = time.perf_counter()
    try:
        findings, metrics = await run_scan(target, model, router, str(BASE / "config"), on_progress=on_progress,
            scan_intensity=config.get("scan_intensity", "light"))
        duration = time.perf_counter() - start
        out = save_results(str(BASE / "results/raw" / f"runner_{scan_id}.json"), findings, router.get_cost_summary(), target, model, duration, metrics)
        pgdb.save_scan_result(scan_id, json.dumps(out, default=str))
        state.update({"status": "completed", "findings_count": len(findings), "duration": round(duration, 1)})
        pgdb.add_all_time_cost(out.get("metadata", {}).get("cost_usd") or 0)
        publish_event(scan_id, "completed", {"findings_count": len(findings)})
    except ScanCancelled:
        state["status"] = "completed"
    except Exception as exc:
        state.update({"status": "error", "error": str(exc)})
        publish_event(scan_id, "error", {"error": str(exc)})
    pgdb.upsert_scan(scan_id, state)
''',
)

w(
    "scripts/gate55_trigger.py",
    '''#!/usr/bin/env python3
import base64, json, os, sys, urllib.error, urllib.request
payload = {
    "target_url": "https://juice-shop.herokuapp.com/",
    "scan_profile": "crawl_only",
    "scan_intensity": "light",
    "model": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "scan_mode": "website",
    "scan_scope": "url_only",
}
body = json.dumps(payload).encode()
user = os.environ.get("DAST_AUTH_USER", "dast-admin")
passwd = os.environ["DAST_AUTH_PASS"]
auth = base64.b64encode(f"{user}:{passwd}".encode()).decode()
req = urllib.request.Request(
    "http://localhost/api/scan",
    data=body,
    headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        print(resp.read().decode())
except urllib.error.HTTPError as e:
    print(e.read().decode(), file=sys.stderr)
    sys.exit(1)
''',
)

w(
    "scripts/gate55_pg_check.py",
    '''#!/usr/bin/env python3
import os, sys
scan_id = sys.argv[1]
import psycopg
url = os.environ["DATABASE_URL"]
with psycopg.connect(url, connect_timeout=10) as conn:
    row = conn.execute(
        "SELECT COUNT(1) FROM findings WHERE scan_id = %s", (scan_id,)
    ).fetchone()
    n = int(row[0])
    print(f"findings_count={n}")
    sys.exit(0 if n > 0 else 1)
''',
)

w(
    "scripts/ec2_build_push_runner.py",
    '''#!/usr/bin/env python3
"""Build scanner-runner on EC2 and push to ECR (avoids Docker Desktop org lock)."""
from __future__ import annotations
import os
import subprocess
import sys

REPO = "168551359048.dkr.ecr.us-east-2.amazonaws.com"
IMAGE = f"{REPO}/dast-scanner-runner"
TAG = os.environ.get("IMAGE_TAG", "v0-57c780f")
KEY = r"C:\\Projects\\Pen-Test\\Acunetix\\siba-dast-agentic-poc.pem"
HOST = "ubuntu@3.20.180.251"


def ssh(cmd: str) -> None:
    args = ["ssh", "-o", "ConnectTimeout=15", "-i", KEY, HOST, cmd]
    print("+", cmd[:120])
    subprocess.run(args, check=True)


def main() -> int:
    os.environ.setdefault("AWS_PROFILE", "dast-poc")
    pw = subprocess.check_output(
        ["aws", "ecr", "get-login-password", "--region", "us-east-2"], text=True
    ).strip()
    ssh(f"echo {pw} | docker login --username AWS --password-stdin {REPO}")
    ssh("rm -rf ~/runner-build; mkdir -p ~/runner-build; tar -xzf /tmp/runner-build.tgz -C ~/runner-build")
    ssh(
        f"cd ~/runner-build; docker build -f scanners/runner/Dockerfile "
        f"-t {IMAGE}:{TAG} -t {IMAGE}:latest ."
    )
    ssh(f"docker push {IMAGE}:{TAG}; docker push {IMAGE}:latest")
    print("pushed", TAG)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''',
)

print("all gate files written")
