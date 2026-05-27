"""Launch scanner workers: Docker or Fargate (Gates 7-9)."""
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
