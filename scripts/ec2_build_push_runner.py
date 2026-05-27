#!/usr/bin/env python3
"""Build scanner-runner on EC2 and push to ECR (avoids Docker Desktop org lock)."""
from __future__ import annotations
import os
import subprocess
import sys
from pathlib import Path

REPO = "168551359048.dkr.ecr.us-east-2.amazonaws.com"
IMAGE = f"{REPO}/dast-scanner-runner"
TAG = os.environ.get("IMAGE_TAG", "v0-57c780f")
KEY = r"C:\Projects\Pen-Test\Acunetix\siba-dast-agentic-poc.pem"
HOST = "ubuntu@3.20.180.251"
CONTAINER = "dast-scanner"


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


def register_task_def(tag: str) -> int:
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    raw = subprocess.check_output(
        [
            "aws",
            "ecs",
            "describe-task-definition",
            "--task-definition",
            "dast-scanner-runner:1",
            "--region",
            "us-east-2",
            "--output",
            "json",
        ],
        text=True,
    )
    td = json.loads(raw)["taskDefinition"]
    for key in (
        "taskDefinitionArn",
        "revision",
        "status",
        "requiresAttributes",
        "compatibilities",
        "registeredAt",
        "registeredBy",
        "deregisteredAt",
    ):
        td.pop(key, None)
    td["containerDefinitions"][0]["image"] = (
        f"{REPO}/dast-scanner-runner:{tag}"
    )
    reg = root / "tmp_td_reg.json"
    reg.write_text(json.dumps(td), encoding="utf-8")
    out = subprocess.check_output(
        [
            "aws",
            "ecs",
            "register-task-definition",
            "--region",
            "us-east-2",
            "--cli-input-json",
            f"file://{reg.as_posix()}",
        ],
        text=True,
    )
    rev = json.loads(out)["taskDefinition"]["revision"]
    print("ecs revision", rev)
    return rev


def deploy_web_files() -> int:
    files = [
        "web/scan_launcher.py",
        "web/scan_job.py",
        "web/live_events.py",
        "web/db_router.py",
        "web/db_pg.py",
    ]
    for rel in files:
        local = Path(__file__).resolve().parents[1] / rel
        name = Path(rel).name
        subprocess.run(
            ["scp", "-i", KEY, str(local), f"{HOST}:/tmp/{name}"],
            check=True,
        )
        dest = f"/app/{rel}"
        ssh(f"docker cp /tmp/{name} {CONTAINER}:{dest}")
    ssh(f"docker cp /tmp/check_scan_active.py {CONTAINER}:/tmp/ 2>/dev/null; docker exec {CONTAINER} python3 /tmp/check_scan_active.py")
    out = subprocess.run(
        ["ssh", "-i", KEY, HOST, f"docker exec {CONTAINER} python3 /tmp/check_scan_active.py"],
        capture_output=True,
        text=True,
    )
    print(out.stdout)
    if "SAFE TO DEPLOY" not in (out.stdout or ""):
        return 1
    ssh(f"docker restart {CONTAINER}")
    import time

    time.sleep(12)
    hc = subprocess.run(
        ["ssh", "-i", KEY, HOST, "curl -s -o /dev/null -w '%{http_code}' http://localhost/healthz"],
        capture_output=True,
        text=True,
    )
    print("healthz", hc.stdout.strip())
    return 0 if hc.stdout.strip() == "200" else 1


def trigger_dual_scans() -> int:
    payload = (
        '{"target_url":"https://juice-shop.herokuapp.com/",'
        '"model":"bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",'
        '"scan_mode":"website","auth_type":"auto","scan_scope":"url_only",'
        '"scan_intensity":"light","scan_profile":"crawl_only"}'
    )
    cmd = (
        "PASS=$(docker exec dast-scanner printenv DAST_AUTH_PASS); "
        "USER=$(docker exec dast-scanner printenv DAST_AUTH_USER); "
        f"for i in 1 2; do docker exec dast-scanner curl -s -u \"$USER:$PASS\" "
        f"-H 'Content-Type: application/json' -d '{payload}' "
        "http://localhost/api/scan & done; wait; echo triggered"
    )
    ssh(cmd)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "register-td":
        tag = sys.argv[2] if len(sys.argv) > 2 else TAG
        raise SystemExit(0 if register_task_def(tag) else 1)
    if len(sys.argv) > 1 and sys.argv[1] == "deploy-web":
        raise SystemExit(deploy_web_files())
    if len(sys.argv) > 1 and sys.argv[1] == "trigger-dual":
        raise SystemExit(trigger_dual_scans())
    raise SystemExit(main())
