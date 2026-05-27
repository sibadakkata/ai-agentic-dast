#!/usr/bin/env python3
"""Build scanner-runner on EC2 and push to ECR (avoids Docker Desktop org lock)."""
from __future__ import annotations
import os
import subprocess
import sys

REPO = "168551359048.dkr.ecr.us-east-2.amazonaws.com"
IMAGE = f"{REPO}/dast-scanner-runner"
TAG = os.environ.get("IMAGE_TAG", "v0-57c780f")
KEY = r"C:\Projects\Pen-Test\Acunetix\siba-dast-agentic-poc.pem"
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
