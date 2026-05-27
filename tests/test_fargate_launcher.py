"""Fargate launcher (Gate 9)."""
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
