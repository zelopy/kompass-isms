"""CloudWatch Logs collector 테스트 (로그 그룹 + 보안 로그 대상 그룹)."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from kompass.aws.guard import read_only_session
from kompass.aws.session import ScanContext
from kompass.collectors.logs import LogsCollector
from kompass.snapshots import SnapshotStore, load_scan
from tests.collectors.stubbing import StubbingSession

ACCOUNT = "123456789012"
HOME = "ap-northeast-2"


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


def _scan(session: Any = None) -> ScanContext:
    return ScanContext(
        session=session or read_only_session(),
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region=HOME,
        regions=(HOME,),
    )


def _build() -> None:
    logs = boto3.client("logs", region_name=HOME)
    logs.create_log_group(logGroupName="trail-logs")
    logs.create_log_group(logGroupName="flow-logs")
    logs.put_retention_policy(logGroupName="flow-logs", retentionInDays=30)
    logs.create_log_group(logGroupName="/aws/lambda/app")
    iam = boto3.client("iam", region_name=HOME)
    role = iam.create_role(RoleName="delivery", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    ec2 = boto3.client("ec2", region_name=HOME)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ec2.create_flow_logs(
        ResourceIds=[vpc],
        ResourceType="VPC",
        TrafficType="ALL",
        LogGroupName="flow-logs",
        DeliverLogsPermissionArn=role,
    )
    s3 = boto3.client("s3", region_name=HOME)
    s3.create_bucket(Bucket="trail-bucket", CreateBucketConfiguration={"LocationConstraint": HOME})
    group_arn = f"arn:aws:logs:{HOME}:{ACCOUNT}:log-group:trail-logs:*"
    boto3.client("cloudtrail", region_name=HOME).create_trail(
        Name="main",
        S3BucketName="trail-bucket",
        CloudWatchLogsLogGroupArn=group_arn,
        CloudWatchLogsRoleArn=role,
    )


def test_collects_log_groups_and_security_sources(aws: None) -> None:
    _build()
    snapshot = LogsCollector().collect(_scan())
    assert snapshot.service == "logs" and snapshot.errors == ()
    region = snapshot.data["regions"][HOME]
    groups = {g["logGroupName"]: g.get("retentionInDays") for g in region["log_groups"]}
    assert groups == {"trail-logs": None, "flow-logs": 30, "/aws/lambda/app": None}
    [flow] = region["flow_log_groups"]
    assert flow["log_group"] == "flow-logs" and flow["flow_log_id"].startswith("fl-")
    [trail] = snapshot.data["trail_log_groups"]
    assert trail["trail"] == "main" and trail["log_group_arn"].endswith(":log-group:trail-logs:*")


def test_snapshot_round_trips_through_store(aws: None, tmp_path: Path) -> None:
    _build()
    scan = _scan()
    snapshot = LogsCollector().collect(scan)
    writer = SnapshotStore(tmp_path / ".kompass").begin(scan)
    writer.write(snapshot)
    assert load_scan(writer.finish())[1]["logs"] == snapshot


def test_failures_leave_keys_missing(aws: None) -> None:
    session = read_only_session()
    logs = session.client("logs", region_name=HOME)
    cloudtrail = session.client("cloudtrail", region_name=HOME)
    with Stubber(logs) as logs_stub, Stubber(cloudtrail) as ct_stub:
        logs_stub.add_client_error(
            "describe_log_groups", service_error_code="AccessDeniedException"
        )
        ct_stub.add_client_error("describe_trails", service_error_code="AccessDeniedException")
        overrides = {("logs", HOME): logs, ("cloudtrail", HOME): cloudtrail}
        snapshot = LogsCollector().collect(_scan(StubbingSession(session, overrides)))
    assert "trail_log_groups" not in snapshot.data
    assert snapshot.data["regions"][HOME] == {"flow_log_groups": []}
    assert {e.operation for e in snapshot.errors} == {
        "logs:DescribeLogGroups",
        "cloudtrail:DescribeTrails",
    }
