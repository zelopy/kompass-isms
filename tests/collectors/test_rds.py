"""RDS collector 테스트."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from kompass.aws.guard import read_only_session
from kompass.aws.session import ScanContext
from kompass.collectors.rds import RESOURCE_KINDS, RdsCollector
from kompass.snapshots import SnapshotStore, load_scan
from tests.collectors.stubbing import StubbingSession

ACCOUNT = "123456789012"
HOME = "ap-northeast-2"
OTHER = "us-east-1"


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


def _scan(regions: tuple[str, ...] = (HOME,), session: Any = None) -> ScanContext:
    return ScanContext(
        session=session or read_only_session(),
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region=HOME,
        regions=regions,
    )


def _build(region: str = HOME) -> None:
    rds = boto3.client("rds", region_name=region)
    rds.create_db_instance(
        DBInstanceIdentifier="orders",
        Engine="postgres",
        DBInstanceClass="db.t4g.micro",
        AllocatedStorage=20,
        MasterUsername="admin_user",
        MasterUserPassword="password-1234",
        PubliclyAccessible=True,
    )
    rds.create_db_cluster(
        DBClusterIdentifier="ledger",
        Engine="aurora-postgresql",
        MasterUsername="admin_user",
        MasterUserPassword="password-1234",
    )


def test_collects_instances_and_clusters(aws: None) -> None:
    _build()
    snapshot = RdsCollector().collect(_scan())
    assert snapshot.service == "rds" and snapshot.errors == ()
    region = snapshot.data["regions"][HOME]
    assert set(region) == set(RESOURCE_KINDS)
    assert [i["DBInstanceIdentifier"] for i in region["db_instances"]] == ["orders"]
    assert [c["DBClusterIdentifier"] for c in region["db_clusters"]] == ["ledger"]
    assert region["db_instances"][0]["PubliclyAccessible"] is True


def test_only_scan_regions_are_collected(aws: None) -> None:
    _build(OTHER)
    snapshot = RdsCollector().collect(_scan())
    assert snapshot.data["regions"] == {HOME: {"db_instances": [], "db_clusters": []}}


def test_snapshot_round_trips_through_store(aws: None, tmp_path: Path) -> None:
    _build()
    scan = _scan()
    snapshot = RdsCollector().collect(scan)
    writer = SnapshotStore(tmp_path / ".kompass").begin(scan)
    writer.write(snapshot)
    assert load_scan(writer.finish())[1]["rds"] == snapshot


def test_failed_kind_is_missing_and_recorded(aws: None) -> None:
    session = read_only_session()
    client = session.client("rds", region_name=HOME)
    with Stubber(client) as stub:
        stub.add_client_error("describe_db_instances", service_error_code="AccessDenied")
        stub.add_response("describe_db_clusters", {"DBClusters": []})
        snapshot = RdsCollector().collect(
            _scan(session=StubbingSession(session, {("rds", HOME): client}))
        )
    assert snapshot.data["regions"][HOME] == {"db_clusters": []}
    [error] = snapshot.errors
    assert error.operation == "rds:DescribeDBInstances"
    assert error.region == HOME and error.error_code == "AccessDenied"
