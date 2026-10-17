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
from kompass.collectors.rds import RESOURCE_KINDS, SNAPSHOT_KINDS, SSL_PARAMETERS, RdsCollector
from kompass.rules.rds.rds_005_ssl_enforcement import ENGINE_PARAMETERS
from kompass.rules.rds.rds_006_public_snapshot import KINDS
from kompass.snapshots import SnapshotStore, load_scan
from tests.collectors.stubbing import StubbingSession

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
SNAPSHOT_KEYS = {
    "db_snapshots",
    "db_cluster_snapshots",
    "db_snapshot_attributes",
    "db_cluster_snapshot_attributes",
}
EMPTY_SNAPSHOTS: dict[str, Any] = {
    key: [] if key.endswith("snapshots") else {} for key in SNAPSHOT_KEYS
}
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
    # moto는 기본 클러스터 파라미터 그룹을 조회하지 못하므로 그룹을 직접 만든다
    rds.create_db_parameter_group(
        DBParameterGroupName="orders-params", DBParameterGroupFamily="postgres17", Description="x"
    )
    rds.modify_db_parameter_group(
        DBParameterGroupName="orders-params",
        Parameters=[
            {"ParameterName": "rds.force_ssl", "ParameterValue": "1", "ApplyMethod": "immediate"},
            {"ParameterName": "work_mem", "ParameterValue": "4096", "ApplyMethod": "immediate"},
        ],
    )
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName="ledger-params",
        DBParameterGroupFamily="aurora-postgresql17",
        Description="x",
    )
    rds.create_db_instance(
        DBInstanceIdentifier="orders",
        Engine="postgres",
        DBInstanceClass="db.t4g.micro",
        AllocatedStorage=20,
        MasterUsername="admin_user",
        MasterUserPassword="password-1234",
        PubliclyAccessible=True,
        DBParameterGroupName="orders-params",
    )
    rds.create_db_cluster(
        DBClusterIdentifier="ledger",
        Engine="aurora-postgresql",
        MasterUsername="admin_user",
        MasterUserPassword="password-1234",
        DBClusterParameterGroupName="ledger-params",
    )


def _stub_no_snapshots(stub: Stubber) -> None:
    stub.add_response("describe_db_snapshots", {"DBSnapshots": []}, {"SnapshotType": "manual"})
    stub.add_response(
        "describe_db_cluster_snapshots", {"DBClusterSnapshots": []}, {"SnapshotType": "manual"}
    )


def _build_snapshots(rds: Any) -> None:
    rds.create_db_snapshot(DBSnapshotIdentifier="orders-public", DBInstanceIdentifier="orders")
    rds.modify_db_snapshot_attribute(
        DBSnapshotIdentifier="orders-public", AttributeName="restore", ValuesToAdd=["all"]
    )
    rds.create_db_snapshot(DBSnapshotIdentifier="orders-shared", DBInstanceIdentifier="orders")
    rds.modify_db_snapshot_attribute(
        DBSnapshotIdentifier="orders-shared", AttributeName="restore", ValuesToAdd=[OTHER_ACCOUNT]
    )
    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier="ledger-final", DBClusterIdentifier="ledger"
    )


def test_collects_instances_and_clusters(aws: None) -> None:
    _build()
    snapshot = RdsCollector().collect(_scan())
    assert snapshot.service == "rds" and snapshot.errors == ()
    region = snapshot.data["regions"][HOME]
    assert set(region) == {
        *RESOURCE_KINDS,
        "db_parameter_groups",
        "db_cluster_parameter_groups",
        *SNAPSHOT_KEYS,
    }
    assert [i["DBInstanceIdentifier"] for i in region["db_instances"]] == ["orders"]
    assert [c["DBClusterIdentifier"] for c in region["db_clusters"]] == ["ledger"]
    assert region["db_instances"][0]["PubliclyAccessible"] is True


def test_collects_only_ssl_parameters(aws: None) -> None:
    _build()
    region = RdsCollector().collect(_scan()).data["regions"][HOME]
    groups = region["db_parameter_groups"]
    assert list(groups) == ["orders-params"]
    assert list(groups["orders-params"]) == ["rds.force_ssl"]  # work_mem은 버린다
    assert groups["orders-params"]["rds.force_ssl"]["ParameterValue"] == "1"
    assert region["db_cluster_parameter_groups"] == {"ledger-params": {}}


def test_ssl_parameters_match_rule() -> None:
    assert set(ENGINE_PARAMETERS.values()) == SSL_PARAMETERS


def test_failed_parameter_group_is_missing_and_recorded(aws: None) -> None:
    session = read_only_session()
    client = session.client("rds", region_name=HOME)
    instance = {
        "DBInstanceIdentifier": "orders",
        "Engine": "postgres",
        "DBParameterGroups": [{"DBParameterGroupName": "pg", "ParameterApplyStatus": "in-sync"}],
    }
    with Stubber(client) as stub:
        stub.add_response("describe_db_instances", {"DBInstances": [instance]})
        stub.add_response("describe_db_clusters", {"DBClusters": []})
        stub.add_client_error("describe_db_parameters", service_error_code="AccessDenied")
        _stub_no_snapshots(stub)
        snapshot = RdsCollector().collect(
            _scan(session=StubbingSession(session, {("rds", HOME): client}))
        )
    assert snapshot.data["regions"][HOME]["db_parameter_groups"] == {}
    [error] = snapshot.errors
    assert error.operation == "rds:DescribeDBParameters" and error.resource == "pg"


def test_only_scan_regions_are_collected(aws: None) -> None:
    _build(OTHER)
    snapshot = RdsCollector().collect(_scan())
    assert snapshot.data["regions"] == {
        HOME: {
            "db_instances": [],
            "db_clusters": [],
            "db_parameter_groups": {},
            "db_cluster_parameter_groups": {},
            **EMPTY_SNAPSHOTS,
        }
    }


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
        _stub_no_snapshots(stub)
        snapshot = RdsCollector().collect(
            _scan(session=StubbingSession(session, {("rds", HOME): client}))
        )
    assert snapshot.data["regions"][HOME] == {
        "db_clusters": [],
        "db_cluster_parameter_groups": {},
        **EMPTY_SNAPSHOTS,
    }
    [error] = snapshot.errors
    assert error.operation == "rds:DescribeDBInstances"
    assert error.region == HOME and error.error_code == "AccessDenied"


def test_collects_manual_snapshots_and_attributes(aws: None) -> None:
    _build()
    _build_snapshots(boto3.client("rds", region_name=HOME))
    snapshot = RdsCollector().collect(_scan())
    assert snapshot.errors == ()
    region = snapshot.data["regions"][HOME]
    # moto가 만드는 자동 스냅샷(rds:orders-…)은 수집하지 않는다
    assert sorted(s["DBSnapshotIdentifier"] for s in region["db_snapshots"]) == [
        "orders-public",
        "orders-shared",
    ]
    assert [s["DBClusterSnapshotIdentifier"] for s in region["db_cluster_snapshots"]] == [
        "ledger-final"
    ]
    attributes = region["db_snapshot_attributes"]
    assert attributes["orders-public"] == [{"AttributeName": "restore", "AttributeValues": ["all"]}]
    assert attributes["orders-shared"][0]["AttributeValues"] == [OTHER_ACCOUNT]
    assert region["db_cluster_snapshot_attributes"]["ledger-final"] == [
        {"AttributeName": "restore", "AttributeValues": []}
    ]


def test_failed_snapshot_attributes_are_missing_and_recorded(aws: None) -> None:
    session = read_only_session()
    client = session.client("rds", region_name=HOME)
    with Stubber(client) as stub:
        stub.add_response("describe_db_instances", {"DBInstances": []})
        stub.add_response("describe_db_clusters", {"DBClusters": []})
        stub.add_response(
            "describe_db_snapshots",
            {"DBSnapshots": [{"DBSnapshotIdentifier": "orders-copy"}]},
            {"SnapshotType": "manual"},
        )
        stub.add_client_error(
            "describe_db_snapshot_attributes",
            service_error_code="AccessDenied",
            expected_params={"DBSnapshotIdentifier": "orders-copy"},
        )
        stub.add_client_error("describe_db_cluster_snapshots", service_error_code="AccessDenied")
        snapshot = RdsCollector().collect(
            _scan(session=StubbingSession(session, {("rds", HOME): client}))
        )
    region = snapshot.data["regions"][HOME]
    assert region["db_snapshot_attributes"] == {}
    assert "db_cluster_snapshots" not in region
    assert "db_cluster_snapshot_attributes" not in region
    assert [(e.operation, e.resource) for e in snapshot.errors] == [
        ("rds:DescribeDBSnapshotAttributes", "orders-copy"),
        ("rds:DescribeDBClusterSnapshots", None),
    ]


def test_snapshot_keys_match_rule() -> None:
    assert {kind.list_key for kind in KINDS} == set(SNAPSHOT_KINDS)
    assert {kind.attributes_key for kind in KINDS} == {
        spec.attributes_key for spec in SNAPSHOT_KINDS.values()
    }
