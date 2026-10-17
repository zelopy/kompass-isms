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
from kompass.collectors.rds import RESOURCE_KINDS, SSL_PARAMETERS, RdsCollector
from kompass.rules.rds.rds_005_ssl_enforcement import ENGINE_PARAMETERS
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


def test_collects_instances_and_clusters(aws: None) -> None:
    _build()
    snapshot = RdsCollector().collect(_scan())
    assert snapshot.service == "rds" and snapshot.errors == ()
    region = snapshot.data["regions"][HOME]
    assert set(region) == {*RESOURCE_KINDS, "db_parameter_groups", "db_cluster_parameter_groups"}
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
        snapshot = RdsCollector().collect(
            _scan(session=StubbingSession(session, {("rds", HOME): client}))
        )
    assert snapshot.data["regions"][HOME] == {"db_clusters": [], "db_cluster_parameter_groups": {}}
    [error] = snapshot.errors
    assert error.operation == "rds:DescribeDBInstances"
    assert error.region == HOME and error.error_code == "AccessDenied"
