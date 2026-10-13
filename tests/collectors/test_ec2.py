"""EC2(보안그룹·VPC) collector 테스트."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from kompass.aws.guard import read_only_session
from kompass.aws.session import ScanContext
from kompass.collectors.ec2 import RESOURCE_KINDS, Ec2Collector
from kompass.snapshots import SnapshotStore, load_scan
from tests.collectors.stubbing import StubbingSession

ACCOUNT = "123456789012"
HOME = "ap-northeast-2"
OTHER = "us-east-1"


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


@pytest.fixture
def setup(aws: None) -> Any:
    """테스트 데이터 준비용. 가드가 없다."""
    return boto3.Session()


def _scan(regions: tuple[str, ...] = (HOME,), session: Any = None) -> ScanContext:
    return ScanContext(
        session=session or read_only_session(),
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region=HOME,
        regions=regions,
    )


def _build_vpc(setup: Any, region: str = HOME) -> dict[str, str]:
    ec2 = setup.client("ec2", region_name=region)
    vpc = ec2.create_vpc(CidrBlock="10.10.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.10.1.0/24")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    table = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=table, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=table, SubnetId=subnet)
    group = ec2.create_security_group(GroupName="open-ssh", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group, IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0"
    )
    eni = ec2.create_network_interface(SubnetId=subnet, Groups=[group])["NetworkInterface"]
    return {
        "vpc": vpc,
        "subnet": subnet,
        "table": table,
        "group": group,
        "eni": eni["NetworkInterfaceId"],
    }


def _ids(items: list[dict[str, Any]], key: str) -> set[str]:
    return {item[key] for item in items}


# --- 정상 경로 ---


def test_collects_all_resource_kinds_per_region(setup: Any) -> None:
    built = _build_vpc(setup)
    snapshot = Ec2Collector().collect(_scan())

    assert snapshot.service == "ec2"
    assert snapshot.regions == (HOME,)
    assert snapshot.errors == ()
    region = snapshot.data["regions"][HOME]
    assert set(region) == set(RESOURCE_KINDS)
    assert built["vpc"] in _ids(region["vpcs"], "VpcId")
    assert built["subnet"] in _ids(region["subnets"], "SubnetId")
    assert built["table"] in _ids(region["route_tables"], "RouteTableId")
    assert built["eni"] in _ids(region["network_interfaces"], "NetworkInterfaceId")
    [group] = [g for g in region["security_groups"] if g["GroupId"] == built["group"]]
    assert group["IpPermissions"][0]["IpRanges"][0]["CidrIp"] == "0.0.0.0/0"


def test_only_scan_regions_are_collected(setup: Any) -> None:
    _build_vpc(setup, region=OTHER)
    snapshot = Ec2Collector().collect(_scan(regions=(HOME,)))
    assert set(snapshot.data["regions"]) == {HOME}


def test_multiple_regions(setup: Any) -> None:
    other = _build_vpc(setup, region=OTHER)
    snapshot = Ec2Collector().collect(_scan(regions=(HOME, OTHER)))
    assert set(snapshot.data["regions"]) == {HOME, OTHER}
    assert other["vpc"] in _ids(snapshot.data["regions"][OTHER]["vpcs"], "VpcId")
    assert other["vpc"] not in _ids(snapshot.data["regions"][HOME]["vpcs"], "VpcId")


def test_snapshot_round_trips_through_store(setup: Any, tmp_path: Path) -> None:
    _build_vpc(setup)
    scan = _scan()
    snapshot = Ec2Collector().collect(scan)
    writer = SnapshotStore(tmp_path / ".kompass").begin(scan)
    writer.write(snapshot)
    assert load_scan(writer.finish())[1]["ec2"] == snapshot


# --- 오류 경로 ---


def test_failed_kind_is_missing_and_others_collected(setup: Any) -> None:
    # 한 종류만 실패하면 그 키만 빠지고, 같은 리전의 다른 종류는 정상 수집된다
    session = read_only_session()
    client = session.client("ec2", region_name=HOME)
    real = session.client("ec2", region_name=HOME)
    with Stubber(client) as stub:
        stub.add_client_error(
            "describe_security_groups", service_error_code="UnauthorizedOperation"
        )
        for method, key in [
            ("describe_vpcs", "Vpcs"),
            ("describe_subnets", "Subnets"),
            ("describe_route_tables", "RouteTables"),
            ("describe_network_interfaces", "NetworkInterfaces"),
        ]:
            response = getattr(real, method)()
            stub.add_response(method, {key: response[key]})
        snapshot = Ec2Collector().collect(
            _scan(session=StubbingSession(session, {("ec2", HOME): client}))
        )

    region = snapshot.data["regions"][HOME]
    assert "security_groups" not in region
    assert {"vpcs", "subnets", "route_tables", "network_interfaces"} <= set(region)
    [error] = snapshot.errors
    assert error.operation == "ec2:DescribeSecurityGroups"
    assert error.region == HOME
    assert error.error_code == "UnauthorizedOperation"


def test_region_wide_failure_keeps_other_regions(setup: Any) -> None:
    # SCP 등으로 리전 전체가 막혀도 다른 리전은 정상 수집된다
    session = read_only_session()
    client = session.client("ec2", region_name=OTHER)
    with Stubber(client) as stub:
        for method in (
            "describe_security_groups",
            "describe_vpcs",
            "describe_subnets",
            "describe_route_tables",
            "describe_network_interfaces",
        ):
            stub.add_client_error(method, service_error_code="UnauthorizedOperation")
        snapshot = Ec2Collector().collect(
            _scan(regions=(HOME, OTHER), session=StubbingSession(session, {("ec2", OTHER): client}))
        )

    assert snapshot.data["regions"][OTHER] == {}
    assert set(snapshot.data["regions"][HOME]) == set(RESOURCE_KINDS)
    assert len(snapshot.errors) == 5
    assert {e.region for e in snapshot.errors} == {OTHER}
