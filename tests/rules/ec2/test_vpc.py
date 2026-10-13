"""VPC-001 공개·내부 서브넷 미분리, VPC-002 공인 IP가 할당된 네트워크 인터페이스."""

from typing import Any

from kompass.config import Settings
from kompass.models import Severity, Status
from kompass.rules.ec2.vpc_001_subnet_separation import Vpc001SubnetSeparation
from kompass.rules.ec2.vpc_002_public_ip_interface import Vpc002PublicIpInterface
from tests.rules.ec2.data import (
    REGION,
    collect_error,
    eni,
    region,
    route_table,
    snapshot,
    subnet,
    vpc,
)

VPC001 = Vpc001SubnetSeparation()
VPC002 = Vpc002PublicIpInterface()


def _network(
    *,
    route_tables: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
    subnets: tuple[str, ...] = ("subnet-pub", "subnet-priv"),
    missing: tuple[str, ...] = (),
) -> dict[str, Any]:
    return region(
        vpcs=[vpc("vpc-1")],
        subnets=[subnet(s) for s in subnets],
        route_tables=route_tables,
        network_interfaces=interfaces,
        missing=missing,
    )


MIXED_TABLES = [
    route_table("rtb-main", main=True),
    route_table("rtb-pub", subnets=("subnet-pub",), igw=True),
]


# --- VPC-001 ---


def _vpc001(network: dict[str, Any]) -> Any:
    [finding] = VPC001.evaluate(snapshot({REGION: network}), Settings())
    return finding


def test_vpc001_pass_resource_in_private_subnet() -> None:
    finding = _vpc001(
        _network(route_tables=MIXED_TABLES, interfaces=[eni("eni-1", subnet_id="subnet-priv")])
    )
    assert finding.status == Status.PASS
    assert finding.resource == "vpc-1"
    assert finding.severity == Severity.MEDIUM


def test_vpc001_fail_resources_only_in_public_subnet() -> None:
    finding = _vpc001(
        _network(route_tables=MIXED_TABLES, interfaces=[eni("eni-1", subnet_id="subnet-pub")])
    )
    assert finding.status == Status.FAIL
    assert finding.evidence["subnets"]["subnet-pub"] == {"public": True, "interfaces": 1}


def test_vpc001_main_table_with_igw_makes_implicit_subnets_public() -> None:
    # 기본 VPC처럼 기본 라우팅 테이블에 IGW 경로가 있고 서브넷이 암묵적으로 연결된 경우
    tables = [route_table("rtb-main", main=True, igw=True)]
    finding = _vpc001(
        _network(route_tables=tables, interfaces=[eni("eni-1", subnet_id="subnet-priv")])
    )
    assert finding.status == Status.FAIL


def test_vpc001_ipv6_igw_route_is_public() -> None:
    tables = [
        route_table("rtb-main", main=True),
        route_table("rtb-6", subnets=("subnet-pub",), ipv6_igw=True),
    ]
    finding = _vpc001(
        _network(route_tables=tables, interfaces=[eni("eni-1", subnet_id="subnet-pub")])
    )
    assert finding.status == Status.FAIL


def test_vpc001_blackhole_igw_route_is_not_public() -> None:
    tables = [route_table("rtb-main", main=True, igw=True, igw_state="blackhole")]
    finding = _vpc001(
        _network(route_tables=tables, interfaces=[eni("eni-1", subnet_id="subnet-pub")])
    )
    assert finding.status == Status.PASS


def test_vpc001_not_applicable_without_interfaces() -> None:
    assert (
        _vpc001(_network(route_tables=MIXED_TABLES, interfaces=[])).status == Status.NOT_APPLICABLE
    )


def test_vpc001_error_when_route_tables_missing() -> None:
    network = _network(route_tables=[], interfaces=[eni("eni-1")], missing=("route_tables",))
    data = snapshot({REGION: network}, errors=(collect_error("ec2:DescribeRouteTables"),))
    [finding] = VPC001.evaluate(data, Settings())
    assert finding.status == Status.ERROR
    assert finding.resource == "account"


def test_vpc001_not_applicable_without_vpcs() -> None:
    [finding] = VPC001.evaluate(snapshot({REGION: region()}), Settings())
    assert finding.status == Status.NOT_APPLICABLE


# --- VPC-002 ---


def _vpc002(*interfaces: dict[str, Any], missing: tuple[str, ...] = ()) -> list[Any]:
    network = _network(route_tables=MIXED_TABLES, interfaces=list(interfaces), missing=missing)
    return VPC002.evaluate(snapshot({REGION: network}), Settings())


def test_vpc002_review_public_interface() -> None:
    [finding] = _vpc002(eni("eni-1", subnet_id="subnet-pub", public_ip="203.0.113.10"))
    assert finding.status == Status.REVIEW
    assert finding.resource == "eni-1"
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["public_ip"] == "203.0.113.10"
    assert finding.evidence["subnet_public"] is True


def test_vpc002_includes_requester_managed_rds() -> None:
    # 공개 RDS의 인터페이스도 RequesterManaged=true다. 제외하면 CA-08의 주 대상을 놓친다
    rds = eni(
        "eni-rds",
        public_ip="203.0.113.20",
        requester_managed=True,
        requester_id="amazon-rds",
        description="RDSNetworkInterface",
    )
    [finding] = _vpc002(rds)
    assert finding.status == Status.REVIEW


def test_vpc002_excludes_nat_and_load_balancers() -> None:
    findings = _vpc002(
        eni("eni-nat", public_ip="203.0.113.1", interface_type="nat_gateway"),
        eni("eni-nlb", public_ip="203.0.113.2", interface_type="network_load_balancer"),
        eni("eni-alb", public_ip="203.0.113.3", requester_id="amazon-elb", requester_managed=True),
    )
    [finding] = findings
    assert finding.status == Status.PASS
    assert finding.resource == "account"
    assert sorted(finding.evidence["excluded_interfaces"]) == ["eni-alb", "eni-nat", "eni-nlb"]


def test_vpc002_pass_when_no_public_interfaces() -> None:
    [finding] = _vpc002(eni("eni-1"))
    assert finding.status == Status.PASS
    assert finding.region == REGION


def test_vpc002_subnet_public_unknown_when_tables_missing() -> None:
    [finding] = _vpc002(eni("eni-1", public_ip="203.0.113.10"), missing=("route_tables",))
    assert finding.status == Status.REVIEW
    assert finding.evidence["subnet_public"] is None


def test_vpc002_error_when_interfaces_missing() -> None:
    network = _network(route_tables=MIXED_TABLES, interfaces=[], missing=("network_interfaces",))
    data = snapshot({REGION: network}, errors=(collect_error("ec2:DescribeNetworkInterfaces"),))
    [finding] = VPC002.evaluate(data, Settings())
    assert finding.status == Status.ERROR
