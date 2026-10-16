"""EC2 룰 공용 판별 함수. 모두 `ec2` 스냅샷 하나만 본다 (ADR-015).

실제 응답은 값이 비어 있는 키를 생략하므로 키 존재를 가정하지 않는다.
"""

from collections.abc import Iterator
from typing import Any

from kompass.models import Snapshot
from kompass.rules.base import errors_evidence

WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
_PORT_PROTOCOLS = frozenset({"tcp", "udp", "6", "17"})
_ALL_PROTOCOLS = "-1"
MAX_PORT = 65535

# 스냅샷 데이터 키 → 수집 오퍼레이션 (오류 기록 대조용)
OPERATIONS = {
    "security_groups": "ec2:DescribeSecurityGroups",
    "vpcs": "ec2:DescribeVpcs",
    "subnets": "ec2:DescribeSubnets",
    "route_tables": "ec2:DescribeRouteTables",
    "network_interfaces": "ec2:DescribeNetworkInterfaces",
    "flow_logs": "ec2:DescribeFlowLogs",
}


def regions(snapshot: Snapshot) -> Iterator[tuple[str, dict[str, Any]]]:
    yield from snapshot.data.get("regions", {}).items()


def region_errors(snapshot: Snapshot, region: str, kinds: tuple[str, ...]) -> list[dict[str, Any]]:
    """해당 리전에서 수집하지 못한 종류의 오류 기록 (evidence 형태)."""
    operations = {OPERATIONS[kind] for kind in kinds}
    return errors_evidence(
        [e for e in snapshot.errors if e.region == region and e.operation in operations]
    )


def missing_kinds(region_data: dict[str, Any], kinds: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(kind for kind in kinds if kind not in region_data)


# --- 보안그룹 규칙 ---


def open_cidrs(permission: dict[str, Any]) -> list[str]:
    """규칙에서 전체 개방(0.0.0.0/0, ::/0)에 해당하는 CIDR."""
    cidrs = [r.get("CidrIp") for r in permission.get("IpRanges", [])]
    cidrs += [r.get("CidrIpv6") for r in permission.get("Ipv6Ranges", [])]
    return sorted(c for c in cidrs if c in WORLD_CIDRS)


def _port_range(permission: dict[str, Any]) -> tuple[int, int] | None:
    """포트를 가진 규칙의 범위. 모든 프로토콜(-1)이면 전체 범위, ICMP 등이면 None."""
    protocol = str(permission.get("IpProtocol", ""))
    if protocol == _ALL_PROTOCOLS:
        return (0, MAX_PORT)
    if protocol not in _PORT_PROTOCOLS:
        return None
    return (int(permission.get("FromPort", 0)), int(permission.get("ToPort", MAX_PORT)))


def matched_ports(permission: dict[str, Any], ports: tuple[int, ...]) -> list[int]:
    """규칙이 포함하는 포트 목록 중 `ports`에 있는 것."""
    port_range = _port_range(permission)
    if port_range is None:
        return []
    low, high = port_range
    return sorted(p for p in ports if low <= p <= high)


def is_all_ports(permission: dict[str, Any]) -> bool:
    """모든 프로토콜이거나 포트 범위가 1 이하~65535다. 1~65535도 사실상 전체 개방이다."""
    port_range = _port_range(permission)
    return port_range is not None and port_range[0] <= 1 and port_range[1] >= MAX_PORT


def prefix_lists(group: dict[str, Any]) -> list[str]:
    """인바운드 규칙이 참조하는 접두사 목록 ID. 내용은 수집하지 않으므로 판정하지 않는다."""
    return sorted(
        {
            p["PrefixListId"]
            for rule in group.get("IpPermissions", [])
            for p in rule.get("PrefixListIds", [])
        }
    )


def attached_counts(region_data: dict[str, Any]) -> dict[str, int] | None:
    """보안그룹 ID → 연결된 네트워크 인터페이스 수. 인터페이스를 수집하지 못했으면 None."""
    interfaces = region_data.get("network_interfaces")
    if interfaces is None:
        return None
    counts: dict[str, int] = {}
    for interface in interfaces:
        for group in interface.get("Groups", []):
            counts[group["GroupId"]] = counts.get(group["GroupId"], 0) + 1
    return counts


# --- 퍼블릭 서브넷 판별 (RULES.md "VPC 공통") ---


def _routes_to_internet(table: dict[str, Any]) -> bool:
    for route in table.get("Routes", []):
        to_world = (
            route.get("DestinationCidrBlock") == "0.0.0.0/0"
            or route.get("DestinationIpv6CidrBlock") == "::/0"
        )
        via_igw = str(route.get("GatewayId", "")).startswith("igw-")
        if to_world and via_igw and route.get("State") != "blackhole":
            return True
    return False


class SubnetClassifier:
    """서브넷이 퍼블릭인지 판별한다. 명시적 연결이 없으면 VPC의 기본 라우팅 테이블을 쓴다."""

    def __init__(self, route_tables: list[dict[str, Any]]):
        self._by_subnet: dict[str, bool] = {}
        self._main_by_vpc: dict[str, bool] = {}
        for table in route_tables:
            public = _routes_to_internet(table)
            for association in table.get("Associations", []):
                if association.get("Main"):
                    self._main_by_vpc[table["VpcId"]] = public
                elif association.get("SubnetId"):
                    self._by_subnet[association["SubnetId"]] = public

    def is_public(self, subnet_id: str, vpc_id: str) -> bool | None:
        """판별할 수 없으면(연결도 기본 테이블도 없음) None."""
        if subnet_id in self._by_subnet:
            return self._by_subnet[subnet_id]
        return self._main_by_vpc.get(vpc_id)
