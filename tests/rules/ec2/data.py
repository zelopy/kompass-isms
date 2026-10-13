"""EC2 룰 테스트용 가짜 데이터. 실습 계정에서 확인한 실제 응답 형태를 따른다.

- 값이 비어 있는 키는 생략된다 (예: 태그 없는 VPC의 `Tags`)
- 기본 라우팅 테이블을 쓰는 서브넷은 `Associations`에 나오지 않는다
"""

from datetime import UTC, datetime
from typing import Any

from kompass.models import CollectError, Snapshot

T0 = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
WORLD4 = "0.0.0.0/0"
WORLD6 = "::/0"


def permission(
    protocol: str = "tcp",
    from_port: int | None = 22,
    to_port: int | None = 22,
    cidrs: tuple[str, ...] = (WORLD4,),
    groups: tuple[str, ...] = (),
    prefix_lists: tuple[str, ...] = (),
) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "IpProtocol": protocol,
        "IpRanges": [{"CidrIp": c} for c in cidrs if ":" not in c],
        "Ipv6Ranges": [{"CidrIpv6": c} for c in cidrs if ":" in c],
        "PrefixListIds": [{"PrefixListId": p} for p in prefix_lists],
        "UserIdGroupPairs": [{"GroupId": g, "UserId": ACCOUNT} for g in groups],
    }
    if protocol != "-1":
        rule["FromPort"] = from_port
        rule["ToPort"] = to_port
    return rule


def security_group(
    group_id: str,
    name: str = "app",
    vpc_id: str = "vpc-1",
    ingress: list[dict[str, Any]] | None = None,
    egress: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "GroupId": group_id,
        "GroupName": name,
        "Description": "d",
        "VpcId": vpc_id,
        "OwnerId": ACCOUNT,
        "IpPermissions": ingress or [],
        "IpPermissionsEgress": egress or [],
    }


def vpc(vpc_id: str, default: bool = False) -> dict[str, Any]:
    return {"VpcId": vpc_id, "CidrBlock": "10.0.0.0/16", "IsDefault": default, "State": "available"}


def subnet(subnet_id: str, vpc_id: str = "vpc-1") -> dict[str, Any]:
    return {"SubnetId": subnet_id, "VpcId": vpc_id, "CidrBlock": "10.0.1.0/24"}


def route_table(
    table_id: str,
    vpc_id: str = "vpc-1",
    *,
    main: bool = False,
    subnets: tuple[str, ...] = (),
    igw: bool = False,
    igw_state: str = "active",
    ipv6_igw: bool = False,
) -> dict[str, Any]:
    routes: list[dict[str, Any]] = [
        {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"}
    ]
    if igw:
        routes.append({"DestinationCidrBlock": WORLD4, "GatewayId": "igw-1", "State": igw_state})
    if ipv6_igw:
        routes.append({"DestinationIpv6CidrBlock": WORLD6, "GatewayId": "igw-1", "State": "active"})
    associations: list[dict[str, Any]] = [{"Main": False, "SubnetId": s} for s in subnets]
    if main:
        associations.append({"Main": True})
    return {
        "RouteTableId": table_id,
        "VpcId": vpc_id,
        "Routes": routes,
        "Associations": associations,
    }


def eni(
    eni_id: str,
    subnet_id: str = "subnet-1",
    vpc_id: str = "vpc-1",
    groups: tuple[str, ...] = (),
    *,
    public_ip: str | None = None,
    interface_type: str = "interface",
    requester_id: str | None = None,
    requester_managed: bool = False,
    description: str = "",
    instance_id: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "NetworkInterfaceId": eni_id,
        "SubnetId": subnet_id,
        "VpcId": vpc_id,
        "Groups": [{"GroupId": g, "GroupName": g} for g in groups],
        "InterfaceType": interface_type,
        "RequesterManaged": requester_managed,
        "Description": description,
    }
    if public_ip:
        item["Association"] = {"PublicIp": public_ip}
    if requester_id:
        item["RequesterId"] = requester_id
    if instance_id:
        item["Attachment"] = {"InstanceId": instance_id}
    return item


def snapshot(regions: dict[str, dict[str, Any]], errors: tuple[CollectError, ...] = ()) -> Snapshot:
    return Snapshot(
        service="ec2",
        account_id=ACCOUNT,
        regions=tuple(regions),
        collected_at=T0,
        data={"regions": regions},
        errors=errors,
    )


def region(
    *,
    security_groups: list[dict[str, Any]] | None = None,
    vpcs: list[dict[str, Any]] | None = None,
    subnets: list[dict[str, Any]] | None = None,
    route_tables: list[dict[str, Any]] | None = None,
    network_interfaces: list[dict[str, Any]] | None = None,
    missing: tuple[str, ...] = (),
) -> dict[str, Any]:
    data = {
        "security_groups": security_groups or [],
        "vpcs": vpcs or [],
        "subnets": subnets or [],
        "route_tables": route_tables or [],
        "network_interfaces": network_interfaces or [],
    }
    for kind in missing:
        del data[kind]
    return data


def collect_error(operation: str, region_name: str = REGION) -> CollectError:
    return CollectError(
        operation=operation, region=region_name, error_code="UnauthorizedOperation", message="no"
    )
