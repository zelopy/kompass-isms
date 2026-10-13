"""VPC-002 공인 IP가 할당된 네트워크 인터페이스 (KISA CA-08, docs/RULES.md).

공인 IP가 있는 인터페이스마다 REVIEW. 내부용 리소스인지는 사람이 판단한다.
공개가 목적인 NAT 게이트웨이와 로드 밸런서만 제외한다. `RequesterManaged` 전체를 제외하지
않는 이유는 공개 RDS 같은 AWS 관리형 리소스가 CA-08의 주요 점검 대상이기 때문이다.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule
from kompass.rules.ec2 import _network as net

_EXCLUDED_TYPES = frozenset({"nat_gateway", "network_load_balancer", "gateway_load_balancer"})
_ELB_REQUESTER = "amazon-elb"


def _excluded(interface: dict[str, Any]) -> bool:
    return (
        interface.get("InterfaceType") in _EXCLUDED_TYPES
        or interface.get("RequesterId") == _ELB_REQUESTER
    )


class Vpc002PublicIpInterface(BaseRule):
    id: ClassVar[str] = "VPC-002"
    service: ClassVar[str] = "ec2"
    title: ClassVar[str] = "공인 IP가 할당된 네트워크 인터페이스"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        for region, data in net.regions(snapshot):
            interfaces = data.get("network_interfaces")
            if interfaces is None:
                findings.append(
                    self._region(
                        snapshot,
                        region,
                        Status.ERROR,
                        "네트워크 인터페이스 목록을 수집하지 못했다",
                        {"errors": net.region_errors(snapshot, region, ("network_interfaces",))},
                    )
                )
                continue
            public = [i for i in interfaces if i.get("Association", {}).get("PublicIp")]
            excluded = sorted(i["NetworkInterfaceId"] for i in public if _excluded(i))
            reviewed = [i for i in public if not _excluded(i)]
            if not reviewed:
                findings.append(
                    self._region(
                        snapshot,
                        region,
                        Status.PASS,
                        "검토 대상인 공인 IP 인터페이스가 없다",
                        {"excluded_interfaces": excluded},
                    )
                )
                continue
            route_tables = data.get("route_tables")
            classifier = None if route_tables is None else net.SubnetClassifier(route_tables)
            findings.extend(self._review(snapshot, region, i, classifier) for i in reviewed)
        return findings

    def _review(
        self,
        snapshot: Snapshot,
        region: str,
        interface: dict[str, Any],
        classifier: net.SubnetClassifier | None,
    ) -> Finding:
        interface_id: str = interface["NetworkInterfaceId"]
        subnet_public = (
            None
            if classifier is None
            else classifier.is_public(interface.get("SubnetId", ""), interface.get("VpcId", ""))
        )
        evidence: dict[str, Any] = {
            "public_ip": interface["Association"]["PublicIp"],
            "interface_type": interface.get("InterfaceType"),
            "requester_id": interface.get("RequesterId"),
            "requester_managed": interface.get("RequesterManaged") is True,
            "description": interface.get("Description"),
            "instance_id": interface.get("Attachment", {}).get("InstanceId"),
            "vpc_id": interface.get("VpcId"),
            "subnet_id": interface.get("SubnetId"),
            "subnet_public": subnet_public,
            "security_groups": [g["GroupId"] for g in interface.get("Groups", [])],
        }
        return self.finding(
            snapshot,
            resource=interface_id,
            region=region,
            status=Status.REVIEW,
            message=f"공인 IP가 할당된 네트워크 인터페이스: {interface_id}",
            evidence=evidence,
        )

    def _region(
        self,
        snapshot: Snapshot,
        region: str,
        status: Status,
        message: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return self.finding(
            snapshot,
            resource=ACCOUNT_RESOURCE,
            region=region,
            status=status,
            message=message,
            evidence=evidence,
        )
