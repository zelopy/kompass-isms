"""VPC-001 공개·내부 서브넷 미분리 (KISA CA-07, docs/RULES.md).

VPC별로 네트워크 인터페이스가 있는 서브넷을 모아, 모두 퍼블릭이면 FAIL, 프라이빗 서브넷에
리소스가 하나라도 있으면 PASS. 인터페이스가 없는 VPC는 NOT_APPLICABLE.
판별에 필요한 서브넷의 퍼블릭 여부를 알 수 없으면 FAIL로 단정하지 않고 ERROR.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule
from kompass.rules.ec2 import _network as net

_REQUIRED = ("vpcs", "route_tables", "network_interfaces")


class Vpc001SubnetSeparation(BaseRule):
    id: ClassVar[str] = "VPC-001"
    service: ClassVar[str] = "ec2"
    title: ClassVar[str] = "공개·내부 서브넷 미분리"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        for region, data in net.regions(snapshot):
            missing = net.missing_kinds(data, _REQUIRED)
            if missing:
                findings.append(
                    self._region(
                        snapshot,
                        region,
                        Status.ERROR,
                        f"VPC 판정에 필요한 데이터를 수집하지 못했다: {', '.join(missing)}",
                        {"errors": net.region_errors(snapshot, region, missing)},
                    )
                )
                continue
            if not data["vpcs"]:
                findings.append(
                    self._region(snapshot, region, Status.NOT_APPLICABLE, "VPC가 없다", {})
                )
                continue
            classifier = net.SubnetClassifier(data["route_tables"])
            findings.extend(
                self._judge(snapshot, region, vpc, data["network_interfaces"], classifier)
                for vpc in data["vpcs"]
            )
        return findings

    def _judge(
        self,
        snapshot: Snapshot,
        region: str,
        vpc: dict[str, Any],
        interfaces: list[dict[str, Any]],
        classifier: net.SubnetClassifier,
    ) -> Finding:
        vpc_id: str = vpc["VpcId"]
        counts: dict[str, int] = {}
        for interface in interfaces:
            if interface.get("VpcId") == vpc_id and interface.get("SubnetId"):
                counts[interface["SubnetId"]] = counts.get(interface["SubnetId"], 0) + 1
        subnets = {
            subnet_id: {"public": classifier.is_public(subnet_id, vpc_id), "interfaces": count}
            for subnet_id, count in sorted(counts.items())
        }
        evidence: dict[str, Any] = {
            "is_default_vpc": vpc.get("IsDefault") is True,
            "subnets": subnets,
        }

        publics = [s["public"] for s in subnets.values()]
        if not subnets:
            status, message = Status.NOT_APPLICABLE, f"VPC에 네트워크 인터페이스가 없다: {vpc_id}"
        elif False in publics:
            status, message = Status.PASS, f"프라이빗 서브넷에 리소스가 있다: {vpc_id}"
        elif None in publics:
            status = Status.ERROR
            message = f"서브넷의 라우팅을 판별하지 못했다: {vpc_id}"
        else:
            status, message = Status.FAIL, f"리소스가 퍼블릭 서브넷에만 있다: {vpc_id}"
        return self.finding(
            snapshot,
            resource=vpc_id,
            region=region,
            status=status,
            message=message,
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
