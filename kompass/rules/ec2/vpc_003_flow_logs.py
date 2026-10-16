"""VPC-003 VPC 흐름 로그 미설정 (KISA CA-14, docs/RULES.md).

VPC별로 네트워크 인터페이스가 모두 활성 흐름 로그로 기록되면 PASS. 흐름 로그는 VPC·서브넷·
인터페이스 어느 단위에 걸려 있어도 인정한다. 인터페이스가 없는 VPC는 NOT_APPLICABLE.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule
from kompass.rules.ec2 import _network as net

_REQUIRED = ("vpcs", "network_interfaces", "flow_logs")
_ACTIVE = "ACTIVE"


class Vpc003FlowLogs(BaseRule):
    id: ClassVar[str] = "VPC-003"
    service: ClassVar[str] = "ec2"
    title: ClassVar[str] = "VPC 흐름 로그 미설정"
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
                        f"흐름 로그 판정에 필요한 데이터를 수집하지 못함: {', '.join(missing)}",
                        {"errors": net.region_errors(snapshot, region, missing)},
                    )
                )
                continue
            if not data["vpcs"]:
                findings.append(
                    self._region(snapshot, region, Status.NOT_APPLICABLE, "VPC가 없음", {})
                )
                continue
            active = [f for f in data["flow_logs"] if f.get("FlowLogStatus") == _ACTIVE]
            findings.extend(
                self._judge(snapshot, region, v, data["network_interfaces"], active)
                for v in data["vpcs"]
            )
        return findings

    def _judge(
        self,
        snapshot: Snapshot,
        region: str,
        vpc: dict[str, Any],
        interfaces: list[dict[str, Any]],
        active: list[dict[str, Any]],
    ) -> Finding:
        vpc_id: str = vpc["VpcId"]
        members = [i for i in interfaces if i.get("VpcId") == vpc_id]
        subnets = {i.get("SubnetId") for i in members}
        ids = {i.get("NetworkInterfaceId") for i in members}
        logged = {f["ResourceId"] for f in active if f.get("ResourceId")}
        applied = [f for f in active if f.get("ResourceId") in {vpc_id, *subnets, *ids} - {None}]
        uncovered = [
            i
            for i in members
            if vpc_id not in logged
            and i.get("SubnetId") not in logged
            and i.get("NetworkInterfaceId") not in logged
        ]
        evidence: dict[str, Any] = {
            "is_default_vpc": vpc.get("IsDefault") is True,
            "interfaces": len(members),
            "uncovered_interfaces": len(uncovered),
            "flow_logs": [
                {
                    "flow_log_id": f.get("FlowLogId"),
                    "resource_id": f.get("ResourceId"),
                    "traffic_type": f.get("TrafficType"),
                    "destination_type": f.get("LogDestinationType"),
                    "deliver_logs_status": f.get("DeliverLogsStatus"),
                }
                for f in applied
            ],
        }
        if not members:
            status, message = Status.NOT_APPLICABLE, f"VPC에 네트워크 인터페이스가 없음: {vpc_id}"
        elif uncovered:
            status = Status.FAIL
            message = f"흐름 로그로 기록되지 않는 네트워크 인터페이스 {len(uncovered)}개: {vpc_id}"
        else:
            status, message = (
                Status.PASS,
                f"모든 네트워크 인터페이스가 흐름 로그로 기록됨: {vpc_id}",
            )
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
