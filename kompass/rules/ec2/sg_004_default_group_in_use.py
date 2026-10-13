"""SG-004 사용 중인 기본 보안그룹에 규칙 존재 (KISA 매핑 없음, ADR-018, docs/RULES.md).

이름이 `default`인 보안그룹에 규칙이 있고 네트워크 인터페이스가 연결되어 있으면 FAIL.
쓰지 않는 기본 보안그룹은 규칙이 있어도 PASS다. 규칙이 있는데 연결 여부를 모르면 ERROR.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule
from kompass.rules.ec2 import _network as net

_DEFAULT_GROUP_NAME = "default"


class Sg004DefaultGroupInUse(BaseRule):
    id: ClassVar[str] = "SG-004"
    service: ClassVar[str] = "ec2"
    title: ClassVar[str] = "사용 중인 기본 보안그룹에 규칙 존재"
    severity: ClassVar[Severity] = Severity.LOW

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        for region, data in net.regions(snapshot):
            groups = data.get("security_groups")
            if groups is None:
                findings.append(
                    self._region(
                        snapshot,
                        region,
                        Status.ERROR,
                        "보안그룹 목록을 수집하지 못했다",
                        {"errors": net.region_errors(snapshot, region, ("security_groups",))},
                    )
                )
                continue
            defaults = [g for g in groups if g.get("GroupName") == _DEFAULT_GROUP_NAME]
            if not defaults:
                findings.append(
                    self._region(
                        snapshot, region, Status.NOT_APPLICABLE, "기본 보안그룹이 없다", {}
                    )
                )
                continue
            attached = net.attached_counts(data)
            findings.extend(self._judge(snapshot, region, g, attached) for g in defaults)
        return findings

    def _judge(
        self,
        snapshot: Snapshot,
        region: str,
        group: dict[str, Any],
        attached: dict[str, int] | None,
    ) -> Finding:
        group_id: str = group["GroupId"]
        has_rules = bool(group.get("IpPermissions")) or bool(group.get("IpPermissionsEgress"))
        count = None if attached is None else attached.get(group_id, 0)
        evidence: dict[str, Any] = {
            "vpc_id": group.get("VpcId"),
            "has_rules": has_rules,
            "ingress_rules": len(group.get("IpPermissions", [])),
            "egress_rules": len(group.get("IpPermissionsEgress", [])),
            "attached_interfaces": count,
        }
        if not has_rules:
            status, message = Status.PASS, f"기본 보안그룹에 규칙이 없다: {group_id}"
        elif count is None:
            evidence["errors"] = net.region_errors(snapshot, region, ("network_interfaces",))
            status = Status.ERROR
            message = f"기본 보안그룹의 사용 여부를 확인하지 못했다: {group_id}"
        elif count > 0:
            status, message = Status.FAIL, f"사용 중인 기본 보안그룹에 규칙이 있다: {group_id}"
        else:
            status, message = (
                Status.PASS,
                f"기본 보안그룹에 규칙이 있지만 사용하지 않는다: {group_id}",
            )
        return self.finding(
            snapshot,
            resource=group_id,
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
