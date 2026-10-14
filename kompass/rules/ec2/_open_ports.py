"""SG-001~003 공통: 전체 개방된 인바운드 규칙을 보안그룹별로 판정한다."""

from typing import Any

from kompass.config import Settings
from kompass.models import Finding, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule
from kompass.rules.ec2 import _network as net


class OpenPortRule(BaseRule):
    """하위 룰은 `_matches`로 "이 규칙이 위반인가"만 정한다."""

    service = "ec2"
    _violation: str  # FAIL 메시지에 쓸 위반 설명

    def _matches(self, permission: dict[str, Any], settings: Settings) -> list[int] | bool:
        """위반이면 포함된 포트 목록(또는 True), 아니면 빈 목록(또는 False)."""
        raise NotImplementedError

    def _extra_evidence(self, settings: Settings) -> dict[str, Any]:
        return {}

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        for region, data in net.regions(snapshot):
            groups = data.get("security_groups")
            if groups is None:
                findings.append(
                    self._region_finding(
                        snapshot,
                        region,
                        Status.ERROR,
                        "보안그룹 목록을 수집하지 못함",
                        {"errors": net.region_errors(snapshot, region, ("security_groups",))},
                    )
                )
                continue
            if not groups:
                findings.append(
                    self._region_finding(
                        snapshot, region, Status.NOT_APPLICABLE, "보안그룹이 없음", {}
                    )
                )
                continue
            attached = net.attached_counts(data)
            findings.extend(
                self._group_finding(snapshot, region, g, attached, settings) for g in groups
            )
        return findings

    def _group_finding(
        self,
        snapshot: Snapshot,
        region: str,
        group: dict[str, Any],
        attached: dict[str, int] | None,
        settings: Settings,
    ) -> Finding:
        open_rules: list[dict[str, Any]] = []
        for permission in group.get("IpPermissions", []):
            cidrs = net.open_cidrs(permission)
            if not cidrs:
                continue
            matched = self._matches(permission, settings)
            if not matched:
                continue
            entry: dict[str, Any] = {
                "protocol": permission.get("IpProtocol"),
                "from_port": permission.get("FromPort"),
                "to_port": permission.get("ToPort"),
                "cidrs": cidrs,
            }
            if isinstance(matched, list):
                entry["matched_ports"] = matched
            open_rules.append(entry)

        group_id: str = group["GroupId"]
        evidence: dict[str, Any] = {
            "group_name": group.get("GroupName"),
            "vpc_id": group.get("VpcId"),
            "open_rules": open_rules,
            "prefix_lists": net.prefix_lists(group),
            "attached_interfaces": None if attached is None else attached.get(group_id, 0),
            **self._extra_evidence(settings),
        }
        if open_rules:
            status, message = Status.FAIL, f"{self._violation}: {group_id}"
        else:
            status, message = Status.PASS, f"{self._violation} 규칙이 없음: {group_id}"
        return self.finding(
            snapshot,
            resource=group_id,
            region=region,
            status=status,
            message=message,
            evidence=evidence,
        )

    def _region_finding(
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
