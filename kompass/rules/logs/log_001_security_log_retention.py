"""LOG-001 보안 로그 보존 기간 부족 (KISA CA-17, docs/RULES.md).

리전마다 보안 로그 그룹만 판정한다: 같은 계정·리전의 CloudTrail 추적이 보내는 그룹, VPC 흐름
로그가 보내는 그룹, 이름이 `logs.security_log_group_prefixes`로 시작하는 그룹. 보존 기간이
`logs.min_retention_days` 미만이면 FAIL, 설정되지 않았으면(영구 보관) PASS. 추적·흐름 로그가
가리키는 그룹이 없으면 로그가 저장되지 않으므로 FAIL.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence


def _parse_group_arn(arn: str) -> tuple[str, str, str] | None:
    """`arn:aws:logs:<리전>:<계정>:log-group:<이름>[:*]` → (리전, 계정, 이름)."""
    parts = arn.split(":")
    if len(parts) < 7 or parts[2] != "logs" or parts[5] != "log-group":
        return None
    name = ":".join(parts[6:])
    return parts[3], parts[4], name.removesuffix(":*")


class Log001SecurityLogRetention(BaseRule):
    id: ClassVar[str] = "LOG-001"
    service: ClassVar[str] = "logs"
    title: ClassVar[str] = "보안 로그 보존 기간 부족"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        trails = snapshot.data.get("trail_log_groups")
        findings: list[Finding] = []
        for region, data in snapshot.data.get("regions", {}).items():
            missing = [k for k in ("log_groups", "flow_log_groups") if k not in data]
            if trails is None or missing:
                findings.append(self._error(snapshot, region))
                continue
            findings.extend(self._region(snapshot, region, data, trails, settings))
        return findings

    def _region(
        self,
        snapshot: Snapshot,
        region: str,
        data: dict[str, Any],
        trails: list[dict[str, Any]],
        settings: Settings,
    ) -> list[Finding]:
        sources: dict[str, list[dict[str, Any]]] = {}
        for trail in trails:
            parsed = _parse_group_arn(trail.get("log_group_arn", ""))
            if parsed and parsed[0] == region and parsed[1] == snapshot.account_id:
                sources.setdefault(parsed[2], []).append(
                    {"type": "cloudtrail", "trail": trail.get("trail")}
                )
        for flow in data["flow_log_groups"]:
            sources.setdefault(flow["log_group"], []).append(
                {"type": "flow_log", "flow_log_id": flow.get("flow_log_id")}
            )
        groups = {g["logGroupName"]: g for g in data["log_groups"]}
        for name in groups:
            prefix = next(
                (p for p in settings.logs.security_log_group_prefixes if name.startswith(p)), None
            )
            if prefix is not None:
                sources.setdefault(name, []).append({"type": "prefix", "prefix": prefix})

        if not sources:
            return [
                self._finding(
                    snapshot,
                    ACCOUNT_RESOURCE,
                    region,
                    Status.NOT_APPLICABLE,
                    "보안 로그로 확인되는 로그 그룹이 없음",
                    {"log_groups": len(groups)},
                )
            ]
        minimum = settings.logs.min_retention_days
        return [
            self._judge(snapshot, region, name, groups.get(name), sources[name], minimum)
            for name in sorted(sources)
        ]

    def _judge(
        self,
        snapshot: Snapshot,
        region: str,
        name: str,
        group: dict[str, Any] | None,
        sources: list[dict[str, Any]],
        minimum: int,
    ) -> Finding:
        evidence: dict[str, Any] = {"sources": sources, "min_retention_days": minimum}
        if group is None:
            evidence["retention_days"] = None
            message = f"보안 로그를 보내는 로그 그룹이 없음: {name}"
            return self._finding(snapshot, name, region, Status.FAIL, message, evidence)
        days = group.get("retentionInDays")
        evidence["retention_days"] = days
        if days is None:
            message = f"보존 기간 미설정(영구 보관): {name}"
            return self._finding(snapshot, name, region, Status.PASS, message, evidence)
        if days < minimum:
            message = f"보존 기간 {days}일 (기준 {minimum}일 미만): {name}"
            return self._finding(snapshot, name, region, Status.FAIL, message, evidence)
        message = f"보존 기간 {days}일: {name}"
        return self._finding(snapshot, name, region, Status.PASS, message, evidence)

    def _error(self, snapshot: Snapshot, region: str) -> Finding:
        operations = {"logs:DescribeLogGroups", "ec2:DescribeFlowLogs", "cloudtrail:DescribeTrails"}
        errors = [
            e
            for e in snapshot.errors
            if e.operation in operations
            and (e.region == region or e.operation == "cloudtrail:DescribeTrails")
        ]
        return self._finding(
            snapshot,
            ACCOUNT_RESOURCE,
            region,
            Status.ERROR,
            "보안 로그 판정에 필요한 데이터를 수집하지 못함",
            {"errors": errors_evidence(errors)},
        )

    def _finding(
        self,
        snapshot: Snapshot,
        resource: str,
        region: str,
        status: Status,
        message: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return self.finding(
            snapshot,
            resource=resource,
            region=region,
            status=status,
            message=message,
            evidence=evidence,
        )
