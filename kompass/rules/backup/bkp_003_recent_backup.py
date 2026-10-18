"""BKP-003 AWS Backup 최근 백업 없음 (KISA CA-18, docs/RULES.md).

AWS Backup으로 백업된 리소스마다 마지막 백업이 `backup.max_backup_age_days` 이내인지 본다.
백업된 리소스가 없는데 리소스 선택이 있는 계획이 있으면 백업이 수행되지 않은 것이다 (ADR-054).
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.backup._backup import (
    PLAN_OPERATIONS,
    PROTECTED_OPERATIONS,
    SELECTION_OPERATIONS,
    BackupRule,
    plan_name,
    plan_selections,
    region_errors,
)
from kompass.rules.base import parse_aws_datetime


class Bkp003RecentBackup(BackupRule):
    id: ClassVar[str] = "BKP-003"
    title: ClassVar[str] = "AWS Backup 최근 백업 없음"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        for region, data in snapshot.data.get("regions", {}).items():
            resources = data.get("protected_resources")
            if resources is None:
                findings.append(
                    self.region_finding(
                        snapshot,
                        region,
                        Status.ERROR,
                        "AWS Backup 보호 리소스 목록을 수집하지 못함",
                        {"errors": region_errors(snapshot, region, PROTECTED_OPERATIONS)},
                    )
                )
            elif not resources:
                findings.append(self._nothing_backed_up(snapshot, region, data.get("plans")))
            else:
                findings.extend(self._judge(snapshot, settings, region, r) for r in resources)
        return findings

    def _nothing_backed_up(
        self, snapshot: Snapshot, region: str, plans: list[dict[str, Any]] | None
    ) -> Finding:
        if plans is None:
            return self.region_finding(
                snapshot,
                region,
                Status.ERROR,
                "백업된 리소스가 없으나 백업 계획 목록을 수집하지 못해 판정할 수 없음",
                {"errors": region_errors(snapshot, region, PLAN_OPERATIONS)},
            )
        selected = [plan_name(p) for p in plans if plan_selections(p)]
        if selected:
            return self.region_finding(
                snapshot,
                region,
                Status.FAIL,
                "백업 대상이 지정된 계획은 있으나 백업된 리소스가 없음",
                {"plans_with_selections": selected},
            )
        if any(plan_selections(p) is None for p in plans):
            return self.region_finding(
                snapshot,
                region,
                Status.ERROR,
                "백업된 리소스가 없으나 백업 계획의 백업 대상을 수집하지 못해 판정할 수 없음",
                {"errors": region_errors(snapshot, region, SELECTION_OPERATIONS)},
            )
        return self.region_finding(
            snapshot,
            region,
            Status.NOT_APPLICABLE,
            "AWS Backup으로 백업된 리소스와 백업 대상이 지정된 계획이 없음",
            {"plans": [plan_name(p) for p in plans]},
        )

    def _judge(
        self, snapshot: Snapshot, settings: Settings, region: str, resource: dict[str, Any]
    ) -> Finding:
        arn = resource["ResourceArn"]
        limit = settings.backup.max_backup_age_days
        last = parse_aws_datetime(resource.get("LastBackupTime"))
        days = None if last is None else (snapshot.collected_at - last).days
        evidence = {
            "resource_type": resource.get("ResourceType"),
            "resource_name": resource.get("ResourceName"),
            "last_backup_time": resource.get("LastBackupTime"),
            "days_since_backup": days,
            "max_backup_age_days": limit,
            "last_backup_vault": resource.get("LastBackupVaultArn"),
        }
        if days is None:
            status, message = Status.ERROR, f"마지막 백업 시각을 확인할 수 없음: {arn}"
        elif days > limit:
            status, message = Status.FAIL, f"마지막 백업이 {days}일 전임: {arn}"
        else:
            status, message = Status.PASS, f"최근 {limit}일 안에 백업됨: {arn}"
        return self.finding(
            snapshot,
            resource=arn,
            region=region,
            status=status,
            message=message,
            evidence=evidence,
        )
