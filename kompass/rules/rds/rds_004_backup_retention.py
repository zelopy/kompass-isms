"""RDS-004 자동 백업 보존 기간 부족 (KISA CA-18, docs/RULES.md)."""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Severity, Status
from kompass.rules.rds._rds import RdsRule, Target


class Rds004BackupRetention(RdsRule):
    id: ClassVar[str] = "RDS-004"
    title: ClassVar[str] = "자동 백업 보존 기간 부족"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def _assess(self, target: Target, settings: Settings) -> tuple[Status, str, dict[str, Any]]:
        days = target.item.get("BackupRetentionPeriod")
        minimum = settings.rds.min_backup_retention_days
        evidence: dict[str, Any] = {
            "backup_retention_days": days,
            "min_backup_retention_days": minimum,
        }
        source = target.item.get("ReadReplicaSourceDBInstanceIdentifier")
        if source:
            evidence["read_replica_source"] = source
            return Status.NOT_APPLICABLE, "읽기 전용 복제본은 원본의 백업을 따름", evidence
        if isinstance(days, bool) or not isinstance(days, int):
            return Status.ERROR, f"백업 보존 기간을 확인할 수 없음: {target.resource}", evidence
        if days >= minimum:
            return Status.PASS, f"자동 백업 보존 기간 {days}일", evidence
        if days == 0:
            return Status.FAIL, f"자동 백업 꺼짐: {target.resource}", evidence
        return Status.FAIL, f"자동 백업 보존 기간 {days}일 (기준 {minimum}일 미만)", evidence
