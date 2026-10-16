"""RDS-001 데이터베이스 스토리지 암호화 미적용 (KISA CA-11, docs/RULES.md)."""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Severity, Status
from kompass.rules.rds._rds import RdsRule, Target


class Rds001StorageEncryption(RdsRule):
    id: ClassVar[str] = "RDS-001"
    title: ClassVar[str] = "데이터베이스 스토리지 암호화 미적용"
    severity: ClassVar[Severity] = Severity.HIGH

    def _assess(self, target: Target, settings: Settings) -> tuple[Status, str, dict[str, Any]]:
        encrypted = target.item.get("StorageEncrypted")
        evidence = {"storage_encrypted": encrypted, "kms_key_id": target.item.get("KmsKeyId")}
        if not isinstance(encrypted, bool):
            return (
                Status.ERROR,
                f"스토리지 암호화 여부를 확인할 수 없음: {target.resource}",
                evidence,
            )
        if encrypted:
            return Status.PASS, "스토리지 암호화 적용됨", evidence
        return Status.FAIL, f"스토리지 암호화 미적용: {target.resource}", evidence
