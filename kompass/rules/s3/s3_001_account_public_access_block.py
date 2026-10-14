"""S3-001 계정 수준 퍼블릭 액세스 차단 미설정 (KISA CA-10, docs/RULES.md)."""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence, errors_for
from kompass.rules.s3._buckets import BLOCK_SETTINGS, MISSING, account_block, all_blocked


class S3001AccountPublicAccessBlock(BaseRule):
    id: ClassVar[str] = "S3-001"
    service: ClassVar[str] = "s3"
    title: ClassVar[str] = "계정 수준 퍼블릭 액세스 차단 미설정"
    severity: ClassVar[Severity] = Severity.HIGH

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        config = account_block(snapshot)
        evidence: dict[str, Any]
        if config is MISSING:
            errors = errors_for(snapshot, "s3control:GetPublicAccessBlock")
            status, message = Status.ERROR, "계정 수준 퍼블릭 액세스 차단 설정을 수집하지 못함"
            evidence = {"errors": errors_evidence(errors)}
        elif all_blocked(config):
            status, message = Status.PASS, "계정 수준 퍼블릭 액세스 차단 4개 설정이 모두 켜져 있음"
            evidence = {"public_access_block": config}
        else:
            disabled = (
                list(BLOCK_SETTINGS)
                if config is None
                else [key for key in BLOCK_SETTINGS if config.get(key) is not True]
            )
            status = Status.FAIL
            message = (
                "계정 수준 퍼블릭 액세스 차단이 설정되지 않음"
                if config is None
                else f"계정 수준 퍼블릭 액세스 차단 중 꺼진 설정: {', '.join(disabled)}"
            )
            evidence = {"public_access_block": config, "disabled_settings": disabled}
        return [
            self.finding(
                snapshot,
                resource=ACCOUNT_RESOURCE,
                region=None,
                status=status,
                message=message,
                evidence=evidence,
            )
        ]
