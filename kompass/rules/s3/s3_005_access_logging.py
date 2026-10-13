"""S3-005 서버 액세스 로깅 미설정 (KISA CA-16, docs/RULES.md).

`s3.exclude_log_target_buckets`면 다른 버킷의 로그를 받는 버킷은 N/A로 제외한다 (기본 꺼짐).
CloudTrail S3 데이터 이벤트로 대신하는 경우도 이 룰에서는 FAIL이다 (ADR-015).
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.s3._buckets import MISSING, BucketRule


def _log_sources(snapshot: Snapshot) -> dict[str, list[str]]:
    """로그를 받는 버킷 → 로그를 보내는 버킷 목록."""
    sources: dict[str, list[str]] = {}
    for name, details in snapshot.data.get("bucket_details", {}).items():
        logging = details.get("logging")
        if isinstance(logging, dict) and logging.get("TargetBucket"):
            sources.setdefault(logging["TargetBucket"], []).append(name)
    return {target: sorted(names) for target, names in sources.items()}


class S3005AccessLogging(BucketRule):
    id: ClassVar[str] = "S3-005"
    title: ClassVar[str] = "서버 액세스 로깅 미설정"
    severity: ClassVar[Severity] = Severity.LOW

    def judge(
        self,
        snapshot: Snapshot,
        settings: Settings,
        name: str,
        region: str | None,
        details: dict[str, Any],
    ) -> Finding:
        logging = details.get("logging", MISSING)
        if logging is MISSING:
            return self.bucket_error(
                snapshot, name, region, "s3:GetBucketLogging", "서버 액세스 로깅 설정"
            )
        log_target_for = _log_sources(snapshot).get(name, [])
        evidence: dict[str, Any] = {
            "target_bucket": logging.get("TargetBucket") if logging else None,
            "target_prefix": logging.get("TargetPrefix") if logging else None,
            "log_target_for": log_target_for,
        }
        if log_target_for and settings.s3.exclude_log_target_buckets:
            status, message = Status.NOT_APPLICABLE, f"로그 저장 버킷이라 제외한다: {name}"
        elif logging:
            status, message = Status.PASS, f"서버 액세스 로깅이 켜져 있다: {name}"
        else:
            status, message = Status.FAIL, f"서버 액세스 로깅이 꺼져 있다: {name}"
        return self.bucket_finding(snapshot, name, region, status, message, evidence)
