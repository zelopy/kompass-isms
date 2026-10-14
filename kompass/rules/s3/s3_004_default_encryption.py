"""S3-004 기본 암호화 설정 (KISA 매핑 없음, docs/RULES.md).

2023년 1월부터 모든 버킷에 SSE-S3가 기본 적용되므로 기본 설정에서는 사실상 항상 PASS이며,
암호화 방식을 증적으로 남기는 것이 주목적이다. `s3.require_kms`면 SSE-KMS일 때만 PASS.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.s3._buckets import MISSING, BucketRule

_KMS_ALGORITHMS = frozenset({"aws:kms", "aws:kms:dsse"})


class S3004DefaultEncryption(BucketRule):
    id: ClassVar[str] = "S3-004"
    title: ClassVar[str] = "기본 암호화 설정"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def judge(
        self,
        snapshot: Snapshot,
        settings: Settings,
        name: str,
        region: str | None,
        details: dict[str, Any],
    ) -> Finding:
        config = details.get("encryption", MISSING)
        if config is MISSING:
            return self.bucket_error(
                snapshot, name, region, "s3:GetBucketEncryption", "기본 암호화 설정"
            )
        require_kms = settings.s3.require_kms
        rules = (config or {}).get("Rules", [])
        algorithms = sorted(
            {
                rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                for rule in rules
                if rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            }
        )
        evidence: dict[str, Any] = {"algorithms": algorithms, "require_kms": require_kms}
        if not algorithms:
            status, message = Status.FAIL, f"기본 암호화가 설정되지 않음: {name}"
        elif require_kms and not _KMS_ALGORITHMS & set(algorithms):
            status, message = Status.FAIL, f"기본 암호화가 SSE-KMS가 아님: {name}"
        else:
            status = Status.PASS
            message = f"기본 암호화가 설정되어 있음 ({', '.join(algorithms)}): {name}"
        return self.bucket_finding(snapshot, name, region, status, message, evidence)
