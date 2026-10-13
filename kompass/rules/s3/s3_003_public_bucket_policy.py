"""S3-003 버킷 정책에 의한 퍼블릭 노출 (KISA CA-10, docs/RULES.md).

`PolicyStatus.IsPublic`은 정책 문서만 평가한다. 퍼블릭 액세스 차단으로 실제 노출이 막혀 있어도
공개 정책이 있으면 FAIL이고, 막고 있는 `RestrictPublicBuckets` 값을 evidence에 남긴다
(공통 원칙 "설정이 존재하면 FAIL", 실습 계정 확인).
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.s3._buckets import MISSING, BucketRule, account_block, block_value


class S3003PublicBucketPolicy(BucketRule):
    id: ClassVar[str] = "S3-003"
    title: ClassVar[str] = "버킷 정책에 의한 퍼블릭 노출"
    severity: ClassVar[Severity] = Severity.CRITICAL

    def judge(
        self,
        snapshot: Snapshot,
        settings: Settings,
        name: str,
        region: str | None,
        details: dict[str, Any],
    ) -> Finding:
        policy_status = details.get("policy_status", MISSING)
        if policy_status is MISSING:
            return self.bucket_error(
                snapshot, name, region, "s3:GetBucketPolicyStatus", "버킷 정책 상태"
            )
        evidence: dict[str, Any] = {
            "policy_status": policy_status,
            "restrict_public_buckets": {
                "bucket": block_value(details.get("public_access_block"), "RestrictPublicBuckets"),
                "account": block_value(account_block(snapshot), "RestrictPublicBuckets"),
            },
        }
        if policy_status is not None and policy_status.get("IsPublic") is True:
            status, message = Status.FAIL, f"버킷 정책이 퍼블릭 접근을 허용한다: {name}"
        elif policy_status is None:
            status, message = Status.PASS, f"버킷 정책이 없다: {name}"
        else:
            status, message = Status.PASS, f"버킷 정책이 퍼블릭이 아니다: {name}"
        return self.bucket_finding(snapshot, name, region, status, message, evidence)
