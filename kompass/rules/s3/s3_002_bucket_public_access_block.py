"""S3-002 버킷 수준 퍼블릭 액세스 차단 미설정 (KISA CA-10, docs/RULES.md).

버킷 4개 설정이 모두 true이거나, 계정 수준 4개 설정이 모두 true이면 PASS.
둘 다 만족하지 않고, 둘 중 하나라도 수집하지 못했으면 FAIL로 단정하지 않고 ERROR.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import errors_evidence, errors_for
from kompass.rules.s3._buckets import MISSING, BucketRule, account_block, all_blocked


class S3002BucketPublicAccessBlock(BucketRule):
    id: ClassVar[str] = "S3-002"
    title: ClassVar[str] = "버킷 수준 퍼블릭 액세스 차단 미설정"
    severity: ClassVar[Severity] = Severity.HIGH

    def judge(
        self,
        snapshot: Snapshot,
        settings: Settings,
        name: str,
        region: str | None,
        details: dict[str, Any],
    ) -> Finding:
        bucket = details.get("public_access_block", MISSING)
        account = account_block(snapshot)
        evidence: dict[str, Any] = {
            "public_access_block": None if bucket is MISSING else bucket,
            "account_public_access_block": None if account is MISSING else account,
        }
        if all_blocked(bucket):
            status, message = Status.PASS, f"버킷 수준 퍼블릭 액세스 차단이 모두 켜져 있음: {name}"
        elif all_blocked(account):
            status, message = Status.PASS, f"계정 수준 퍼블릭 액세스 차단이 모두 켜져 있음: {name}"
        elif bucket is MISSING or account is MISSING:
            errors = errors_for(snapshot, "s3:GetPublicAccessBlock", name)
            errors += errors_for(snapshot, "s3control:GetPublicAccessBlock")
            evidence["errors"] = errors_evidence(errors)
            status, message = Status.ERROR, f"퍼블릭 액세스 차단 설정을 확인하지 못함: {name}"
        else:
            status = Status.FAIL
            message = f"버킷과 계정 모두 퍼블릭 액세스 차단이 다 켜져 있지 않음: {name}"
        return self.bucket_finding(snapshot, name, region, status, message, evidence)
