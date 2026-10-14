"""S3 룰 공용 부품. 모두 `s3` 스냅샷 하나만 본다 (ADR-015).

collector 규약: 값이 None이면 "설정 없음", 키가 없으면 "수집 실패"(`MISSING`).
"""

from typing import Any, Final

from kompass.config import Settings
from kompass.models import Finding, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence, errors_for

BLOCK_SETTINGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


class _Missing:
    def __repr__(self) -> str:
        return "MISSING"


MISSING: Final = _Missing()


def all_blocked(config: Any) -> bool:
    """퍼블릭 액세스 차단 4개 설정이 모두 true인가. 설정 없음·수집 실패는 False."""
    return isinstance(config, dict) and all(config.get(key) is True for key in BLOCK_SETTINGS)


def block_value(config: Any, key: str) -> bool | None:
    """차단 설정 하나의 값. 설정 없음·수집 실패면 None."""
    return config.get(key) is True if isinstance(config, dict) else None


def account_block(snapshot: Snapshot) -> Any:
    return snapshot.data.get("account_public_access_block", MISSING)


class BucketRule(BaseRule):
    """버킷별로 판정하는 룰. 하위 룰은 `judge`만 구현한다."""

    service = "s3"

    def judge(
        self,
        snapshot: Snapshot,
        settings: Settings,
        name: str,
        region: str | None,
        details: dict[str, Any],
    ) -> Finding:
        raise NotImplementedError

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        data = snapshot.data
        if "buckets" not in data:
            return [
                self.finding(
                    snapshot,
                    resource=ACCOUNT_RESOURCE,
                    region=None,
                    status=Status.ERROR,
                    message="S3 버킷 목록을 수집하지 못함",
                    evidence={"errors": errors_evidence(errors_for(snapshot, "s3:ListBuckets"))},
                )
            ]
        if not data["buckets"]:
            return [
                self.finding(
                    snapshot,
                    resource=ACCOUNT_RESOURCE,
                    region=None,
                    status=Status.NOT_APPLICABLE,
                    message="S3 버킷이 없음",
                    evidence={},
                )
            ]
        return [
            self.judge(
                snapshot,
                settings,
                bucket["Name"],
                bucket.get("Region"),
                data["bucket_details"].get(bucket["Name"], {}),
            )
            for bucket in data["buckets"]
        ]

    def bucket_finding(
        self,
        snapshot: Snapshot,
        name: str,
        region: str | None,
        status: Status,
        message: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return self.finding(
            snapshot,
            resource=name,
            region=region,
            status=status,
            message=message,
            evidence=evidence,
        )

    def bucket_error(
        self, snapshot: Snapshot, name: str, region: str | None, operation: str, what: str
    ) -> Finding:
        return self.bucket_finding(
            snapshot,
            name,
            region,
            Status.ERROR,
            f"{what}을(를) 수집하지 못함: {name}",
            {"errors": errors_evidence(errors_for(snapshot, operation, name))},
        )
