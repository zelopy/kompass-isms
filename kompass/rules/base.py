"""룰 공용 부품.

룰은 스냅샷 하나와 설정만 보고 결정론적으로 finding을 낸다 (원칙 1, ADR-015).
- 필요한 데이터 수집이 실패했으면 ERROR finding을 낸다 (ADR-005).
- 점검 대상 리소스가 없으면 NOT_APPLICABLE finding 하나를 낸다.
- 어떤 경우에도 finding을 하나 이상 낸다. 실행기가 검사한다.
"""

from datetime import UTC, datetime
from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import CollectError, Finding, Severity, Snapshot, Status

ACCOUNT_RESOURCE = "account"  # 계정 단위 finding의 resource 값

# 자격증명 보고서 등에서 "날짜 없음"을 뜻하는 값. "사용 안 함"과 같지 않을 수 있다
# (예: 루트의 password_last_used가 no_information이어도 실제로는 사용했을 수 있다)
_NO_DATE_VALUES = frozenset({"", "N/A", "no_information", "not_supported"})


class BaseRule:
    """룰 하나 = 파일 하나. id·title은 docs/RULES.md와 일치해야 한다 (테스트로 검사)."""

    id: ClassVar[str]
    service: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        snapshot: Snapshot,
        *,
        resource: str,
        region: str | None,
        status: Status,
        message: str,
        evidence: dict[str, Any],
    ) -> Finding:
        """룰의 ID·심각도와 스냅샷의 수집 시각을 채운 finding을 만든다.

        `collected_at`은 판정 시각이 아니라 증적을 수집한 시각이다.
        """
        return Finding(
            rule_id=self.id,
            resource=resource,
            region=region,
            status=status,
            severity=self.severity,
            message=message,
            evidence=evidence,
            collected_at=snapshot.collected_at,
        )


def errors_for(
    snapshot: Snapshot, operation: str, resource: str | None = None
) -> list[CollectError]:
    """스냅샷의 수집 실패 중 해당 오퍼레이션(과 리소스)에 대한 것."""
    return [
        error
        for error in snapshot.errors
        if error.operation == operation and (resource is None or error.resource == resource)
    ]


def errors_evidence(errors: list[CollectError]) -> list[dict[str, Any]]:
    """수집 실패 기록을 evidence에 넣을 형태로 바꾼다."""
    return [error.model_dump(mode="json") for error in errors]


def parse_aws_datetime(value: str | None) -> datetime | None:
    """스냅샷의 ISO 8601 날짜 문자열을 UTC datetime으로 바꾼다 (ADR-019).

    특수 값(`N/A`, `no_information`, `not_supported`, 빈 값)은 None이다. 시간대가 없거나
    해석할 수 없는 값은 ValueError로 실행을 멈춘다. 조용히 None으로 만들면 "날짜 없음"으로
    잘못 판정될 수 있기 때문이다 (ADR-023).
    """
    if value is None or value in _NO_DATE_VALUES:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"시간대가 없는 날짜: {value!r}")
    return parsed.astimezone(UTC)
