"""공용 pydantic 모델과 항목 단위 집계.

모든 모델은 생성 후 변경할 수 없다(frozen). finding의 status는 룰 엔진 이후 바뀌지 않는다 (ADR-001).
"""

from collections.abc import Iterable
from enum import StrEnum
from typing import Annotated, Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class Status(StrEnum):
    """판정 상태."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"  # 수집 실패, 권한 없음 (ADR-005)
    REVIEW = "REVIEW"  # 수집은 자동, 양호/취약 판단은 사람이 함 (ADR-010)
    NOT_APPLICABLE = "N/A"  # 점검 대상 리소스 없음


class Severity(StrEnum):
    """kompass 내부 심각도. KISA 중요도(상/중/하)는 매핑 데이터에 따로 둔다 (ADR-011)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Automation(StrEnum):
    """KISA 항목의 자동화 분류 (COVERAGE.md)."""

    FULL = "full"
    PARTIAL = "partial"
    MANUAL = "manual"


AccountId = Annotated[str, Field(pattern=r"^\d{12}$")]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CollectError(_Frozen):
    """API 호출 하나의 수집 실패 기록."""

    operation: str  # "s3control:GetPublicAccessBlock"
    region: str | None
    error_code: str  # "AccessDenied"
    message: str


class Snapshot(_Frozen):
    """서비스 하나의 수집 결과. 룰은 스냅샷 하나만 입력으로 받는다 (ADR-015)."""

    service: str  # "iam" | "s3" | "ec2" | "cloudtrail"
    account_id: AccountId
    regions: list[str]
    collected_at: AwareDatetime
    data: dict[str, Any]  # API 응답 원본(필요한 부분)
    errors: list[CollectError] = []


class Mappings(_Frozen):
    """finding에 부착되는 기준 매핑. Mapper가 채운다."""

    kisa: list[str]
    isms_p: list[str]
    verified: bool


class Finding(_Frozen):
    """룰 하나가 리소스 하나에 내린 판정."""

    rule_id: str  # "S3-001"
    resource: str  # ARN 또는 계정 단위면 "account"
    region: str | None
    status: Status
    severity: Severity
    message: str  # 사람이 읽는 판정 요약
    evidence: dict[str, Any]  # 판정 근거가 된 원본 설정 (증적)
    collected_at: AwareDatetime
    mappings: Mappings | None = None


_PRECEDENCE = (Status.FAIL, Status.ERROR, Status.REVIEW)


def aggregate_status(
    statuses: Iterable[Status], automation: Automation = Automation.FULL
) -> Status:
    """항목에 매핑된 finding들의 상태를 항목 결과 하나로 집계한다.

    우선순위는 FAIL > ERROR > REVIEW > PASS > N/A (ADR-009).
    full이 아닌 항목은 PASS가 나와도 REVIEW로 낮춘다 (ADR-013).
    finding이 하나도 없으면 "점검하지 않음"과 "해당 없음"을 구분할 수 없으므로 ValueError.
    """
    present = set(statuses)
    if not present:
        raise ValueError("집계할 finding이 없다")
    for status in _PRECEDENCE:
        if status in present:
            return status
    if Status.PASS in present:
        return Status.PASS if automation is Automation.FULL else Status.REVIEW
    return Status.NOT_APPLICABLE
