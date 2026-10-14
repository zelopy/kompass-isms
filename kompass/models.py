"""공용 pydantic 모델과 항목 단위 집계.

모든 모델은 생성 후 변경할 수 없다 (ADR-001, ADR-019).
- 필드 대입과 `model_copy(update=...)`를 막는다. 매핑은 `Finding.with_mappings()`로만 붙인다.
- 시퀀스는 튜플, `data`·`evidence`는 생성 시 JSON 호환 형태로 깊은 복사·정규화한다.
  바로 수집한 스냅샷과 저장했다 불러온 스냅샷이 같은 모양이 되도록 하기 위해서다.
  날짜는 ISO 8601 문자열("2026-01-01T00:00:00Z")이 된다.
- 시각 필드는 시간대가 있는 값만 받고 UTC로 맞춘다.
"""

import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field
from pydantic_core import PydanticSerializationError, to_json


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


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


def _to_json_compatible(value: dict[str, Any]) -> dict[str, Any]:
    """JSON으로 한 번 왕복시켜 원본과 분리된 JSON 호환 dict를 만든다."""
    try:
        normalized: dict[str, Any] = json.loads(to_json(value))
    except PydanticSerializationError as exc:
        raise ValueError(f"JSON으로 표현할 수 없는 값이 있다: {exc}") from exc
    return normalized


AccountId = Annotated[str, Field(pattern=r"^\d{12}$")]
RuleId = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9]*-\d{3}$")]  # "IAM-001", "S3-006"
UtcDatetime = Annotated[AwareDatetime, AfterValidator(_to_utc)]
JsonObject = Annotated[dict[str, Any], AfterValidator(_to_json_compatible)]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """`update`는 검증 없이 값을 바꾸므로 막는다 (ADR-001)."""
        if update:
            raise TypeError(
                f"{type(self).__name__}는 생성 후 변경할 수 없다 (ADR-001). "
                "매핑은 Finding.with_mappings()로 붙인다."
            )
        return super().model_copy(deep=deep)


class CollectError(_Frozen):
    """API 호출 하나의 수집 실패 기록."""

    operation: str  # "s3control:GetPublicAccessBlock"
    region: str | None  # 전역 서비스(IAM 등)는 None
    error_code: str  # "AccessDenied"
    message: str
    resource: str | None = None  # 리소스 단위 호출이면 대상 (버킷 이름, 추적 ARN 등)


class Snapshot(_Frozen):
    """서비스 하나의 수집 결과. 룰은 스냅샷 하나만 입력으로 받는다 (ADR-015)."""

    service: str  # "iam" | "s3" | "ec2" | "cloudtrail"
    account_id: AccountId
    regions: tuple[str, ...]
    collected_at: UtcDatetime
    data: JsonObject  # API 응답 원본(필요한 부분)
    errors: tuple[CollectError, ...] = ()


class Mappings(_Frozen):
    """finding에 부착되는 기준 매핑. 보고서를 만들 때 Mapper가 채운다 (ADR-025)."""

    kisa: tuple[str, ...]
    isms_p: tuple[str, ...]
    kisa_verified: bool  # KISA 매핑의 원문 근거를 사용자가 확인했다
    isms_p_verified: bool  # ISMS-P 매핑은 공식 대응표가 없는 초안이다


KisaImportance = Literal["상", "중", "하"]


class KisaItem(_Frozen):
    """KISA 클라우드 점검 항목 (`mappings/kisa_items.yaml`)."""

    code: str  # "CA-01"
    title: str
    importance: KisaImportance
    page: int  # 원문 PDF 쪽
    automation: Automation
    isms_p: tuple[str, ...]
    isms_p_verified: bool


class RuleMapping(_Frozen):
    """룰 하나의 매핑 (`mappings/rules.yaml`)."""

    kisa: tuple[str, ...]
    isms_p: tuple[str, ...]
    kisa_verified: bool
    isms_p_verified: bool


class Finding(_Frozen):
    """룰 하나가 리소스 하나에 내린 판정."""

    rule_id: RuleId
    resource: str  # ARN 또는 계정 단위면 "account"
    region: str | None
    status: Status
    severity: Severity
    message: str  # 사람이 읽는 판정 요약
    evidence: JsonObject  # 판정 근거가 된 원본 설정 (증적)
    collected_at: UtcDatetime
    mappings: Mappings | None = None

    @property
    def key(self) -> str:
        """점검 안에서 finding 하나를 가리키는 식별자 `룰:리전:리소스` (저장하지 않는다).

        LLM 해설을 finding에 다시 붙일 때 쓴다. 전역 리소스는 리전 자리에 `-`를 쓴다.
        """
        return f"{self.rule_id}:{self.region or '-'}:{self.resource}"

    def with_mappings(self, mappings: Mappings) -> Self:
        """매핑을 붙인 새 finding을 돌려준다. 나머지 필드는 그대로 다시 검증한다."""
        return self.model_validate({**self.model_dump(), "mappings": mappings})


class ScanManifest(_Frozen):
    """점검 한 번의 정보와 스냅샷 파일 목록 (`scan.json`).

    점검 폴더에 맨 마지막에 쓴다. 이 파일이 없는 폴더는 중단된 점검이다.
    `snapshots`는 서비스 이름 → 스냅샷 파일의 SHA-256. 불러올 때 대조해 손상·수정을 찾는다.
    """

    format_version: Literal[1] = 1
    scan_id: str
    account_id: AccountId
    partition: str
    caller_arn: str  # 점검 수행 주체
    home_region: str
    regions: tuple[str, ...]
    kompass_version: str
    started_at: UtcDatetime
    finished_at: UtcDatetime
    snapshots: dict[str, str]
    # 리전 전체 접근 거부로 점검 범위에서 뺀 리전 → 거부 메시지 (ADR-028). 양호가 아니라 범위 밖이다
    excluded_regions: dict[str, str] = {}


class EvaluationReport(_Frozen):
    """판정 결과 파일 (`*.findings.json`).

    같은 스냅샷을 어떤 기준값과 버전으로 판정했는지 재현할 수 있도록 판정 조건을 함께 남긴다.
    """

    format_version: Literal[1] = 1
    scan_id: str
    account_id: AccountId
    kompass_version: str
    evaluated_at: UtcDatetime
    settings: JsonObject  # 적용한 판정 기준값 (kompass.yaml + 기본값)
    skipped_rules: tuple[str, ...]  # 스냅샷이 없어 실행하지 않은 룰. PASS가 아니다
    findings: tuple[Finding, ...]


class ItemOutcome(StrEnum):
    """KISA 항목·ISMS-P 통제항목의 결과. `Status`의 값에 항목 단위 상태 두 가지를 더한다."""

    FAIL = "FAIL"
    ERROR = "ERROR"
    REVIEW = "REVIEW"
    PASS = "PASS"
    NOT_APPLICABLE = "N/A"
    NOT_EVALUATED = "NOT_EVALUATED"  # 담당 룰이 있지만 스냅샷이 없어 실행하지 않음
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"  # 담당 룰이 없음. 수동 점검 대상


class KisaItemResult(_Frozen):
    code: str
    title: str
    importance: KisaImportance
    page: int
    automation: Automation
    outcome: ItemOutcome
    rule_ids: tuple[str, ...]
    status_counts: dict[str, int]  # finding 상태별 개수
    isms_p: tuple[str, ...]


class IsmsPControlResult(_Frozen):
    code: str
    name: str
    area: str  # "보호대책 요구사항" 등
    outcome: ItemOutcome  # 관련 룰이 없으면 NOT_IMPLEMENTED (자동 점검 범위 밖)
    kisa_items: tuple[str, ...]
    rule_ids: tuple[str, ...]


class AuditReport(_Frozen):
    """보고서 원본 데이터. 리포터(JSON·Markdown·Excel)는 이것만 읽는다."""

    format_version: Literal[1] = 1
    scan: ScanManifest
    evaluation: EvaluationReport
    mapping_digest: str  # 매핑 데이터 세 파일의 SHA-256
    generated_at: UtcDatetime
    kisa_items: tuple[KisaItemResult, ...]
    isms_p_controls: tuple[IsmsPControlResult, ...]
    findings: tuple[Finding, ...]  # 매핑을 붙인 finding


_PRECEDENCE = (Status.FAIL, Status.ERROR, Status.REVIEW)


def aggregate_status(statuses: Iterable[Status], automation: Automation) -> Status:
    """항목에 매핑된 finding들의 상태를 항목 결과 하나로 집계한다.

    우선순위는 FAIL > ERROR > REVIEW > PASS > N/A (ADR-009).
    full이 아닌 항목은 PASS가 나와도 REVIEW로 낮춘다 (ADR-013). 분류를 빠뜨리는 실수가
    "양호"로 이어지지 않도록 `automation`에는 기본값을 두지 않는다.
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
