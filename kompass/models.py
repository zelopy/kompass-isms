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


class EvidenceRequest(_Frozen):
    """담당자에게 요청할 증적 하나 (`mappings/evidence_requests.yaml`, ADR-037)."""

    id: str  # "CA-01-1" (항목 코드 + 순번)
    request: str  # 요청 증적
    purpose: str  # 확인 목적
    basis: str  # 근거가 된 KISA 원문 구절


class EvidenceCatalogItem(_Frozen):
    """KISA 항목 하나의 증적 요청 목록."""

    verified: bool  # 요청 문구를 사용자가 원문과 대조해 확인했다
    requests: tuple[EvidenceRequest, ...]


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


class EvidenceTarget(_Frozen):
    """증적 요청과 함께 담당자가 확인할 리소스 (검토 필요·확인 불가 finding)."""

    finding_key: str
    rule_id: str
    resource: str
    region: str | None
    status: Status
    message: str


class EvidenceRequestGroup(_Frozen):
    """KISA 항목 하나에 대해 담당자에게 요청할 증적 (ADR-037). 판정에는 영향이 없다."""

    code: str
    title: str
    importance: KisaImportance
    page: int
    automation: Automation
    outcome: ItemOutcome
    reason: str  # 사람의 확인이 필요한 이유
    verified: bool  # 요청 문구의 원문 대조 확인 여부
    requests: tuple[EvidenceRequest, ...]
    targets: tuple[EvidenceTarget, ...]


class AuditReport(_Frozen):
    """보고서 원본 데이터. 리포터(JSON·Markdown·Excel)는 이것만 읽는다."""

    format_version: Literal[1] = 1
    scan: ScanManifest
    evaluation: EvaluationReport
    mapping_digest: str  # 매핑 데이터 파일의 SHA-256
    generated_at: UtcDatetime
    kisa_items: tuple[KisaItemResult, ...]
    isms_p_controls: tuple[IsmsPControlResult, ...]
    findings: tuple[Finding, ...]  # 매핑을 붙인 finding
    # 담당자 증적 요청 목록 (ADR-037). 매핑 데이터로 정해지며 LLM을 쓰지 않는다
    evidence_requests: tuple[EvidenceRequestGroup, ...] = ()
    # LLM 해설 (참고). 같은 판정 결과를 해설한 것만 붙는다. 판정에는 영향이 없다 (원칙 1)
    explanations: "ExplanationReport | None" = None

    def with_explanations(self, explanations: "ExplanationReport") -> Self:
        """해설을 붙인 새 보고서. 다른 점검이나 다시 판정하기 전의 해설이면 ValueError."""
        if (
            explanations.scan_id != self.scan.scan_id
            or explanations.findings_evaluated_at != self.evaluation.evaluated_at
        ):
            raise ValueError("해설이 이 판정 결과를 대상으로 한 것이 아니다")
        return self.model_validate({**self.model_dump(), "explanations": explanations})

    # 에이전트 추가 조사 (참고, ADR-035). 같은 판정 결과를 조사한 것만 붙는다
    investigations: "InvestigationReport | None" = None

    def with_investigations(self, investigations: "InvestigationReport") -> Self:
        """조사 결과를 붙인 새 보고서. 다른 점검이나 다시 판정하기 전의 조사면 ValueError."""
        if (
            investigations.scan_id != self.scan.scan_id
            or investigations.findings_evaluated_at != self.evaluation.evaluated_at
        ):
            raise ValueError("조사 결과가 이 판정 결과를 대상으로 한 것이 아니다")
        return self.model_validate({**self.model_dump(), "investigations": investigations})


class SourceEntry(_Frozen):
    """기준 문서 원문의 항목 하나 (KISA 항목 또는 ISMS-P 통제항목)."""

    title: str
    page: int  # 항목이 시작하는 PDF 쪽
    text: str


class SourceDocument(_Frozen):
    """색인을 만든 원문 파일. 해시로 판(版)을 확인한다 (knowledge/SOURCES.md)."""

    file: str
    sha256: str


class SourceIndex(_Frozen):
    """기준 문서 원문 색인 (`knowledge/index.json`, ADR-029). 원문을 담으므로 커밋하지 않는다."""

    format_version: Literal[1] = 1
    built_at: UtcDatetime
    documents: dict[str, SourceDocument]  # "kisa", "isms_p"
    kisa: dict[str, SourceEntry]  # "CA-01" → 원문
    isms_p: dict[str, SourceEntry]  # "2.5.3" → 원문


# --- LLM 해설 (3단계) ---
# LLM 응답 스키마에는 판정 상태(status) 필드를 두지 않는다 (원칙 1). 판정은 룰이 이미 내렸고,
# LLM은 그 결과를 설명·우선순위화·조치안 작성만 한다. 우선순위는 의견이며 severity를 바꾸지 않는다.


class Citation(_Frozen):
    """해설의 근거로 인용한 기준 문서 구절. 코드와 구절이 원문 색인에 있어야 검증된다."""

    scheme: Literal["kisa", "isms_p"]
    code: str  # "CA-03", "2.5.3"
    quote: str  # 원문을 그대로 옮긴 구절


class Remediation(_Frozen):
    steps: list[str]  # 사람이 따라 할 조치 절차
    aws_cli: list[str]  # 조치 명령 예시 (실행은 사람이 판단한다)
    terraform: str | None  # Terraform 수정 예시. 해당 없으면 null


class ResourceNote(_Frozen):
    finding_key: str  # `Finding.key` (마스킹된 값)
    note: str  # 이 리소스에만 해당하는 설명


class RuleExplanationDraft(_Frozen):
    """룰 하나(조치가 필요한 finding 묶음)에 대한 LLM 응답. 마스킹된 상태 그대로다."""

    summary: str  # 무엇이 문제인지
    risk: str  # 방치했을 때의 위험
    priority: Literal["critical", "high", "medium", "low"]  # 조치 우선순위 의견
    priority_reason: str
    citations: list[Citation]
    remediation: Remediation
    resource_notes: list[ResourceNote]


class TokenUsage(_Frozen):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_write_input_tokens: int = 0


class RuleExplanation(_Frozen):
    """룰 하나에 대한 해설 (마스킹 복원 후). finding의 판정은 바꾸지 않는다."""

    rule_id: str
    finding_keys: tuple[str, ...]  # 해설 대상 finding (`Finding.key`)
    explanation: RuleExplanationDraft
    verified: bool  # 인용이 모두 매핑·원문과 일치하고 지어낸 식별자가 없다
    problems: tuple[str, ...]  # 마지막 응답의 검증 문제. verified면 비어 있다
    model: str  # 실제로 답한 모델
    fallback_used: bool
    attempts: int
    usage: TokenUsage


class ExplanationFailure(_Frozen):
    rule_id: str
    finding_keys: tuple[str, ...]
    error: str


class RiskScenario(_Frozen):
    """여러 finding이 겹쳐 생기는 위험 (LLM 의견)."""

    title: str
    description: str
    finding_keys: list[str]  # 이 시나리오를 이루는 finding (`Finding.key`, 마스킹된 값)
    impact: Literal["critical", "high", "medium", "low"]


class ActionStep(_Frozen):
    rule_id: str
    reason: str  # 이 순서인 이유


class RiskAssessmentDraft(_Frozen):
    """보고서 전체에 대한 종합 위험 평가 LLM 응답 (마스킹된 상태). status 필드 없음 (원칙 1)."""

    summary: str
    scenarios: list[RiskScenario]
    action_order: list[ActionStep]  # 해설 대상 룰을 모두 한 번씩, 먼저 할 것부터


class RiskAssessment(_Frozen):
    """종합 위험 평가 (마스킹 복원 후)."""

    assessment: RiskAssessmentDraft
    verified: bool  # 참조한 finding·룰이 실제로 있고 조치 순서에 빠진 룰이 없다
    problems: tuple[str, ...]
    model: str
    fallback_used: bool
    attempts: int
    usage: TokenUsage


class ExplanationReport(_Frozen):
    """해설 결과 파일 (`*.explanations.json`). 원본 식별정보가 복원되어 있으므로 커밋하지 않는다."""

    format_version: Literal[1] = 1
    scan_id: str
    account_id: AccountId
    findings_evaluated_at: UtcDatetime  # 어떤 판정 결과를 해설했는가
    generated_at: UtcDatetime
    model: str  # 설정한 모델
    effort: str
    source_documents: dict[str, SourceDocument]  # 인용 검증에 쓴 원문 색인의 판
    explanations: tuple[RuleExplanation, ...]
    failures: tuple[ExplanationFailure, ...]
    usage: TokenUsage
    estimated_cost_usd: float | None
    # 룰을 엮은 종합 위험 평가 (ADR-034). 하지 않았으면 둘 다 None, 실패했으면 이유만 있다
    assessment: RiskAssessment | None = None
    assessment_failure: str | None = None


NEEDS_ACTION = frozenset({Status.FAIL, Status.ERROR, Status.REVIEW})  # 해설·종합 평가 대상
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


class EvalCase(_Frozen):
    """해설 평가 케이스 하나 = 룰 묶음 하나 (ADR-033). 가짜 데이터만 담는다 (원칙 4).

    `findings`에는 그 룰의 finding을 PASS까지 모두 담는다. 해설 대상은 조치가 필요한 것뿐이지만,
    다른 finding의 이름이 증적에서 참조되는 실제 상황을 재현하기 위해서다.
    """

    id: str
    title: str  # 이 케이스가 시험하는 상황
    source: Literal["lab", "synthetic"]
    rule_id: RuleId
    tags: tuple[str, ...]
    findings: tuple[Finding, ...]


class GoldenRule(_Frozen):
    """룰 하나의 조치 정답 (`evals/explain/golden.yaml`)."""

    fail: tuple[str, ...] = ()  # FAIL을 해소하는 작업 ("서비스:작업", botocore 이름)
    review: tuple[str, ...] = ()  # REVIEW를 확인·조치하는 작업. 비어 있으면 fail을 쓴다
    example: str  # 정답 예시 명령. {resource}는 대상 리소스 이름으로 바뀐다

    def actions_for(self, status: Status) -> tuple[str, ...]:
        return (self.review or self.fail) if status == Status.REVIEW else self.fail


class Golden(_Frozen):
    error_actions: tuple[str, ...]  # ERROR(수집 실패)를 해소하는 작업: 점검 권한 부여
    error_example: str
    rules: dict[str, GoldenRule]


class AgentToolCall(_Frozen):
    """에이전트의 도구 호출 하나 (조사 로그, ADR-035). 로컬에만 남기고 커밋하지 않는다."""

    call_id: str  # "T1", "T2", … 조사 결과의 사실이 이 ID로 근거를 가리킨다
    tool: str
    input_masked: JsonObject  # LLM이 보낸 입력 (자리표시자 그대로)
    input_raw: JsonObject  # AWS에 보낸 입력 (복원한 값)
    output_masked: str  # LLM에 돌려준 결과 (마스킹 후)
    error: str | None  # 입력 오류·AWS 오류·예산 초과·마스킹 차단이면 그 분류
    duration_s: float


# --- 에이전트 추가 조사 (4단계, ADR-035) ---
# 조사 응답에도 판정 상태(status) 필드를 두지 않는다 (원칙 1). 에이전트는 사실을 모으고
# 사람이 판단할 질문을 남길 뿐 판정을 바꾸지 않는다.


class InvestigationFact(_Frozen):
    statement: str  # 도구 결과로 확인한 사실
    call_ids: list[str]  # 근거가 된 도구 호출 ("T1", "T3")


class InvestigationNote(_Frozen):
    finding_key: str  # `Finding.key` (마스킹된 값)
    note: str


class InvestigationDraft(_Frozen):
    """룰 하나(FAIL·REVIEW finding 묶음)에 대한 에이전트 조사 응답. 마스킹된 상태 그대로다."""

    summary: str
    facts: list[InvestigationFact]
    finding_notes: list[InvestigationNote]
    open_questions: list[str]  # 도구로 확인하지 못해 사람이 확인해야 할 것


class Investigation(_Frozen):
    """룰 하나의 조사 결과 (마스킹 복원 후). 판정은 바꾸지 않는다."""

    rule_id: str
    finding_keys: tuple[str, ...]
    investigation: InvestigationDraft
    verified: bool  # 모든 사실이 실제 도구 호출을 근거로 가리키고 지어낸 식별자가 없다
    problems: tuple[str, ...]
    tool_calls: tuple[AgentToolCall, ...]  # 조사 로그 (LLM이 본 입출력과 AWS에 보낸 값)
    model: str
    iterations: int
    stop: str  # end_turn, max_iterations, token_budget, …
    usage: TokenUsage


class InvestigationFailure(_Frozen):
    rule_id: str
    finding_keys: tuple[str, ...]
    error: str


class InvestigationReport(_Frozen):
    """조사 결과 파일 (`*.investigation.json`). 원본 식별정보가 담기므로 커밋하지 않는다."""

    format_version: Literal[1] = 1
    scan_id: str
    account_id: AccountId
    findings_evaluated_at: UtcDatetime  # 어떤 판정 결과를 조사했는가
    generated_at: UtcDatetime
    model: str
    effort: str
    investigations: tuple[Investigation, ...]
    failures: tuple[InvestigationFailure, ...]
    usage: TokenUsage
    estimated_cost_usd: float | None


# --- 제출된 증적 문서 (5단계, ADR-049) ---
# 담당자가 낸 파일의 원문이 담기므로 저장·커밋하지 않는다. LLM에는 마스킹한 뒤에만 보낸다.


class EvidenceFileKind(StrEnum):
    PDF = "pdf"
    XLSX = "xlsx"
    TEXT = "text"  # txt·md·csv·json


class EvidenceFile(_Frozen):
    """요청 ID 폴더에 제출된 파일 하나와 로컬에서 추출한 텍스트."""

    request_id: str  # "CA-02-1"
    path: str  # 증적 폴더 기준 상대 경로 (POSIX 구분자)
    sha256: str
    size: int
    kind: EvidenceFileKind | None  # 지원하지 않는 형식이면 None
    text: str | None  # 추출하지 못했으면 None
    problem: str | None  # 추출하지 못한 이유 (사람이 검토해야 함)


class EvidenceSubmission(_Frozen):
    """증적 폴더 하나를 읽은 결과."""

    files: tuple[EvidenceFile, ...]
    ignored: tuple[str, ...]  # 카탈로그에 없는 폴더·폴더 밖 파일·링크 (상대 경로)

    def for_request(self, request_id: str) -> tuple[EvidenceFile, ...]:
        return tuple(f for f in self.files if f.request_id == request_id)


# 전방 참조(ExplanationReport, InvestigationReport)를 해석한다. 모든 모델 정의 뒤에 둔다
AuditReport.model_rebuild()
