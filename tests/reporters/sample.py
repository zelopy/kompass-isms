"""리포터 테스트용 보고서 데이터."""

from datetime import UTC, datetime

from kompass.mappings.data import load_mappings
from kompass.mappings.mapper import build_report
from kompass.models import (
    ActionStep,
    AgentToolCall,
    AuditReport,
    Citation,
    EvaluationReport,
    EvidenceDocumentRef,
    EvidenceFact,
    EvidenceReview,
    EvidenceReviewDraft,
    EvidenceReviewFailure,
    EvidenceReviewReport,
    EvidenceUnreadable,
    ExplanationFailure,
    ExplanationReport,
    Finding,
    Investigation,
    InvestigationDraft,
    InvestigationFact,
    InvestigationFailure,
    InvestigationNote,
    InvestigationReport,
    Remediation,
    ResourceNote,
    RiskAssessment,
    RiskAssessmentDraft,
    RiskScenario,
    RuleExplanation,
    RuleExplanationDraft,
    ScanManifest,
    Severity,
    Status,
    TokenUsage,
)

T0 = datetime(2026, 10, 13, 23, 7, 54, tzinfo=UTC)  # KST 2026-10-14 08:07:54
ACCOUNT = "123456789012"


def finding(
    rule_id: str,
    status: Status,
    resource: str = "account",
    region: str | None = None,
    message: str = "m",
    evidence: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        resource=resource,
        region=region,
        status=status,
        severity=Severity.HIGH,
        message=message,
        evidence=evidence or {},
        collected_at=T0,
    )


def sample_report(*findings: Finding, skipped: tuple[str, ...] = ()) -> AuditReport:
    manifest = ScanManifest(
        scan_id="20261013T230754Z-e013",
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region="ap-northeast-2",
        regions=("ap-northeast-2",),
        kompass_version="0.1.0",
        started_at=T0,
        finished_at=T0,
        snapshots={},
    )
    evaluation = EvaluationReport(
        scan_id=manifest.scan_id,
        account_id=ACCOUNT,
        kompass_version="0.1.0",
        evaluated_at=T0,
        settings={"ec2": {"admin_ports": [22, 3389]}},
        skipped_rules=skipped,
        findings=findings,
    )
    return build_report(manifest, evaluation, load_mappings())


DEFAULT = sample_report(
    finding(
        "SG-001",
        Status.FAIL,
        "sg-1",
        "ap-northeast-2",
        "관리 포트가 전체 개방: sg-1",
        {"group_name": "open|ssh", "open_rules": [{"cidrs": ["0.0.0.0/0"]}]},
    ),
    finding("SG-001", Status.PASS, "sg-2", "ap-northeast-2"),
    finding("SG-002", Status.PASS, "sg-1", "ap-northeast-2"),
    finding("SG-003", Status.PASS, "sg-1", "ap-northeast-2"),
    finding("CT-001", Status.PASS),
    finding("IAM-008", Status.REVIEW, message="루트 비밀번호 사용 이력을 확인할 수 없다"),
    finding("S3-004", Status.FAIL, "bucket-a", "ap-northeast-2", "기본 암호화가 없다"),
    skipped=("IAM-001", "IAM-002"),
)


def _rule_explanation(
    rule_id: str,
    keys: tuple[str, ...],
    verified: bool,
    cli: list[str],
    terraform: str | None = None,
    problems: tuple[str, ...] = (),
) -> RuleExplanation:
    return RuleExplanation(
        rule_id=rule_id,
        finding_keys=keys,
        explanation=RuleExplanationDraft(
            summary=f"{rule_id} 요약 <b>굵게</b>\n# 제목 아님",
            risk="외부에서 접속할 수 있다",
            priority="critical" if verified else "medium",
            priority_reason="인터넷에 노출됨",
            citations=[Citation(scheme="kisa", code="CA-09", quote="불필요한 포트를 차단해야 함")],
            remediation=Remediation(
                steps=["규칙 확인", "규칙 삭제"], aws_cli=cli, terraform=terraform
            ),
            resource_notes=[ResourceNote(finding_key=keys[0], note="bastion 용도 확인")],
        ),
        verified=verified,
        problems=problems,
        model="claude-opus-5-5",
        fallback_used=False,
        attempts=1 if verified else 2,
        usage=TokenUsage(input_tokens=1000, output_tokens=500),
    )


EXPLAINED = DEFAULT.with_explanations(
    ExplanationReport(
        scan_id=DEFAULT.scan.scan_id,
        account_id=ACCOUNT,
        findings_evaluated_at=DEFAULT.evaluation.evaluated_at,
        generated_at=T0,
        model="claude-opus-5-5",
        effort="high",
        source_documents={},
        explanations=(
            _rule_explanation(
                "SG-001",
                ("SG-001:ap-northeast-2:sg-1",),
                True,
                ["=cmd|' /C calc'!A0", "aws ec2 revoke-security-group-ingress --group-id sg-1 ```"],
                terraform='resource "aws_security_group_rule" "x" {}',
            ),
            _rule_explanation(
                "S3-004",
                ("S3-004:ap-northeast-2:bucket-a",),
                False,
                [],
                problems=('원문에 없는 구절: kisa CA-10 "지어낸 문장"',),
            ),
        ),
        failures=(
            ExplanationFailure(
                rule_id="IAM-008", finding_keys=("IAM-008:-:account",), error="거부됨"
            ),
        ),
        usage=TokenUsage(input_tokens=2000, output_tokens=1000),
        estimated_cost_usd=0.028,
        assessment=RiskAssessment(
            assessment=RiskAssessmentDraft(
                summary="- 외부 노출 경로가 겹쳐 있음\n- 즉시 조치 필요",
                scenarios=[
                    RiskScenario(
                        title="공개 SSH <script>와 암호화 없는 버킷",
                        description="관리 포트 개방과 버킷 노출이 함께 있음",
                        finding_keys=[
                            "SG-001:ap-northeast-2:sg-1",
                            "S3-004:ap-northeast-2:bucket-a",
                        ],
                        impact="critical",
                    )
                ],
                action_order=[
                    ActionStep(rule_id="SG-001", reason="외부 접근 경로 차단 우선"),
                    ActionStep(rule_id="S3-004", reason="데이터 보호"),
                    ActionStep(rule_id="IAM-008", reason="확인 작업"),
                ],
            ),
            verified=True,
            problems=(),
            model="claude-opus-5-5",
            fallback_used=False,
            attempts=1,
            usage=TokenUsage(input_tokens=500, output_tokens=300),
        ),
    )
)


def _investigation_report() -> InvestigationReport:
    call = AgentToolCall(
        call_id="T1",
        tool="ec2_interfaces_for_security_group",
        input_masked={"group_id": "MASKED_SG_1"},
        input_raw={"group_id": "sg-1"},
        output_masked='{"call_id": "T1", "items": []}',
        error=None,
        duration_s=0.4,
    )
    denied = AgentToolCall(
        call_id="T2",
        tool="cloudtrail_lookup_events",
        input_masked={"attribute_key": "ResourceName", "attribute_value": "MASKED_SG_1"},
        input_raw={"attribute_key": "ResourceName", "attribute_value": "sg-1"},
        output_masked='{"call_id": "T2", "error": "AccessDenied"}',
        error="AccessDenied",
        duration_s=0.2,
    )
    return InvestigationReport(
        scan_id=DEFAULT.scan.scan_id,
        account_id=ACCOUNT,
        findings_evaluated_at=DEFAULT.evaluation.evaluated_at,
        generated_at=T0,
        model="claude-opus-5-5",
        effort="high",
        investigations=(
            Investigation(
                rule_id="SG-001",
                finding_keys=("SG-001:ap-northeast-2:sg-1",),
                investigation=InvestigationDraft(
                    summary="- 연결된 인터페이스 없음\n- 변경 이력 조회 권한 없음",
                    facts=[
                        InvestigationFact(
                            statement="sg-1에 연결된 인터페이스 <b>0개</b>", call_ids=["T1"]
                        ),
                        InvestigationFact(statement="이벤트 조회 권한 없음", call_ids=["T2"]),
                    ],
                    finding_notes=[
                        InvestigationNote(
                            finding_key="SG-001:ap-northeast-2:sg-1", note="미사용 그룹으로 보임"
                        )
                    ],
                    open_questions=["보안그룹 삭제 가능 여부 담당자 확인 필요"],
                ),
                verified=True,
                problems=(),
                tool_calls=(call, denied),
                model="claude-opus-5-5",
                iterations=3,
                stop="end_turn",
                usage=TokenUsage(input_tokens=3000, output_tokens=400),
            ),
        ),
        failures=(
            InvestigationFailure(
                rule_id="IAM-008",
                finding_keys=("IAM-008:-:account",),
                error="조사 결과 없음 (종료 사유: max_iterations)",
            ),
        ),
        usage=TokenUsage(input_tokens=3000, output_tokens=400),
        estimated_cost_usd=0.02,
    )


INVESTIGATED = EXPLAINED.with_investigations(_investigation_report())


def _evidence_review_report() -> EvidenceReviewReport:
    return EvidenceReviewReport(
        scan_id=DEFAULT.scan.scan_id,
        account_id=ACCOUNT,
        findings_evaluated_at=DEFAULT.evaluation.evaluated_at,
        generated_at=T0,
        model="claude-opus-5-5",
        effort="high",
        reviews=(
            EvidenceReview(
                request_id="CA-02-2",
                documents=(
                    EvidenceDocumentRef(
                        document_id="D1", path="CA-02-2/권한 검토.pdf", sha256="c" * 64,
                        truncated=True,
                    ),
                ),
                review=EvidenceReviewDraft(
                    summary="- 2026년 3분기 검토 기록 있음\n- 검토 주기 정의 없음",
                    facts=[
                        EvidenceFact(
                            statement="2026-09-30 권한 검토 <b>수행</b>",
                            document_id="D1",
                            excerpt="2026-09-30 권한 검토 수행. 검토자 홍길동",
                        )
                    ],
                    gaps=["검토 주기 확인 안 됨", "# 제목처럼 시작하는 문장"],
                    follow_up_requests=["권한 검토 절차서 요청"],
                ),
                verified=True,
                problems=(),
                model="claude-opus-5-5",
                fallback_used=False,
                attempts=1,
                usage=TokenUsage(input_tokens=2000, output_tokens=300),
            ),
        ),
        failures=(EvidenceReviewFailure(request_id="CA-09-1", error="Claude API 호출 실패"),),
        unreadable=(
            EvidenceUnreadable(
                request_id="CA-09-2", path="CA-09-2/scan.png",
                problem="지원하지 않는 형식 (.png). 사람이 검토해야 함",
            ),
        ),
        ignored=("misc",),
        usage=TokenUsage(input_tokens=2000, output_tokens=300),
        estimated_cost_usd=0.01,
    )  # fmt: skip


REVIEWED = DEFAULT.with_evidence_reviews(_evidence_review_report())
