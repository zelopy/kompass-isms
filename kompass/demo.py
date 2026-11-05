"""공개 데모용 가공 보고서 (ADR-055).

실제 계정 데이터가 아니다. 계정 ID는 AWS 문서의 예시 값이고, 리소스·증적·해설·조사·증적 검토는
모두 지어낸 값이다. `scripts/build_demo.py`가 이 보고서를 `docs/demo/index.html`로 렌더링하고,
`tests/test_demo.py`가 커밋된 파일이 현재 리포터 출력과 같은지 확인한다.

원문 색인(`knowledge/index.json`)은 읽지 않는다. 해설 인용은 짧은 구절만 넣는다.
시각은 고정값이라 실행할 때마다 같은 출력이 나온다.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
    EvidenceReviewReport,
    EvidenceUnreadable,
    ExplanationFailure,
    ExplanationReport,
    Finding,
    Investigation,
    InvestigationDraft,
    InvestigationFact,
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

DEMO_PATH = Path("docs/demo/index.html")  # 저장소 루트 기준
DEMO_ACCOUNT = "123456789012"  # AWS 문서의 예시 계정 ID
_T = datetime(2026, 11, 1, 1, 0, 0, tzinfo=UTC)  # KST 2026-11-01 10:00:00
_SCAN_ID = "20261101T010000Z-demo"
_SEOUL = "ap-northeast-2"
_MODEL = "claude-opus-5-5"

_SG_SSH = "sg-0demo00000000ssh"
_SG_DB = "sg-0demo000000000db"
_BUCKET = f"arn:aws:s3:::demo-public-assets-{DEMO_ACCOUNT}"
_DEV_USER = f"arn:aws:iam::{DEMO_ACCOUNT}:user/demo-developer"


def _finding(
    rule_id: str,
    status: Status,
    severity: Severity,
    message: str,
    evidence: dict[str, Any],
    resource: str = "account",
    region: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        resource=resource,
        region=region,
        status=status,
        severity=severity,
        message=message,
        evidence=evidence,
        collected_at=_T,
    )


def _findings() -> tuple[Finding, ...]:
    fail, review, error = Status.FAIL, Status.REVIEW, Status.ERROR
    ok, na = Status.PASS, Status.NOT_APPLICABLE
    high, critical, medium = Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM
    return (
        _finding("IAM-001", fail, critical, "루트 계정 MFA 미설정", {"AccountMFAEnabled": 0}),
        _finding(
            "IAM-003",
            fail,
            high,
            "콘솔 비밀번호가 있는 사용자의 MFA 미설정: demo-developer",
            {"user": "demo-developer", "password_enabled": True, "mfa_active": False},
            _DEV_USER,
        ),
        _finding(
            "IAM-004",
            ok,
            medium,
            "비밀번호 정책이 기준 충족",
            {"MinimumPasswordLength": 14, "RequireSymbols": True, "MaxPasswordAge": 90},
        ),
        _finding(
            "IAM-008",
            review,
            medium,
            "루트 계정 최근 사용 이력 확인 필요",
            {"password_last_used": "2026-10-20T03:12:00+00:00"},
        ),
        _finding(
            "SG-001",
            fail,
            high,
            f"관리 포트가 전체 개방: {_SG_SSH}",
            {
                "group_name": "demo-bastion",
                "open_rules": [{"protocol": "tcp", "port": 22, "cidrs": ["0.0.0.0/0"]}],
            },
            _SG_SSH,
            _SEOUL,
        ),
        _finding(
            "SG-003",
            fail,
            high,
            f"데이터베이스 포트가 전체 개방: {_SG_DB}",
            {
                "group_name": "demo-db",
                "open_rules": [{"protocol": "tcp", "port": 5432, "cidrs": ["0.0.0.0/0"]}],
            },
            _SG_DB,
            _SEOUL,
        ),
        _finding(
            "SG-002",
            ok,
            high,
            f"전체 포트 개방 규칙 없음: {_SG_DB}",
            {"group_name": "demo-db"},
            _SG_DB,
            _SEOUL,
        ),
        _finding(
            "S3-002",
            fail,
            high,
            "버킷 퍼블릭 액세스 차단 미설정",
            {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            _BUCKET,
            _SEOUL,
        ),
        _finding(
            "S3-004",
            ok,
            medium,
            "기본 암호화 설정됨",
            {"rules": [{"SSEAlgorithm": "aws:kms", "BucketKeyEnabled": True}]},
            _BUCKET,
            _SEOUL,
        ),
        _finding(
            "CT-001",
            ok,
            high,
            "멀티 리전 추적이 관리 이벤트 기록 중",
            {"trail": "demo-trail", "IsMultiRegionTrail": True, "IsLogging": True},
        ),
        _finding(
            "GD-001",
            error,
            medium,
            "GuardDuty 탐지기 조회 실패: AccessDenied",
            {"error": {"code": "AccessDeniedException", "operation": "ListDetectors"}},
            "account",
            "us-east-1",
        ),
        _finding(
            "RDS-002",
            na,
            high,
            "점검 대상 DB 인스턴스 없음",
            {"db_instances": []},
            "account",
            "us-east-1",
        ),
    )


def _explanations(base: AuditReport) -> ExplanationReport:
    sg_keys = (f"SG-001:{_SEOUL}:{_SG_SSH}",)
    s3_keys = (f"S3-002:{_SEOUL}:{_BUCKET}",)
    usage = TokenUsage(input_tokens=1800, output_tokens=650)
    sg = RuleExplanation(
        rule_id="SG-001",
        finding_keys=sg_keys,
        explanation=RuleExplanationDraft(
            summary="SSH(22) 포트가 인터넷 전체에 열려 있음",
            risk="무작위 대입 공격과 취약점 악용으로 서버 장악 가능성 있음",
            priority="critical",
            priority_reason="인터넷에서 바로 접근 가능한 관리 경로임",
            citations=[Citation(scheme="kisa", code="CA-09", quote="불필요한 정책 제거")],
            remediation=Remediation(
                steps=[
                    "접속이 필요한 관리자 IP 대역 확인",
                    "0.0.0.0/0 규칙 삭제 후 관리자 대역만 허용",
                    "가능하면 Session Manager로 대체",
                ],
                aws_cli=[
                    f"aws ec2 revoke-security-group-ingress --group-id {_SG_SSH} "
                    "--protocol tcp --port 22 --cidr 0.0.0.0/0"
                ],
                terraform=(
                    'resource "aws_vpc_security_group_ingress_rule" "ssh" {\n'
                    "  security_group_id = aws_security_group.bastion.id\n"
                    '  cidr_ipv4         = "203.0.113.0/24" # 관리자 대역 (예시)\n'
                    "  from_port         = 22\n"
                    "  to_port           = 22\n"
                    '  ip_protocol       = "tcp"\n'
                    "}"
                ),
            ),
            resource_notes=[
                ResourceNote(finding_key=sg_keys[0], note="bastion 용도 여부 확인 필요")
            ],
        ),
        verified=True,
        problems=(),
        model=_MODEL,
        fallback_used=False,
        attempts=1,
        usage=usage,
    )
    s3 = RuleExplanation(
        rule_id="S3-002",
        finding_keys=s3_keys,
        explanation=RuleExplanationDraft(
            summary="버킷 단위 퍼블릭 액세스 차단 네 항목이 모두 꺼져 있음",
            risk="정책·ACL 변경 한 번으로 객체가 공개될 수 있음",
            priority="high",
            priority_reason="현재 공개 정책은 없으나 보호 장치가 없음",
            citations=[Citation(scheme="kisa", code="CA-10", quote="퍼블릭 접근 차단 설정")],
            remediation=Remediation(
                steps=["공개가 필요한 버킷인지 확인", "필요 없으면 네 항목 모두 켬"],
                aws_cli=[
                    "aws s3api put-public-access-block --bucket demo-public-assets-"
                    f"{DEMO_ACCOUNT} --public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ],
                terraform=None,
            ),
            resource_notes=[],
        ),
        verified=False,
        problems=('원문에서 찾지 못한 구절: kisa CA-10 "퍼블릭 접근 차단 설정"',),
        model=_MODEL,
        fallback_used=False,
        attempts=2,
        usage=usage,
    )
    assessment = RiskAssessment(
        assessment=RiskAssessmentDraft(
            summary="인터넷에 열린 관리·DB 포트와 MFA 없는 관리 경로가 겹쳐 있음",
            scenarios=[
                RiskScenario(
                    title="공개 SSH를 통한 서버 장악 후 DB 접근",
                    description="bastion 장악 뒤 같은 VPC의 열린 DB 포트로 이동 가능",
                    finding_keys=[sg_keys[0], f"SG-003:{_SEOUL}:{_SG_DB}"],
                    impact="critical",
                ),
                RiskScenario(
                    title="MFA 없는 계정 탈취",
                    description="루트·콘솔 사용자 비밀번호 유출 시 추가 인증 없이 로그인 가능",
                    finding_keys=["IAM-001:-:account", f"IAM-003:-:{_DEV_USER}"],
                    impact="high",
                ),
            ],
            action_order=[
                ActionStep(rule_id="SG-001", reason="외부 접근 경로를 먼저 차단"),
                ActionStep(rule_id="S3-002", reason="데이터 노출 보호 장치 복구"),
            ],
        ),
        verified=True,
        problems=(),
        model=_MODEL,
        fallback_used=False,
        attempts=1,
        usage=TokenUsage(input_tokens=900, output_tokens=420),
    )
    return ExplanationReport(
        scan_id=base.scan.scan_id,
        account_id=DEMO_ACCOUNT,
        findings_evaluated_at=base.evaluation.evaluated_at,
        generated_at=_T,
        model=_MODEL,
        effort="high",
        source_documents={},
        explanations=(sg, s3),
        failures=(
            ExplanationFailure(
                rule_id="IAM-003",
                finding_keys=(f"IAM-003:-:{_DEV_USER}",),
                error="마스킹 차단: 응답에 지어낸 식별자 포함",
            ),
        ),
        usage=TokenUsage(input_tokens=4500, output_tokens=1720),
        estimated_cost_usd=0.07,
        assessment=assessment,
    )


def _investigations(base: AuditReport) -> InvestigationReport:
    key = f"SG-001:{_SEOUL}:{_SG_SSH}"
    calls = (
        AgentToolCall(
            call_id="T1",
            tool="ec2_interfaces_for_security_group",
            input_masked={"group_id": "MASKED_SG_1"},
            input_raw={"group_id": _SG_SSH},
            output_masked='{"call_id": "T1", "items": [{"interface": "MASKED_ENI_1"}]}',
            error=None,
            duration_s=0.4,
        ),
        AgentToolCall(
            call_id="T2",
            tool="cloudtrail_lookup_events",
            input_masked={"attribute_key": "ResourceName", "attribute_value": "MASKED_SG_1"},
            input_raw={"attribute_key": "ResourceName", "attribute_value": _SG_SSH},
            output_masked=(
                '{"call_id": "T2", "events": [{"name": "AuthorizeSecurityGroupIngress"}]}'
            ),
            error=None,
            duration_s=0.7,
        ),
    )
    return InvestigationReport(
        scan_id=base.scan.scan_id,
        account_id=DEMO_ACCOUNT,
        findings_evaluated_at=base.evaluation.evaluated_at,
        generated_at=_T,
        model=_MODEL,
        effort="high",
        investigations=(
            Investigation(
                rule_id="SG-001",
                finding_keys=(key,),
                investigation=InvestigationDraft(
                    summary="실행 중인 인스턴스 1대가 이 보안그룹을 사용함",
                    facts=[
                        InvestigationFact(
                            statement="보안그룹에 연결된 네트워크 인터페이스 1개", call_ids=["T1"]
                        ),
                        InvestigationFact(
                            statement="최근 90일 안에 22번 포트 허용 규칙 추가 이벤트 있음",
                            call_ids=["T2"],
                        ),
                    ],
                    finding_notes=[InvestigationNote(finding_key=key, note="사용 중인 그룹임")],
                    open_questions=["규칙을 추가한 담당자와 목적 확인 필요"],
                ),
                verified=True,
                problems=(),
                tool_calls=calls,
                model=_MODEL,
                iterations=3,
                stop="end_turn",
                usage=TokenUsage(input_tokens=5200, output_tokens=380),
            ),
        ),
        failures=(),
        usage=TokenUsage(input_tokens=5200, output_tokens=380),
        estimated_cost_usd=0.04,
    )


def _evidence_reviews(base: AuditReport) -> EvidenceReviewReport:
    return EvidenceReviewReport(
        scan_id=base.scan.scan_id,
        account_id=DEMO_ACCOUNT,
        findings_evaluated_at=base.evaluation.evaluated_at,
        generated_at=_T,
        model=_MODEL,
        effort="high",
        reviews=(
            EvidenceReview(
                request_id="CA-02-2",
                documents=(
                    EvidenceDocumentRef(
                        document_id="D1",
                        path="CA-02-2/권한 검토 기록.pdf",
                        sha256="0" * 64,
                        truncated=False,
                    ),
                ),
                review=EvidenceReviewDraft(
                    summary="분기별 권한 검토 기록이 있으나 검토 기준 문서 없음",
                    facts=[
                        EvidenceFact(
                            statement="2026년 3분기 권한 검토 수행 기록 있음",
                            document_id="D1",
                            excerpt="2026-09-30 IAM 권한 검토 완료 (가공 문서)",
                        )
                    ],
                    gaps=["검토 기준(불필요 권한 판단 기준) 확인 안 됨"],
                    follow_up_requests=["권한 검토 절차서 제출 요청"],
                ),
                verified=True,
                problems=(),
                model=_MODEL,
                fallback_used=False,
                attempts=1,
                usage=TokenUsage(input_tokens=2100, output_tokens=310),
            ),
        ),
        failures=(),
        unreadable=(
            EvidenceUnreadable(
                request_id="CA-09-2",
                path="CA-09-2/방화벽 화면.png",
                problem="지원하지 않는 형식 (.png). 사람이 검토해야 함",
            ),
        ),
        ignored=(),
        usage=TokenUsage(input_tokens=2100, output_tokens=310),
        estimated_cost_usd=0.01,
    )


def demo_report() -> AuditReport:
    """데모 시나리오 보고서. 같은 매핑 데이터면 항상 같은 값이다."""
    manifest = ScanManifest(
        scan_id=_SCAN_ID,
        account_id=DEMO_ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{DEMO_ACCOUNT}:user/security_manager",
        home_region=_SEOUL,
        regions=(_SEOUL, "us-east-1"),
        kompass_version="0.1.0",
        started_at=_T,
        finished_at=_T,
        snapshots={},
        excluded_regions={"ap-southeast-1": "가공 예시: 리전 전체 접근 거부 (SCP)"},
    )
    evaluation = EvaluationReport(
        scan_id=_SCAN_ID,
        account_id=DEMO_ACCOUNT,
        kompass_version="0.1.0",
        evaluated_at=_T,
        settings={"ec2": {"admin_ports": [22, 3389]}},
        skipped_rules=("BKP-001", "BKP-002", "BKP-003"),
        findings=_findings(),
    )
    base = build_report(manifest, evaluation, load_mappings())
    # build_report는 생성 시각을 현재 시각으로 넣는다. 데모는 고정 시각으로 바꾼다
    # (model_copy는 막혀 있으므로 with_* 메서드처럼 다시 검증해 만든다, ADR-001)
    base = AuditReport.model_validate({**base.model_dump(), "generated_at": _T})
    return (
        base.with_explanations(_explanations(base))
        .with_investigations(_investigations(base))
        .with_evidence_reviews(_evidence_reviews(base))
    )
