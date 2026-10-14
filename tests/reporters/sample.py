"""리포터 테스트용 보고서 데이터."""

from datetime import UTC, datetime

from kompass.mappings.data import load_mappings
from kompass.mappings.mapper import build_report
from kompass.models import (
    AuditReport,
    Citation,
    EvaluationReport,
    ExplanationFailure,
    ExplanationReport,
    Finding,
    Remediation,
    ResourceNote,
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
    finding("SG-001", Status.FAIL, "sg-1", "ap-northeast-2", "관리 포트가 전체 개방: sg-1",
            {"group_name": "open|ssh", "open_rules": [{"cidrs": ["0.0.0.0/0"]}]}),
    finding("SG-001", Status.PASS, "sg-2", "ap-northeast-2"),
    finding("SG-002", Status.PASS, "sg-1", "ap-northeast-2"),
    finding("SG-003", Status.PASS, "sg-1", "ap-northeast-2"),
    finding("CT-001", Status.PASS),
    finding("IAM-008", Status.REVIEW, message="루트 비밀번호 사용 이력을 확인할 수 없다"),
    finding("S3-004", Status.FAIL, "bucket-a", "ap-northeast-2", "기본 암호화가 없다"),
    skipped=("IAM-001", "IAM-002"),
)  # fmt: skip


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
    )
)
