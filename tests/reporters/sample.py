"""리포터 테스트용 보고서 데이터."""

from datetime import UTC, datetime

from kompass.mappings.data import load_mappings
from kompass.mappings.mapper import build_report
from kompass.models import (
    AuditReport,
    EvaluationReport,
    Finding,
    ScanManifest,
    Severity,
    Status,
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
