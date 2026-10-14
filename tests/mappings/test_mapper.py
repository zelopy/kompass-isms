"""매퍼: finding 매핑 부착, KISA 항목·ISMS-P 통제항목 집계."""

from datetime import UTC, datetime
from typing import Any

from kompass.mappings.data import load_mappings
from kompass.mappings.mapper import build_report
from kompass.models import (
    AuditReport,
    EvaluationReport,
    Finding,
    ItemOutcome,
    ScanManifest,
    Severity,
    Status,
)

T0 = datetime(2026, 10, 14, 0, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
MAPPINGS = load_mappings()


def _finding(rule_id: str, status: Status, resource: str = "account") -> Finding:
    return Finding(
        rule_id=rule_id,
        resource=resource,
        region=None,
        status=status,
        severity=Severity.HIGH,
        message="m",
        evidence={},
        collected_at=T0,
    )


def _manifest() -> ScanManifest:
    return ScanManifest(
        scan_id="20261014T000000Z-abcd",
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


def _report(*findings: Finding, skipped: tuple[str, ...] = ()) -> AuditReport:
    evaluation = EvaluationReport(
        scan_id="20261014T000000Z-abcd",
        account_id=ACCOUNT,
        kompass_version="0.1.0",
        evaluated_at=T0,
        settings={},
        skipped_rules=skipped,
        findings=findings,
    )
    return build_report(_manifest(), evaluation, MAPPINGS)


def _item(report: AuditReport, code: str) -> Any:
    return next(i for i in report.kisa_items if i.code == code)


def _control(report: AuditReport, code: str) -> Any:
    return next(c for c in report.isms_p_controls if c.code == code)


# --- finding 매핑 ---


def test_findings_get_mappings() -> None:
    report = _report(_finding("S3-001", Status.FAIL), _finding("S3-004", Status.PASS, "b"))
    by_rule = {f.rule_id: f for f in report.findings}
    s3001 = by_rule["S3-001"].mappings
    assert s3001 is not None
    assert s3001.kisa == ("CA-10",)
    assert s3001.isms_p == ("2.10.2",)
    assert s3001.kisa_verified is True
    assert s3001.isms_p_verified is False
    s3004 = by_rule["S3-004"].mappings
    assert s3004 is not None and s3004.kisa == ()  # KISA 대응 항목이 없는 룰


def test_status_is_unchanged_by_mapping() -> None:
    report = _report(_finding("SG-001", Status.FAIL, "sg-1"))
    assert report.findings[0].status == Status.FAIL


def test_report_records_mapping_digest() -> None:
    assert _report().mapping_digest == MAPPINGS.digest


# --- KISA 항목 ---


def test_all_19_items_present_in_order() -> None:
    codes = [i.code for i in _report().kisa_items]
    assert codes == [f"CA-{n:02d}" for n in range(1, 20)]


def test_full_item_can_pass() -> None:
    report = _report(
        _finding("IAM-001", Status.PASS),
        _finding("IAM-003", Status.PASS, "u"),
        _finding("IAM-009", Status.NOT_APPLICABLE),
    )
    item = _item(report, "CA-03")
    assert item.outcome == ItemOutcome.PASS
    assert item.rule_ids == ("IAM-001", "IAM-003", "IAM-009")
    assert item.status_counts == {"PASS": 2, "N/A": 1}


def test_partial_item_caps_pass_at_review() -> None:
    # ADR-013: partial 항목은 자동으로 양호가 되지 않는다
    report = _report(*(_finding(r, Status.PASS, "sg-1") for r in ("SG-001", "SG-002", "SG-003")))
    assert _item(report, "CA-09").outcome == ItemOutcome.REVIEW


def test_item_fail_wins() -> None:
    report = _report(
        _finding("SG-001", Status.FAIL, "sg-1"), _finding("SG-002", Status.ERROR, "sg-1")
    )
    assert _item(report, "CA-09").outcome == ItemOutcome.FAIL


def test_item_without_rules_is_not_implemented() -> None:
    item = _item(_report(), "CA-05")
    assert item.outcome == ItemOutcome.NOT_IMPLEMENTED
    assert item.rule_ids == ()


def test_item_with_skipped_rules_is_not_evaluated() -> None:
    # 수집하지 않은 서비스의 항목은 PASS도 N/A도 아니다
    report = _report(skipped=("CT-001",))
    assert _item(report, "CA-13").outcome == ItemOutcome.NOT_EVALUATED


def test_item_partly_skipped_keeps_definite_fail() -> None:
    report = _report(_finding("IAM-007", Status.FAIL, "u"), skipped=("IAM-002", "IAM-008"))
    assert _item(report, "CA-02").outcome == ItemOutcome.FAIL


def test_item_partly_skipped_without_fail_is_not_evaluated() -> None:
    report = _report(_finding("IAM-007", Status.PASS), skipped=("IAM-002", "IAM-008"))
    assert _item(report, "CA-02").outcome == ItemOutcome.NOT_EVALUATED


# --- ISMS-P 통제항목 ---


def test_all_101_controls_present() -> None:
    assert len(_report().isms_p_controls) == 101


def test_control_without_rules_is_out_of_scope() -> None:
    control = _control(_report(), "1.1.1")
    assert control.name == "경영진의 참여"
    assert control.outcome == ItemOutcome.NOT_IMPLEMENTED


def test_control_never_passes_automatically() -> None:
    # ISMS-P 통제는 관리 절차까지 포함하므로 자동 점검 결과는 참고 증적이다 (항상 partial)
    report = _report(_finding("IAM-004", Status.PASS))
    control = _control(report, "2.5.4")
    assert control.outcome == ItemOutcome.REVIEW
    assert control.rule_ids == ("IAM-004",)
    assert control.kisa_items == ("CA-04",)


def test_control_fail_from_rule() -> None:
    report = _report(_finding("S3-004", Status.FAIL, "b"))
    assert _control(report, "2.7.1").outcome == ItemOutcome.FAIL


def test_control_with_only_skipped_rules_is_not_evaluated() -> None:
    report = _report(skipped=("IAM-004",))
    assert _control(report, "2.5.4").outcome == ItemOutcome.NOT_EVALUATED
