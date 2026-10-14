"""IAM-001 루트 MFA, IAM-002 루트 액세스 키, IAM-008 루트 최근 사용."""

from kompass.config import Settings
from kompass.models import Finding, Severity, Status
from kompass.rules.base import BaseRule
from kompass.rules.iam.iam_001_root_mfa import Iam001RootMfa
from kompass.rules.iam.iam_002_root_access_key import Iam002RootAccessKey
from kompass.rules.iam.iam_008_root_recent_use import Iam008RootRecentUse
from tests.rules.iam.data import collect_error, days_ago, root_row, snapshot, summary

IAM001 = Iam001RootMfa()
IAM002 = Iam002RootAccessKey()
IAM008 = Iam008RootRecentUse()
NO_ROOT_CREDENTIALS = root_row(password=False, password_last_changed="N/A", mfa=False)


def _one(rule: BaseRule, **kwargs: object) -> Finding:
    [finding] = rule.evaluate(snapshot(**kwargs), Settings())  # type: ignore[arg-type]
    return finding


# --- IAM-001 ---


def test_iam001_pass() -> None:
    finding = _one(IAM001)
    assert finding.status == Status.PASS
    assert finding.resource == "account"
    assert finding.severity == Severity.CRITICAL


def test_iam001_fail() -> None:
    assert _one(IAM001, account_summary=summary(mfa=0)).status == Status.FAIL


def test_iam001_not_applicable_without_root_credentials() -> None:
    # Organizations의 루트 자격증명 중앙 관리로 루트 자격증명이 삭제된 멤버 계정
    finding = _one(IAM001, account_summary=summary(mfa=0), rows=[NO_ROOT_CREDENTIALS])
    assert finding.status == Status.NOT_APPLICABLE


def test_iam001_fail_when_report_missing() -> None:
    # 보고서가 없어 루트 자격증명 여부를 모르면 요약만으로 판정한다 (안전한 쪽인 FAIL)
    finding = _one(IAM001, account_summary=summary(mfa=0), missing=("credential_report",))
    assert finding.status == Status.FAIL
    assert finding.evidence["root_has_credentials"] is None


def test_iam001_error() -> None:
    finding = _one(
        IAM001, missing=("account_summary",), errors=(collect_error("iam:GetAccountSummary"),)
    )
    assert finding.status == Status.ERROR


# --- IAM-002 ---


def test_iam002_pass() -> None:
    finding = _one(IAM002)
    assert finding.status == Status.PASS
    assert finding.severity == Severity.CRITICAL


def test_iam002_fail() -> None:
    finding = _one(IAM002, account_summary=summary(root_keys=1))
    assert finding.status == Status.FAIL
    assert finding.evidence["AccountAccessKeysPresent"] == 1


def test_iam002_error() -> None:
    finding = _one(
        IAM002, missing=("account_summary",), errors=(collect_error("iam:GetAccountSummary"),)
    )
    assert finding.status == Status.ERROR


# --- IAM-008 ---


def test_iam008_review_recent_password_use() -> None:
    finding = _one(IAM008, rows=[root_row(password_last_used=days_ago(5))])
    assert finding.status == Status.REVIEW
    assert finding.severity == Severity.HIGH
    assert finding.evidence["last_used"] == days_ago(5)


def test_iam008_review_recent_key_use() -> None:
    row = root_row(password_last_used=days_ago(200), key1=days_ago(300), key1_last_used=days_ago(1))
    assert _one(IAM008, rows=[row]).status == Status.REVIEW


def test_iam008_pass_old_use() -> None:
    finding = _one(IAM008, rows=[root_row(password_last_used=days_ago(91))])
    assert finding.status == Status.PASS


def test_iam008_review_when_password_use_unknown() -> None:
    # 사용자 결정 (A): no_information은 "사용 안 함"이 아니다. 실습 계정에서 루트로 로그인한
    # 직후에도 no_information이었다
    finding = _one(IAM008, rows=[root_row(password_last_used="no_information")])
    assert finding.status == Status.REVIEW
    assert "확인할 수 없음" in finding.message


def test_iam008_not_applicable_without_root_credentials() -> None:
    assert _one(IAM008, rows=[NO_ROOT_CREDENTIALS]).status == Status.NOT_APPLICABLE


def test_iam008_error_report_missing() -> None:
    finding = _one(
        IAM008,
        missing=("credential_report",),
        errors=(collect_error("iam:GenerateCredentialReport"),),
    )
    assert finding.status == Status.ERROR


def test_iam008_error_root_row_missing() -> None:
    assert _one(IAM008, rows=[]).status == Status.ERROR
