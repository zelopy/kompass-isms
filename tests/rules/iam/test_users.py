"""IAM-003 콘솔 MFA, IAM-004 비밀번호 정책, IAM-005 장기 미사용, IAM-006 키 교체."""

from typing import Any

import pytest

from kompass.config import IamSettings, PasswordPolicySettings, Settings
from kompass.models import Finding, Severity, Status
from kompass.rules.base import BaseRule
from kompass.rules.iam.iam_003_console_user_mfa import Iam003ConsoleUserMfa
from kompass.rules.iam.iam_004_password_policy import Iam004PasswordPolicy
from kompass.rules.iam.iam_005_unused_credentials import Iam005UnusedCredentials
from kompass.rules.iam.iam_006_access_key_rotation import Iam006AccessKeyRotation
from tests.rules.iam.data import (
    collect_error,
    days_ago,
    iam_user,
    report_row,
    root_row,
    snapshot,
    user_arn,
)

IAM003 = Iam003ConsoleUserMfa()
IAM004 = Iam004PasswordPolicy()
IAM005 = Iam005UnusedCredentials()
IAM006 = Iam006AccessKeyRotation()


def _all(rule: BaseRule, settings: Settings | None = None, **kwargs: Any) -> list[Finding]:
    return rule.evaluate(snapshot(**kwargs), settings or Settings())


def _one(rule: BaseRule, settings: Settings | None = None, **kwargs: Any) -> Finding:
    [finding] = _all(rule, settings, **kwargs)
    return finding


# --- IAM-003 ---


def test_iam003_fail_console_without_mfa() -> None:
    finding = _one(IAM003, rows=[root_row(), report_row("alice", password=True)])
    assert finding.status == Status.FAIL
    assert finding.resource == user_arn("alice")
    assert finding.severity == Severity.HIGH


def test_iam003_pass_console_with_mfa() -> None:
    assert _one(IAM003, rows=[report_row("alice", password=True, mfa=True)]).status == Status.PASS


def test_iam003_excludes_root_and_programmatic_users() -> None:
    rows = [root_row(mfa=False), report_row("bot", key1=days_ago(1))]
    assert _one(IAM003, rows=rows).status == Status.NOT_APPLICABLE


def test_iam003_error() -> None:
    finding = _one(
        IAM003, missing=("credential_report",), errors=(collect_error("iam:GetCredentialReport"),)
    )
    assert finding.status == Status.ERROR


# --- IAM-004 ---


def _policy(length: int, upper: bool, lower: bool, numbers: bool, symbols: bool) -> dict[str, Any]:
    return {
        "MinimumPasswordLength": length,
        "RequireUppercaseCharacters": upper,
        "RequireLowercaseCharacters": lower,
        "RequireNumbers": numbers,
        "RequireSymbols": symbols,
    }


@pytest.mark.parametrize(
    ("policy", "expected", "types"),
    [
        (_policy(8, False, True, True, True), Status.PASS, 3),  # 3종 8자
        (_policy(10, True, True, True, False), Status.PASS, 2),  # 영문자+숫자 2종 10자
        (_policy(8, True, True, True, False), Status.FAIL, 2),  # 2종 8자 (실습 weak)
        (_policy(9, False, False, True, True), Status.FAIL, 2),  # 2종 9자
        (_policy(20, True, True, False, False), Status.FAIL, 1),  # 대·소문자는 영문자 1종
        (_policy(8, False, False, False, False), Status.FAIL, 0),
    ],
)
def test_iam004_kisa_criteria(policy: dict[str, Any], expected: Status, types: int) -> None:
    finding = _one(IAM004, password_policy=policy)
    assert finding.status == expected
    assert finding.evidence["character_types"] == types


def test_iam004_fail_no_policy() -> None:
    # NoSuchEntity는 ERROR가 아니라 FAIL이다 (AWS 기본 정책은 KISA 기준을 보장하지 못한다)
    finding = _one(IAM004, password_policy=None)
    assert finding.status == Status.FAIL
    assert finding.severity == Severity.MEDIUM


def test_iam004_evidence_notes_login_attempt_limit_out_of_scope() -> None:
    finding = _one(IAM004, password_policy=_policy(8, False, True, True, True))
    assert finding.evidence["login_attempt_limit"] == "IAM 비밀번호 정책으로 확인할 수 없음"


def test_iam004_lengths_from_settings() -> None:
    strict = Settings(
        iam=IamSettings(password_policy=PasswordPolicySettings(min_length_three_types=12))
    )
    assert _one(IAM004, strict, password_policy=_policy(10, False, True, True, True)).status == (
        Status.FAIL
    )


def test_iam004_error() -> None:
    finding = _one(
        IAM004,
        missing=("password_policy",),
        errors=(collect_error("iam:GetAccountPasswordPolicy"),),
    )
    assert finding.status == Status.ERROR


# --- IAM-005 ---


def test_iam005_fail_stale_password() -> None:
    row = report_row("alice", password=True, password_last_used=days_ago(91))
    finding = _one(IAM005, rows=[row])
    assert finding.status == Status.FAIL
    assert finding.evidence["credentials"][0]["days_since_last_use"] == 91
    assert finding.severity == Severity.MEDIUM


def test_iam005_pass_recent_password() -> None:
    row = report_row("alice", password=True, password_last_used=days_ago(89))
    assert _one(IAM005, rows=[row]).status == Status.PASS


def test_iam005_never_used_password_uses_last_changed() -> None:
    new = report_row(
        "new", password=True, password_last_used="no_information", password_last_changed=days_ago(3)
    )
    old = report_row(
        "old",
        password=True,
        password_last_used="no_information",
        password_last_changed=days_ago(200),
    )
    statuses = {f.resource: f.status for f in _all(IAM005, rows=[new, old])}
    assert statuses == {user_arn("new"): Status.PASS, user_arn("old"): Status.FAIL}


def test_iam005_never_used_key_uses_last_rotated() -> None:
    row = report_row("bot", key1=days_ago(120))
    assert _one(IAM005, rows=[row]).status == Status.FAIL


def test_iam005_any_stale_credential_fails_user() -> None:
    row = report_row(
        "alice",
        password=True,
        password_last_used=days_ago(1),
        key1=days_ago(200),
        key1_last_used=days_ago(150),
    )
    assert _one(IAM005, rows=[row]).status == Status.FAIL


def test_iam005_not_applicable_without_active_credentials() -> None:
    rows = [root_row(password_last_used=days_ago(500)), report_row("disabled")]
    assert _one(IAM005, rows=rows).status == Status.NOT_APPLICABLE


def test_iam005_days_from_settings() -> None:
    settings = Settings(iam=IamSettings(unused_credential_days=30))
    row = report_row("alice", password=True, password_last_used=days_ago(45))
    assert _one(IAM005, settings, rows=[row]).status == Status.FAIL


def test_iam005_error() -> None:
    finding = _one(
        IAM005, missing=("credential_report",), errors=(collect_error("iam:GetCredentialReport"),)
    )
    assert finding.status == Status.ERROR


# --- IAM-006 ---


def test_iam006_finding_per_active_key() -> None:
    row = report_row("bot", key1=days_ago(100), key2=days_ago(10))
    findings = {f.resource: f.status for f in _all(IAM006, rows=[row])}
    assert findings == {
        f"{user_arn('bot')}#access_key_1": Status.FAIL,
        f"{user_arn('bot')}#access_key_2": Status.PASS,
    }


def test_iam006_root_keys_excluded() -> None:
    rows = [root_row(key1=days_ago(500))]
    assert _one(IAM006, rows=rows).status == Status.NOT_APPLICABLE


def test_iam006_evidence() -> None:
    finding = _one(IAM006, rows=[report_row("bot", key1=days_ago(100))])
    assert finding.evidence["last_rotated"] == days_ago(100)
    assert finding.evidence["days_since_rotation"] == 100
    assert finding.severity == Severity.MEDIUM


def test_iam006_error() -> None:
    finding = _one(
        IAM006, missing=("credential_report",), errors=(collect_error("iam:GetCredentialReport"),)
    )
    assert finding.status == Status.ERROR


# --- 자격증명 보고서에 없는 사용자 (ADR-045) ---


@pytest.mark.parametrize(
    "rule_cls", [Iam003ConsoleUserMfa, Iam005UnusedCredentials, Iam006AccessKeyRotation]
)
def test_user_missing_from_credential_report_is_error(rule_cls: Any) -> None:
    # 보고서는 4시간 안에 만든 것이 재사용되므로 그 뒤에 만든 사용자는 보고서에 없다
    data = snapshot(rows=[root_row()], users=[iam_user("new-user")])
    findings = rule_cls().evaluate(data, Settings())
    [finding] = findings
    assert finding.status == Status.ERROR and finding.resource == user_arn("new-user")
    assert "자격증명 보고서 생성 이후" in finding.message


def test_reported_users_are_not_flagged_as_missing() -> None:
    data = snapshot(
        rows=[root_row(), report_row("dev", password=True, mfa=True)],
        users=[iam_user("dev")],
    )
    [finding] = Iam003ConsoleUserMfa().evaluate(data, Settings())
    assert finding.status == Status.PASS
