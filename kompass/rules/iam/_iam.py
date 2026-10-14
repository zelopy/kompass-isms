"""IAM 룰 공용 부품. 모두 `iam` 스냅샷 하나만 본다 (ADR-015).

collector 규약: 값이 None이면 "설정 없음", 키가 없으면 "수집 실패"다.
경과 일수는 판정 시각이 아니라 스냅샷 수집 시각을 기준으로 계산한다. 같은 스냅샷이면 언제
다시 판정해도 같은 결과가 나와야 한다 (ADR-001, ADR-003).
"""

from datetime import datetime
from typing import Any

from kompass.models import Finding, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence, errors_for

ROOT_USER = "<root_account>"
KEY_SLOTS = (1, 2)

# 데이터 키 → 수집 오퍼레이션 (오류 기록 대조용)
OPERATIONS: dict[str, tuple[str, ...]] = {
    "account_summary": ("iam:GetAccountSummary",),
    "password_policy": ("iam:GetAccountPasswordPolicy",),
    "credential_report": ("iam:GenerateCredentialReport", "iam:GetCredentialReport"),
    "authorization_details": ("iam:GetAccountAuthorizationDetails",),
    "saml_providers": ("iam:ListSAMLProviders",),
    "oidc_providers": ("iam:ListOpenIDConnectProviders",),
    "identity_center_instances": ("sso-admin:ListInstances",),
}


def section_errors(snapshot: Snapshot, *keys: str) -> list[dict[str, Any]]:
    errors = [e for key in keys for op in OPERATIONS[key] for e in errors_for(snapshot, op)]
    return errors_evidence(errors)


def report_rows(snapshot: Snapshot) -> list[dict[str, str]] | None:
    report = snapshot.data.get("credential_report")
    return None if report is None else list(report["rows"])


def root_row(rows: list[dict[str, str]]) -> dict[str, str] | None:
    return next((r for r in rows if r.get("user") == ROOT_USER), None)


def user_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [r for r in rows if r.get("user") != ROOT_USER]


def is_true(value: str | None) -> bool:
    return value == "true"


def active_key_slots(row: dict[str, str]) -> list[int]:
    return [n for n in KEY_SLOTS if is_true(row.get(f"access_key_{n}_active"))]


def has_credentials(row: dict[str, str]) -> bool:
    """콘솔 비밀번호나 활성 액세스 키가 있는가."""
    return is_true(row.get("password_enabled")) or bool(active_key_slots(row))


def days_between(earlier: datetime, later: datetime) -> int:
    return (later - earlier).days


def account_finding(
    rule: BaseRule, snapshot: Snapshot, status: Status, message: str, evidence: dict[str, Any]
) -> Finding:
    return rule.finding(
        snapshot,
        resource=ACCOUNT_RESOURCE,
        region=None,
        status=status,
        message=message,
        evidence=evidence,
    )


def missing_section(rule: BaseRule, snapshot: Snapshot, key: str, what: str) -> Finding:
    return account_finding(
        rule,
        snapshot,
        Status.ERROR,
        f"{what}을(를) 수집하지 못함",
        {"errors": section_errors(snapshot, key)},
    )
