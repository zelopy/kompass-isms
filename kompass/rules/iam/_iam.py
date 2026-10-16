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


def unreported_users(
    rule: BaseRule, snapshot: Snapshot, rows: list[dict[str, str]]
) -> list[Finding]:
    """권한 정보에는 있지만 자격증명 보고서에 없는 사용자마다 ERROR (ADR-045).

    `GenerateCredentialReport`는 4시간 안에 만든 보고서를 다시 돌려주므로, 그 뒤에 만든 사용자는
    보고서에 없다. 판정하지 못한 사용자를 조용히 빼면 "대상 없음"으로 잘못 보고하게 된다 (원칙 3).
    권한 정보를 수집하지 못했으면 대조할 수 없으므로 아무것도 내지 않는다.
    """
    details = snapshot.data.get("authorization_details")
    if details is None:
        return []
    reported = {row.get("user") for row in rows}
    generated = snapshot.data["credential_report"]["generated_time"]
    return [
        rule.finding(
            snapshot,
            resource=user["Arn"],
            region=None,
            status=Status.ERROR,
            message=(
                f"자격증명 보고서 생성 이후 확인된 사용자라 판정할 수 없음: {user['UserName']}"
            ),
            evidence={
                "user": user["UserName"],
                "user_created": user.get("CreateDate"),
                "report_generated_time": generated,
                "note": "자격증명 보고서는 최대 4시간 전 상태일 수 있음. 다음 점검에서 확인 필요",
            },
        )
        for user in details.get("users", [])
        if user.get("UserName") not in reported
    ]
