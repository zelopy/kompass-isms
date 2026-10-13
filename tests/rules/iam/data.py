"""IAM 룰 테스트용 가짜 데이터. 실습 계정에서 확인한 실제 응답 형태를 따른다.

- 자격증명 보고서는 22개 열, 값은 문자열. 날짜가 없으면 `N/A`, 비밀번호 미사용은 `no_information`
- 정책 문서는 이미 dict로 풀려 있다
값 None은 "설정 없음", 키 없음은 "수집 실패"다 (collector 규약).
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from kompass.models import CollectError, Snapshot

T0 = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)  # 스냅샷 수집 시각 = 경과 일수 기준
ACCOUNT = "123456789012"
ROOT_ARN = f"arn:aws:iam::{ACCOUNT}:root"
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
READONLY_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
_UNSET = object()


def days_ago(days: int) -> str:
    return (T0 - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def user_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:user/{name}"


def report_row(
    user: str,
    *,
    password: bool = False,
    password_last_used: str = "N/A",
    password_last_changed: str = "N/A",
    mfa: bool = False,
    key1: str | None = None,
    key1_last_used: str = "N/A",
    key2: str | None = None,
    key2_last_used: str = "N/A",
) -> dict[str, str]:
    """`key1`/`key2`에 날짜(마지막 교체일)를 주면 활성 키가 된다."""
    is_root = user == "<root_account>"
    row = {
        "user": user,
        "arn": ROOT_ARN if is_root else user_arn(user),
        "user_creation_time": days_ago(400),
        "password_enabled": "true" if password else "false",
        "password_last_used": password_last_used,
        "password_last_changed": password_last_changed,
        "password_next_rotation": "N/A",
        "mfa_active": "true" if mfa else "false",
        "cert_1_active": "false",
        "cert_1_last_rotated": "N/A",
        "cert_2_active": "false",
        "cert_2_last_rotated": "N/A",
    }
    for slot, rotated, used in ((1, key1, key1_last_used), (2, key2, key2_last_used)):
        row[f"access_key_{slot}_active"] = "true" if rotated else "false"
        row[f"access_key_{slot}_last_rotated"] = rotated or "N/A"
        row[f"access_key_{slot}_last_used_date"] = used
        row[f"access_key_{slot}_last_used_region"] = "N/A"
        row[f"access_key_{slot}_last_used_service"] = "N/A"
    return row


def root_row(**kwargs: Any) -> dict[str, str]:
    kwargs.setdefault("password", True)
    kwargs.setdefault("password_last_used", "no_information")
    kwargs.setdefault("password_last_changed", days_ago(10))
    kwargs.setdefault("mfa", True)
    return report_row("<root_account>", **kwargs)


def summary(mfa: int = 1, root_keys: int = 0) -> dict[str, int]:
    return {"AccountMFAEnabled": mfa, "AccountAccessKeysPresent": root_keys, "Users": 3}


def statement(
    effect: str = "Allow", action: Any = "*", resource: Any = "*", not_action: Any = None
) -> dict[str, Any]:
    stmt: dict[str, Any] = {"Effect": effect, "Resource": resource}
    if not_action is not None:
        stmt["NotAction"] = not_action
    else:
        stmt["Action"] = action
    return stmt


def document(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def iam_user(
    name: str,
    *,
    attached: tuple[str, ...] = (),
    inline: dict[str, dict[str, Any]] | None = None,
    groups: tuple[str, ...] = (),
    boundary: str | None = None,
) -> dict[str, Any]:
    user: dict[str, Any] = {
        "UserName": name,
        "Arn": user_arn(name),
        "Path": "/",
        "GroupList": list(groups),
        "AttachedManagedPolicies": [
            {"PolicyArn": a, "PolicyName": a.split("/")[-1]} for a in attached
        ],
    }
    if inline:
        user["UserPolicyList"] = [{"PolicyName": k, "PolicyDocument": v} for k, v in inline.items()]
    if boundary:
        user["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary}
    return user


def iam_group(
    name: str, *, attached: tuple[str, ...] = (), inline: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    group: dict[str, Any] = {
        "GroupName": name,
        "Arn": f"arn:aws:iam::{ACCOUNT}:group/{name}",
        "AttachedManagedPolicies": [
            {"PolicyArn": a, "PolicyName": a.split("/")[-1]} for a in attached
        ],
        "GroupPolicyList": [
            {"PolicyName": k, "PolicyDocument": v} for k, v in (inline or {}).items()
        ],
    }
    return group


def managed_policy(arn: str, doc: dict[str, Any]) -> dict[str, Any]:
    return {"Arn": arn, "DefaultVersionId": "v1", "Document": doc}


def sso_role(name: str = "AWSReservedSSO_AdministratorAccess_abc") -> dict[str, Any]:
    return {
        "RoleName": name,
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/{name}",
        "Path": "/aws-reserved/sso.amazonaws.com/",
    }


def snapshot(
    *,
    account_summary: Any = _UNSET,
    password_policy: Any = None,
    rows: Any = _UNSET,
    users: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
    roles: list[dict[str, Any]] | None = None,
    policies: list[dict[str, Any]] | None = None,
    saml: list[dict[str, Any]] | None = None,
    oidc: list[dict[str, Any]] | None = None,
    identity_center: dict[str, list[dict[str, Any]]] | None = None,
    missing: tuple[str, ...] = (),
    errors: tuple[CollectError, ...] = (),
) -> Snapshot:
    data: dict[str, Any] = {
        "account_summary": summary() if account_summary is _UNSET else account_summary,
        "password_policy": password_policy,
        "credential_report": {
            "generated_time": days_ago(0),
            "rows": [root_row()] if rows is _UNSET else rows,
        },
        "authorization_details": {
            "users": users or [],
            "groups": groups or [],
            "roles": roles or [],
            "policies": policies or [],
        },
        "saml_providers": saml or [],
        "oidc_providers": oidc or [],
        "identity_center_instances": {"ap-northeast-2": []}
        if identity_center is None
        else identity_center,
    }
    for key in missing:
        del data[key]
    return Snapshot(
        service="iam",
        account_id=ACCOUNT,
        regions=("ap-northeast-2",),
        collected_at=T0,
        data=data,
        errors=errors,
    )


def collect_error(operation: str, region: str | None = None) -> CollectError:
    return CollectError(operation=operation, region=region, error_code="AccessDenied", message="no")
