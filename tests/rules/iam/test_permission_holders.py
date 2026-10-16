"""IAM-010 인스턴스 생성·접근 권한, IAM-011 네트워크 리소스 변경 권한 보유 주체 현황."""

from datetime import UTC, datetime
from typing import Any

import pytest

from kompass.config import IamSettings, Settings
from kompass.models import CollectError, Finding, Snapshot, Status
from kompass.rules.iam._permissions import action_matches, granted_actions
from kompass.rules.iam.iam_010_instance_permissions import Iam010InstancePermissions
from kompass.rules.iam.iam_011_network_permissions import Iam011NetworkPermissions

ACCOUNT = "123456789012"
IAM010 = Iam010InstancePermissions()
IAM011 = Iam011NetworkPermissions()


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action: Any, **extra: Any) -> dict[str, Any]:
    return {"Effect": "Allow", "Action": action, "Resource": "*", **extra}


def managed(name: str, document: dict[str, Any] | None, aws: bool = False) -> dict[str, Any]:
    owner = "aws" if aws else ACCOUNT
    item: dict[str, Any] = {"PolicyName": name, "Arn": f"arn:aws:iam::{owner}:policy/{name}"}
    if document is not None:
        item["Document"] = document
    return item


def attached(policy: dict[str, Any]) -> dict[str, str]:
    return {"PolicyName": policy["PolicyName"], "PolicyArn": policy["Arn"]}


def user(
    name: str,
    *,
    policies: tuple[dict[str, Any], ...] = (),
    inline: tuple[Any, ...] = (),
    groups: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "UserName": name,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "AttachedManagedPolicies": [attached(p) for p in policies],
        "UserPolicyList": [{"PolicyName": n, "PolicyDocument": d} for n, d in inline],
        "GroupList": list(groups),
    }


def role(
    name: str, *, policies: tuple[dict[str, Any], ...] = (), path: str = "/"
) -> dict[str, Any]:
    return {
        "RoleName": name,
        "Path": path,
        "Arn": f"arn:aws:iam::{ACCOUNT}:role{path}{name}",
        "AttachedManagedPolicies": [attached(p) for p in policies],
        "RolePolicyList": [],
    }


def group(name: str, *, policies: tuple[dict[str, Any], ...] = ()) -> dict[str, Any]:
    return {
        "GroupName": name,
        "AttachedManagedPolicies": [attached(p) for p in policies],
        "GroupPolicyList": [],
    }


def _run(
    rule: Any, details: dict[str, Any] | None, settings: Settings | None = None
) -> list[Finding]:
    data: dict[str, Any] = {}
    errors: tuple[CollectError, ...] = ()
    if details is None:
        errors = (
            CollectError(
                operation="iam:GetAccountAuthorizationDetails",
                region=None,
                error_code="AccessDenied",
                message="m",
            ),
        )
    else:
        data["authorization_details"] = {
            "users": [],
            "groups": [],
            "roles": [],
            "policies": [],
            **details,
        }
    snapshot = Snapshot(
        service="iam",
        account_id=ACCOUNT,
        regions=(),
        collected_at=datetime(2026, 10, 16, tzinfo=UTC),
        data=data,
        errors=errors,
    )
    findings: list[Finding] = rule.evaluate(snapshot, settings or Settings())
    return findings


# --- 작업 일치 ---


@pytest.mark.parametrize(
    ("pattern", "action", "expected"),
    [
        ("*", "ec2:RunInstances", True),
        ("ec2:*", "ec2:RunInstances", True),
        ("EC2:runinstances", "ec2:RunInstances", True),  # 대소문자 구분 없음
        ("ec2:Run*", "ec2:RunInstances", True),
        ("ec2:Describe*", "ec2:RunInstances", False),
        ("ec2:RunInstance?", "ec2:RunInstances", True),
        ("s3:*", "ec2:RunInstances", False),
    ],
)
def test_action_matches(pattern: str, action: str, expected: bool) -> None:
    assert action_matches(pattern, action) is expected


def test_granted_actions_handles_not_action_and_conditions() -> None:
    document = doc(
        allow("ec2:Run*", Condition={"StringEquals": {"aws:RequestedRegion": "ap-northeast-2"}}),
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "ec2:TerminateInstances", "Resource": "*"},
    )
    grants = granted_actions(
        document, ("ec2:RunInstances", "ec2:TerminateInstances", "iam:PassRole")
    )
    assert grants == {
        "ec2:RunInstances": {"conditional": False, "not_action": True},
        "ec2:TerminateInstances": {"conditional": False, "not_action": True},
    }


# --- IAM-010 ---


def test_iam010_review_for_users_and_roles_with_instance_actions() -> None:
    ec2_full = managed("AmazonEC2FullAccess", doc(allow("ec2:*")), aws=True)
    readonly = managed("ReadOnly", doc(allow("ec2:Describe*")))
    session = managed("Session", doc(allow("ssm:StartSession")))
    details = {
        "users": [
            user("operator", policies=(ec2_full,)),
            user("viewer", policies=(readonly,)),
            user("member", groups=("ops",)),
        ],
        "groups": [group("ops", policies=(session,))],
        "roles": [role("deployer", policies=(ec2_full,))],
        "policies": [ec2_full, readonly, session],
    }
    findings = {f.resource.split(":", 5)[-1]: f for f in _run(IAM010, details)}
    assert set(findings) == {"user/operator", "user/member", "role/deployer"}
    assert all(f.status == Status.REVIEW for f in findings.values())
    member = findings["user/member"]
    assert member.evidence["actions"] == ["ssm:StartSession"]
    assert member.evidence["sources"][0]["via"] == "group:ops"


def test_iam010_inline_policy_and_conditions_are_recorded() -> None:
    inline = doc(
        allow("ec2:RunInstances", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})
    )
    [finding] = _run(IAM010, {"users": [user("dev", inline=(("launch", inline),))]})
    source = finding.evidence["sources"][0]
    assert source["policy"] == "inline:launch" and source["conditional"] is True


def test_iam010_service_linked_roles_are_excluded() -> None:
    admin = managed("AdministratorAccess", doc(allow("*")), aws=True)
    details = {
        "roles": [
            role("AWSServiceRoleForX", policies=(admin,), path="/aws-service-role/x.amazonaws.com/")
        ],
        "policies": [admin],
    }
    [finding] = _run(IAM010, details)
    assert finding.status == Status.PASS and finding.evidence["excluded_service_roles"] == 1


def test_iam010_unknown_policy_body_is_review() -> None:
    missing = managed("Unknown", None)
    [finding] = _run(IAM010, {"users": [user("dev", policies=(missing,))]})
    assert finding.status == Status.REVIEW
    assert finding.evidence["actions"] == [] and finding.evidence["unknown_policies"]


def test_iam010_pass_when_nobody_has_permissions() -> None:
    [finding] = _run(IAM010, {"users": [user("nobody")]})
    assert finding.status == Status.PASS and finding.resource == "account"


def test_iam010_error_when_details_missing() -> None:
    [finding] = _run(IAM010, None)
    assert finding.status == Status.ERROR


def test_iam010_actions_from_settings() -> None:
    settings = Settings(iam=IamSettings(instance_actions=("lambda:CreateFunction",)))
    policy = managed("Lambda", doc(allow("lambda:*")))
    details = {"users": [user("dev", policies=(policy,))], "policies": [policy]}
    [finding] = _run(IAM010, details, settings)
    assert finding.status == Status.REVIEW and finding.evidence["actions"] == [
        "lambda:CreateFunction"
    ]


# --- IAM-011 ---


def test_iam011_network_actions() -> None:
    sg = managed(
        "SgAdmin",
        doc(allow(["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"])),
    )
    dns = managed("Dns", doc(allow("route53:ChangeResourceRecordSets")))
    instance = managed("Launch", doc(allow("ec2:RunInstances")))
    details = {
        "users": [user("netops", policies=(sg,)), user("dev", policies=(instance,))],
        "roles": [role("dns-updater", policies=(dns,))],
        "policies": [sg, dns, instance],
    }
    findings = {f.resource.split(":", 5)[-1]: f for f in _run(IAM011, details)}
    assert set(findings) == {"user/netops", "role/dns-updater"}
    assert findings["user/netops"].evidence["actions"] == [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress",
    ]
