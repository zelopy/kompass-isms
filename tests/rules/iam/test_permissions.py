"""IAM-007 관리자 권한 사용자, IAM-009 외부 자격증명 공급자."""

from typing import Any

from kompass.config import Settings
from kompass.models import Finding, Severity, Status
from kompass.rules.iam.iam_007_admin_users import Iam007AdminUsers
from kompass.rules.iam.iam_009_external_identity import Iam009ExternalIdentity
from tests.rules.iam.data import (
    ACCOUNT,
    ADMIN_POLICY_ARN,
    READONLY_POLICY_ARN,
    collect_error,
    document,
    iam_group,
    iam_user,
    managed_policy,
    snapshot,
    sso_role,
    statement,
    user_arn,
)

IAM007 = Iam007AdminUsers()
IAM009 = Iam009ExternalIdentity()
CUSTOM_ARN = f"arn:aws:iam::{ACCOUNT}:policy/wildcard"


def _findings(rule: Any, **kwargs: Any) -> list[Finding]:
    return rule.evaluate(snapshot(**kwargs), Settings())  # type: ignore[no-any-return]


def _by_resource(findings: list[Finding]) -> dict[str, Status]:
    return {f.resource: f.status for f in findings}


# --- IAM-007 ---


def test_iam007_direct_aws_admin_policy_fails() -> None:
    [finding] = _findings(IAM007, users=[iam_user("alice", attached=(ADMIN_POLICY_ARN,))])
    assert finding.status == Status.FAIL
    assert finding.resource == user_arn("alice")
    assert finding.severity == Severity.HIGH
    assert finding.evidence["sources"] == [
        {"via": "user", "policy": ADMIN_POLICY_ARN, "kind": "admin"}
    ]


def test_iam007_direct_customer_wildcard_policy_fails() -> None:
    findings = _findings(
        IAM007,
        users=[iam_user("bob", attached=(CUSTOM_ARN,))],
        policies=[managed_policy(CUSTOM_ARN, document(statement()))],
    )
    assert _by_resource(findings) == {user_arn("bob"): Status.FAIL}


def test_iam007_direct_inline_wildcard_fails() -> None:
    user = iam_user("carol", inline={"all": document(statement(action=["*"], resource=["*"]))})
    assert _by_resource(_findings(IAM007, users=[user])) == {user_arn("carol"): Status.FAIL}


def test_iam007_group_admin_is_review() -> None:
    findings = _findings(
        IAM007,
        users=[iam_user("dave", groups=("admins",))],
        groups=[iam_group("admins", attached=(ADMIN_POLICY_ARN,))],
    )
    [finding] = findings
    assert finding.status == Status.REVIEW
    assert finding.evidence["sources"][0]["via"] == "group:admins"


def test_iam007_group_inline_admin_is_review() -> None:
    findings = _findings(
        IAM007,
        users=[iam_user("erin", groups=("ops",))],
        groups=[iam_group("ops", inline={"all": document(statement())})],
    )
    assert _by_resource(findings) == {user_arn("erin"): Status.REVIEW}


def test_iam007_not_action_is_review() -> None:
    user = iam_user("frank", inline={"na": document(statement(not_action=["iam:*"]))})
    [finding] = _findings(IAM007, users=[user])
    assert finding.status == Status.REVIEW
    assert finding.evidence["sources"][0]["kind"] == "ambiguous"


def test_iam007_direct_admin_wins_over_group() -> None:
    findings = _findings(
        IAM007,
        users=[iam_user("gina", attached=(ADMIN_POLICY_ARN,), groups=("admins",))],
        groups=[iam_group("admins", attached=(ADMIN_POLICY_ARN,))],
    )
    assert _by_resource(findings) == {user_arn("gina"): Status.FAIL}


def test_iam007_scoped_policies_are_not_admin() -> None:
    users = [
        iam_user("ro", attached=(READONLY_POLICY_ARN,)),
        iam_user("s3", inline={"s3": document(statement(action="s3:*", resource="*"))}),
        iam_user("one", inline={"x": document(statement(action="*", resource="arn:aws:s3:::b"))}),
        iam_user("deny", inline={"d": document(statement(effect="Deny"))}),
    ]
    policies = [managed_policy(READONLY_POLICY_ARN, document(statement(action="s3:Get*")))]
    [finding] = _findings(IAM007, users=users, policies=policies)
    assert finding.status == Status.PASS
    assert finding.resource == "account"


def test_iam007_single_statement_dict_document() -> None:
    doc = {"Version": "2012-10-17", "Statement": statement()}
    user = iam_user("hal", inline={"one": doc})
    assert _by_resource(_findings(IAM007, users=[user])) == {user_arn("hal"): Status.FAIL}


def test_iam007_records_permissions_boundary() -> None:
    user = iam_user("ivy", attached=(ADMIN_POLICY_ARN,), boundary="arn:aws:iam::aws:policy/X")
    [finding] = _findings(IAM007, users=[user])
    assert finding.status == Status.FAIL
    assert finding.evidence["permissions_boundary"] == "arn:aws:iam::aws:policy/X"


def test_iam007_unknown_managed_policy_is_review() -> None:
    # 고객 관리형 정책 본문이 응답에 없으면 관리자 여부를 확정할 수 없다
    [finding] = _findings(IAM007, users=[iam_user("jay", attached=(CUSTOM_ARN,))])
    assert finding.status == Status.REVIEW


def test_iam007_error() -> None:
    [finding] = _findings(
        IAM007,
        missing=("authorization_details",),
        errors=(collect_error("iam:GetAccountAuthorizationDetails"),),
    )
    assert finding.status == Status.ERROR


# --- IAM-009 ---


def test_iam009_review_each_provider() -> None:
    findings = _findings(
        IAM009,
        saml=[{"Arn": f"arn:aws:iam::{ACCOUNT}:saml-provider/okta"}],
        oidc=[{"Arn": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"}],
        identity_center={"us-east-1": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-1"}]},
    )
    assert {f.status for f in findings} == {Status.REVIEW}
    assert {f.evidence["kind"] for f in findings} == {"saml", "oidc", "identity_center"}
    assert all(f.severity == Severity.MEDIUM for f in findings)


def test_iam009_review_identity_center_roles_in_member_account() -> None:
    # 사용자 결정 (B): 멤버 계정에는 인스턴스가 없지만 Identity Center가 만든 역할이 있다
    [finding] = _findings(IAM009, roles=[sso_role()])
    assert finding.status == Status.REVIEW
    assert finding.evidence["kind"] == "identity_center_roles"
    assert finding.evidence["roles"] == [sso_role()["Arn"]]


def test_iam009_not_applicable_without_external_identity() -> None:
    [finding] = _findings(IAM009, roles=[{"RoleName": "app", "Arn": "arn:x", "Path": "/"}])
    assert finding.status == Status.NOT_APPLICABLE


def test_iam009_error_when_nothing_found_and_collection_failed() -> None:
    [finding] = _findings(
        IAM009,
        identity_center={"ap-northeast-2": []},
        errors=(collect_error("sso-admin:ListInstances", "us-east-1"),),
    )
    assert finding.status == Status.ERROR


def test_iam009_review_even_if_other_collection_failed() -> None:
    findings = _findings(
        IAM009,
        oidc=[{"Arn": "arn:aws:iam::123456789012:oidc-provider/x"}],
        missing=("saml_providers",),
        errors=(collect_error("iam:ListSAMLProviders"),),
    )
    assert [f.status for f in findings] == [Status.REVIEW]
