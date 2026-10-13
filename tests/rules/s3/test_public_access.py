"""S3-001 계정 수준 차단, S3-002 버킷 수준 차단, S3-003 정책 공개, S3-006 ACL 공개."""

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import BaseRule
from kompass.rules.s3.s3_001_account_public_access_block import S3001AccountPublicAccessBlock
from kompass.rules.s3.s3_002_bucket_public_access_block import S3002BucketPublicAccessBlock
from kompass.rules.s3.s3_003_public_bucket_policy import S3003PublicBucketPolicy
from kompass.rules.s3.s3_006_public_bucket_acl import S3006PublicBucketAcl
from tests.rules.s3.data import (
    ALL_BLOCKED,
    ALL_USERS,
    AUTH_USERS,
    NONE_BLOCKED,
    REGION,
    acl,
    block,
    collect_error,
    details,
    ownership,
    snapshot,
)

S3001 = S3001AccountPublicAccessBlock()
S3002 = S3002BucketPublicAccessBlock()
S3003 = S3003PublicBucketPolicy()
S3006 = S3006PublicBucketAcl()


def _one(rule: BaseRule, data: Snapshot) -> Finding:
    [finding] = rule.evaluate(data, Settings())
    return finding


# --- S3-001 ---


def test_s3001_pass_all_blocked() -> None:
    finding = _one(S3001, snapshot({}, account_block=ALL_BLOCKED))
    assert finding.status == Status.PASS
    assert finding.resource == "account"
    assert finding.region is None
    assert finding.severity == Severity.HIGH


def test_s3001_fail_not_configured() -> None:
    finding = _one(S3001, snapshot({}, account_block=None))
    assert finding.status == Status.FAIL
    assert finding.evidence["public_access_block"] is None


def test_s3001_fail_partially_blocked() -> None:
    finding = _one(S3001, snapshot({}, account_block=block(policy=False)))
    assert finding.status == Status.FAIL
    assert finding.evidence["disabled_settings"] == ["BlockPublicPolicy"]


def test_s3001_error_not_collected() -> None:
    data = snapshot(
        {}, account_missing=True, errors=(collect_error("s3control:GetPublicAccessBlock"),)
    )
    finding = _one(S3001, data)
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["error_code"] == "AccessDenied"


# --- S3-002 ---


def test_s3002_pass_bucket_blocked() -> None:
    finding = _one(S3002, snapshot({"b": details()}))
    assert finding.status == Status.PASS
    assert finding.resource == "b"
    assert finding.region == REGION


def test_s3002_pass_by_account_level() -> None:
    finding = _one(
        S3002, snapshot({"b": details(public_access_block=None)}, account_block=ALL_BLOCKED)
    )
    assert finding.status == Status.PASS
    assert finding.evidence["account_public_access_block"] == ALL_BLOCKED


def test_s3002_fail_bucket_partially_blocked() -> None:
    finding = _one(S3002, snapshot({"b": details(public_access_block=block(False, False))}))
    assert finding.status == Status.FAIL


def test_s3002_fail_no_setting_anywhere() -> None:
    assert _one(S3002, snapshot({"b": details(public_access_block=None)})).status == Status.FAIL


def test_s3002_error_bucket_setting_unknown() -> None:
    data = snapshot(
        {"b": details(missing=("public_access_block",))},
        errors=(collect_error("s3:GetPublicAccessBlock", "b"),),
    )
    finding = _one(S3002, data)
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["resource"] == "b"


def test_s3002_unknown_bucket_setting_but_account_blocked_is_pass() -> None:
    data = snapshot({"b": details(missing=("public_access_block",))}, account_block=ALL_BLOCKED)
    assert _one(S3002, data).status == Status.PASS


def test_s3002_error_bucket_list_not_collected() -> None:
    data = snapshot(None, errors=(collect_error("s3:ListBuckets"),))
    finding = _one(S3002, data)
    assert finding.status == Status.ERROR
    assert finding.resource == "account"


def test_s3002_not_applicable_without_buckets() -> None:
    assert _one(S3002, snapshot({})).status == Status.NOT_APPLICABLE


# --- S3-003 ---


def test_s3003_pass_no_policy() -> None:
    finding = _one(S3003, snapshot({"b": details(policy_status=None)}))
    assert finding.status == Status.PASS
    assert finding.severity == Severity.CRITICAL


def test_s3003_pass_private_policy() -> None:
    assert (
        _one(S3003, snapshot({"b": details(policy_status={"IsPublic": False})})).status
        == Status.PASS
    )


def test_s3003_fail_public_policy() -> None:
    data = snapshot(
        {"b": details(public_access_block=NONE_BLOCKED, policy_status={"IsPublic": True})}
    )
    assert _one(S3003, data).status == Status.FAIL


def test_s3003_fail_even_if_restricted_with_evidence() -> None:
    # 공통 원칙: 설정이 존재하면 FAIL, 막고 있는 설정은 evidence에 남긴다
    # (실습 계정에서 차단이 켜져도 IsPublic=true임을 확인)
    data = snapshot(
        {"b": details(public_access_block=block(policy=False), policy_status={"IsPublic": True})}
    )
    finding = _one(S3003, data)
    assert finding.status == Status.FAIL
    assert finding.evidence["restrict_public_buckets"] == {"bucket": True, "account": None}


def test_s3003_error_policy_status_unknown() -> None:
    data = snapshot(
        {"b": details(missing=("policy_status",))},
        errors=(collect_error("s3:GetBucketPolicyStatus", "b"),),
    )
    assert _one(S3003, data).status == Status.ERROR


# --- S3-006 ---


def test_s3006_pass_acl_disabled() -> None:
    finding = _one(S3006, snapshot({"b": details()}))
    assert finding.status == Status.PASS
    assert finding.severity == Severity.HIGH


def test_s3006_pass_acl_enabled_without_public_grant() -> None:
    data = snapshot({"b": details(ownership_controls=ownership("BucketOwnerPreferred"))})
    assert _one(S3006, data).status == Status.PASS


def test_s3006_fail_all_users_grant() -> None:
    data = snapshot(
        {
            "b": details(
                ownership_controls=ownership("BucketOwnerPreferred"), acl_config=acl(ALL_USERS)
            )
        }
    )
    finding = _one(S3006, data)
    assert finding.status == Status.FAIL
    assert finding.evidence["public_grants"] == [{"grantee": ALL_USERS, "permission": "READ"}]


def test_s3006_fail_authenticated_users_grant_without_ownership_controls() -> None:
    data = snapshot({"b": details(ownership_controls=None, acl_config=acl(AUTH_USERS))})
    assert _one(S3006, data).status == Status.FAIL


def test_s3006_fail_records_ignore_public_acls() -> None:
    data = snapshot(
        {"b": details(ownership_controls=None, acl_config=acl(ALL_USERS))},
        account_block=ALL_BLOCKED,
    )
    finding = _one(S3006, data)
    assert finding.status == Status.FAIL
    assert finding.evidence["ignore_public_acls"] == {"bucket": True, "account": True}


def test_s3006_pass_enforced_even_if_acl_unknown() -> None:
    data = snapshot({"b": details(missing=("acl",))})
    assert _one(S3006, data).status == Status.PASS


def test_s3006_error_acl_unknown() -> None:
    data = snapshot(
        {"b": details(ownership_controls=None, missing=("acl",))},
        errors=(collect_error("s3:GetBucketAcl", "b"),),
    )
    assert _one(S3006, data).status == Status.ERROR


def test_one_finding_per_bucket() -> None:
    data = snapshot({"a": details(), "b": details(public_access_block=None)})
    findings = S3002.evaluate(data, Settings())
    assert {(f.resource, f.status) for f in findings} == {("a", Status.PASS), ("b", Status.FAIL)}


def test_bucket_region_used_and_unknown_region_is_none() -> None:
    findings = S3002.evaluate(snapshot({"b": details()}, region=None), Settings())
    assert findings[0].region is None
