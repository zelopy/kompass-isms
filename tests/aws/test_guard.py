"""읽기 전용 가드 테스트.

moto로 AWS를 흉내 내므로 실제 AWS에는 요청이 나가지 않는다.
차단된 호출이 실제로 아무것도 바꾸지 않았는지는 가드가 없는 별도 세션으로 확인한다.
"""

from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from moto import mock_aws

from kompass.aws.guard import ReadOnlyViolation, is_allowed_operation, read_only_session

FAKE_CREDENTIALS = {
    "aws_access_key_id": "testing",
    "aws_secret_access_key": "testing",
    "region_name": "ap-northeast-2",
}


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


@pytest.fixture
def guarded(aws: None) -> Any:
    return read_only_session(**FAKE_CREDENTIALS)


@pytest.fixture
def unguarded(aws: None) -> Any:
    """차단된 호출의 부작용이 없었는지 확인하는 용도. 가드가 없다."""
    return boto3.Session(**FAKE_CREDENTIALS)


# --- 오퍼레이션 이름 판별 ---


@pytest.mark.parametrize(
    "operation",
    [
        "DescribeSecurityGroups",
        "DescribeTrails",
        "GetBucketPolicyStatus",
        "GetAccountAuthorizationDetails",
        "GetCredentialReport",
        "ListUsers",
        "ListBuckets",
        "GenerateCredentialReport",
    ],
)
def test_read_only_operations_are_allowed(operation: str) -> None:
    assert is_allowed_operation("iam", operation)


@pytest.mark.parametrize(
    "operation",
    [
        "PutObject",
        "CreateBucket",
        "DeleteUser",
        "AuthorizeSecurityGroupIngress",
        "ModifyInstanceAttribute",
        "UpdateTrail",
        "StopLogging",
        "TagResource",
        "GenerateDataKey",  # GenerateCredentialReport 외의 Generate*는 허용하지 않는다
        "PutBucketPolicy",
        "",
    ],
)
def test_other_operations_are_blocked(operation: str) -> None:
    assert not is_allowed_operation("iam", operation)


def test_prefix_match_is_case_sensitive() -> None:
    assert not is_allowed_operation("ec2", "describeInstances")
    assert not is_allowed_operation("iam", "listUsers")


# --- sts:AssumeRole 예외 (ADR-020) ---


def test_sts_assume_role_is_allowed() -> None:
    assert is_allowed_operation("sts", "AssumeRole")


@pytest.mark.parametrize(
    ("service", "operation"),
    [
        ("sts", "AssumeRoleWithSAML"),
        ("sts", "AssumeRoleWithWebIdentity"),
        ("sts", "AssumeRoot"),
        ("iam", "AssumeRole"),  # 서비스까지 일치해야 한다
        ("sso", "AssumeRole"),
    ],
)
def test_assume_role_exception_is_exact(service: str, operation: str) -> None:
    assert not is_allowed_operation(service, operation)


def test_assume_role_call_passes_guard(guarded: Any) -> None:
    credentials = guarded.client("sts").assume_role(
        RoleArn="arn:aws:iam::123456789012:role/kompass-audit", RoleSessionName="kompass"
    )["Credentials"]
    assert credentials["AccessKeyId"]


# --- 허용 호출 ---


def test_allowed_call_succeeds(guarded: Any) -> None:
    assert guarded.client("s3").list_buckets()["Buckets"] == []


def test_paginator_is_allowed(guarded: Any) -> None:
    result = guarded.client("iam").get_paginator("list_users").paginate().build_full_result()
    assert result["Users"] == []


def test_generate_credential_report_is_allowed(guarded: Any) -> None:
    assert guarded.client("iam").generate_credential_report()["State"] in {"STARTED", "COMPLETE"}


# --- 차단 호출 ---


def test_write_call_is_blocked_before_request(guarded: Any, unguarded: Any) -> None:
    with pytest.raises(ReadOnlyViolation):
        guarded.client("s3").create_bucket(
            Bucket="must-not-exist",
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"},
        )
    assert unguarded.client("s3").list_buckets()["Buckets"] == []


def test_iam_write_is_blocked(guarded: Any, unguarded: Any) -> None:
    with pytest.raises(ReadOnlyViolation):
        guarded.client("iam").create_user(UserName="must-not-exist")
    assert unguarded.client("iam").list_users()["Users"] == []


def test_security_group_change_is_blocked(guarded: Any, unguarded: Any) -> None:
    ec2 = unguarded.client("ec2")
    group_id = ec2.create_security_group(GroupName="sg", Description="d")["GroupId"]
    with pytest.raises(ReadOnlyViolation):
        guarded.client("ec2").authorize_security_group_ingress(
            GroupId=group_id, IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0"
        )
    group = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    assert group["IpPermissions"] == []


def test_cloudtrail_stop_logging_is_blocked(guarded: Any) -> None:
    with pytest.raises(ReadOnlyViolation):
        guarded.client("cloudtrail").stop_logging(Name="any-trail")


def test_resource_api_is_blocked(guarded: Any, unguarded: Any) -> None:
    with pytest.raises(ReadOnlyViolation):
        guarded.resource("s3").create_bucket(
            Bucket="must-not-exist",
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"},
        )
    assert unguarded.client("s3").list_buckets()["Buckets"] == []


@pytest.mark.parametrize(
    ("service", "region", "method", "kwargs"),
    [
        ("s3", "us-east-1", "delete_bucket", {"Bucket": "b"}),
        ("iam", None, "delete_user", {"UserName": "u"}),
        ("ec2", "eu-west-1", "delete_security_group", {"GroupId": "sg-1"}),
        ("cloudtrail", "us-west-2", "delete_trail", {"Name": "t"}),
    ],
)
def test_every_client_and_region_is_guarded(
    guarded: Any, service: str, region: str | None, method: str, kwargs: dict[str, Any]
) -> None:
    client = guarded.client(service, region_name=region)
    with pytest.raises(ReadOnlyViolation):
        getattr(client, method)(**kwargs)


def test_violation_names_service_and_operation(guarded: Any) -> None:
    with pytest.raises(ReadOnlyViolation) as exc_info:
        guarded.client("iam").create_user(UserName="u")
    assert exc_info.value.service == "iam"
    assert exc_info.value.operation == "CreateUser"
    assert "iam:CreateUser" in str(exc_info.value)


def test_violation_is_not_swallowed_as_client_error(guarded: Any) -> None:
    # collector가 ClientError를 잡아 ERROR로 기록할 때 가드 위반까지 삼키면 안 된다
    from botocore.exceptions import BotoCoreError, ClientError

    with pytest.raises(ReadOnlyViolation) as exc_info:
        guarded.client("iam").create_user(UserName="u")
    assert not isinstance(exc_info.value, ClientError | BotoCoreError)
