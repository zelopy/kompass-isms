"""collector 공용 호출 테스트.

moto가 흉내 내지 못하는 권한 오류는 botocore Stubber로 주입한다. Stubber는 요청을 보내지 않고
미리 정한 응답을 돌려준다.
"""

from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from botocore.exceptions import (
    EndpointConnectionError,
    NoCredentialsError,
    OperationNotPageableError,
    ParamValidationError,
)
from botocore.stub import Stubber
from moto import mock_aws

from kompass.aws.guard import ReadOnlyViolation, read_only_session
from kompass.aws.session import SessionError
from kompass.collectors.base import Absent, CallRecorder


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


@pytest.fixture
def session(aws: None) -> Any:
    return read_only_session(region_name="ap-northeast-2")


@pytest.fixture
def unguarded(aws: None) -> Any:
    """테스트 데이터 준비용. 가드가 없다."""
    return boto3.Session(region_name="ap-northeast-2")


@pytest.fixture
def recorder() -> CallRecorder:
    return CallRecorder()


# --- call ---


def test_call_returns_response(session: Any, recorder: CallRecorder) -> None:
    response = recorder.call(session.client("s3"), "list_buckets")
    assert isinstance(response, dict)
    assert response["Buckets"] == []
    assert recorder.errors == []


def test_call_strips_response_metadata(session: Any, recorder: CallRecorder) -> None:
    # HTTP 헤더의 날짜 등이 스냅샷에 들어가면 같은 설정도 매번 다른 스냅샷이 된다
    response = recorder.call(session.client("iam"), "get_account_summary")
    assert isinstance(response, dict)
    assert "SummaryMap" in response
    assert "ResponseMetadata" not in response


def test_absent_code_is_data_not_error(
    session: Any, unguarded: Any, recorder: CallRecorder
) -> None:
    unguarded.client("s3").create_bucket(
        Bucket="no-policy", CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"}
    )
    result = recorder.call(
        session.client("s3"),
        "get_bucket_policy",
        resource="no-policy",
        absent_codes={"NoSuchBucketPolicy"},
        Bucket="no-policy",
    )
    assert result == Absent("NoSuchBucketPolicy")
    assert recorder.errors == []


def test_access_denied_is_recorded(session: Any, recorder: CallRecorder) -> None:
    iam = session.client("iam")
    with Stubber(iam) as stub:
        stub.add_client_error("list_users", service_error_code="AccessDenied", http_status_code=403)
        assert recorder.call(iam, "list_users") is None
    [error] = recorder.errors
    assert error.operation == "iam:ListUsers"
    assert error.error_code == "AccessDenied"
    assert error.region is None  # IAM은 전역 서비스
    assert error.resource is None


def test_error_records_region_and_resource(session: Any, recorder: CallRecorder) -> None:
    s3 = session.client("s3", region_name="us-east-1")
    with Stubber(s3) as stub:
        stub.add_client_error(
            "get_bucket_policy_status", service_error_code="AccessDenied", http_status_code=403
        )
        recorder.call(s3, "get_bucket_policy_status", resource="my-bucket", Bucket="my-bucket")
    [error] = recorder.errors
    assert error.operation == "s3:GetBucketPolicyStatus"
    assert error.region == "us-east-1"
    assert error.resource == "my-bucket"


def test_absent_codes_do_not_hide_other_errors(session: Any, recorder: CallRecorder) -> None:
    s3 = session.client("s3")
    with Stubber(s3) as stub:
        stub.add_client_error("get_bucket_policy", service_error_code="AccessDenied")
        result = recorder.call(
            s3, "get_bucket_policy", absent_codes={"NoSuchBucketPolicy"}, Bucket="b"
        )
    assert result is None
    assert recorder.errors[0].error_code == "AccessDenied"


def test_connection_failure_is_recorded(
    session: Any, recorder: CallRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    ec2 = session.client("ec2")

    def unreachable(**_: Any) -> None:
        raise EndpointConnectionError(endpoint_url="https://ec2.ap-northeast-2.amazonaws.com")

    monkeypatch.setattr(ec2, "describe_security_groups", unreachable)
    assert recorder.call(ec2, "describe_security_groups") is None
    assert recorder.errors[0].error_code == "EndpointConnectionError"
    assert recorder.errors[0].operation == "ec2:DescribeSecurityGroups"


# --- 잡지 않는 예외 ---


def test_guard_violation_is_not_swallowed(session: Any, recorder: CallRecorder) -> None:
    with pytest.raises(ReadOnlyViolation):
        recorder.call(session.client("iam"), "create_user", UserName="u")
    assert recorder.errors == []


def test_param_validation_error_is_not_swallowed(session: Any, recorder: CallRecorder) -> None:
    # 잘못된 파라미터는 수집 실패가 아니라 kompass 코드 버그다
    with pytest.raises(ParamValidationError):
        recorder.call(session.client("iam"), "list_users", MaxItems="not-a-number")
    assert recorder.errors == []


# --- paginate ---


def test_paginate_collects_all_pages(session: Any, unguarded: Any, recorder: CallRecorder) -> None:
    for name in ("a", "b", "c"):
        unguarded.client("iam").create_user(UserName=name)
    users = recorder.paginate(
        session.client("iam"), "list_users", "Users", PaginationConfig={"PageSize": 1}
    )
    assert users is not None
    assert sorted(u["UserName"] for u in users) == ["a", "b", "c"]


def test_paginate_failure_discards_partial_pages(session: Any, recorder: CallRecorder) -> None:
    # 목록 일부만 보고 "없음"으로 판정하지 않도록 중간 실패 시 받은 페이지도 버린다
    iam = session.client("iam")
    with Stubber(iam) as stub:
        stub.add_response(
            "list_users",
            {
                "Users": [
                    {
                        "UserName": "a",
                        "UserId": "AIDAAAAAAAAAAAAAAAAAA",
                        "Arn": "arn:aws:iam::123456789012:user/a",
                        "Path": "/",
                        "CreateDate": "2026-01-01T00:00:00Z",
                    }
                ],
                "IsTruncated": True,
                "Marker": "next",
            },
        )
        stub.add_client_error("list_users", service_error_code="Throttling")
        assert recorder.paginate(iam, "list_users", "Users") is None
    [error] = recorder.errors
    assert error.error_code == "Throttling"
    assert error.operation == "iam:ListUsers"


def test_errors_accumulate_across_calls(session: Any, recorder: CallRecorder) -> None:
    iam = session.client("iam")
    with Stubber(iam) as stub:
        stub.add_client_error("list_users", service_error_code="AccessDenied")
        stub.add_client_error("get_account_summary", service_error_code="AccessDenied")
        recorder.call(iam, "list_users")
        recorder.call(iam, "get_account_summary")
    assert [e.operation for e in recorder.errors] == ["iam:ListUsers", "iam:GetAccountSummary"]


# --- 코드 버그는 실행 중단 ---


def test_paginate_rejects_unknown_result_key(session: Any, recorder: CallRecorder) -> None:
    # 오타("Users" -> "User")가 빈 목록, 즉 "리소스 없음"으로 둔갑하면 안 된다 (ADR-005)
    iam = session.client("iam")
    with Stubber(iam), pytest.raises(ValueError, match="User"):
        # Stubber에 응답을 넣지 않았으므로 실제 호출이 일어나면 Stubber가 실패한다
        recorder.paginate(iam, "list_users", "User")
    assert recorder.errors == []


def test_paginate_non_pageable_operation_raises(session: Any, recorder: CallRecorder) -> None:
    with pytest.raises(OperationNotPageableError):
        recorder.paginate(session.client("iam"), "get_account_summary", "SummaryMap")
    assert recorder.errors == []


# --- 세션 전체 실패는 실행 중단 ---

SESSION_WIDE_CODES = [
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "UnrecognizedClientException",
    "SignatureDoesNotMatch",
]


@pytest.mark.parametrize("code", SESSION_WIDE_CODES)
def test_session_wide_error_aborts_call(session: Any, recorder: CallRecorder, code: str) -> None:
    # 자격증명 만료 등을 호출마다 ERROR로 쌓으면 보고서 전체가 "확인 불가"로 채워진다
    iam = session.client("iam")
    with Stubber(iam) as stub, pytest.raises(SessionError, match=code):
        stub.add_client_error("list_users", service_error_code=code, http_status_code=403)
        recorder.call(iam, "list_users")
    assert recorder.errors == []


@pytest.mark.parametrize("code", SESSION_WIDE_CODES)
def test_session_wide_error_aborts_paginate(
    session: Any, recorder: CallRecorder, code: str
) -> None:
    iam = session.client("iam")
    with Stubber(iam) as stub, pytest.raises(SessionError, match=code):
        stub.add_client_error("list_users", service_error_code=code, http_status_code=403)
        recorder.paginate(iam, "list_users", "Users")
    assert recorder.errors == []


def test_missing_credentials_aborts(
    session: Any, recorder: CallRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    iam = session.client("iam")

    def no_credentials(**_: Any) -> None:
        raise NoCredentialsError()

    monkeypatch.setattr(iam, "list_users", no_credentials)
    with pytest.raises(SessionError):
        recorder.call(iam, "list_users")
    assert recorder.errors == []
