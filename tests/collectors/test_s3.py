"""S3 collector 테스트.

데이터 표현: 키가 있고 값이 None이면 "설정 없음", 키가 없으면 "수집 실패".
"""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from kompass.aws.guard import read_only_session
from kompass.aws.session import ScanContext
from kompass.collectors.s3 import BUCKET_DETAILS, S3Collector, bucket_region
from kompass.snapshots import SnapshotStore, load_scan
from tests.collectors.stubbing import StubbingSession

ACCOUNT = "123456789012"
HOME = "ap-northeast-2"
TOKYO = "ap-northeast-1"


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


def _create_bucket(name: str, region: str = HOME) -> Any:
    client = boto3.client("s3", region_name=region)
    client.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    return client


def _scan(session: Any = None, regions: tuple[str, ...] = (HOME,)) -> ScanContext:
    return ScanContext(
        session=session or read_only_session(),
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region=HOME,
        regions=regions,
    )


def _listing(name: str) -> dict[str, Any]:
    return {
        "Buckets": [{"Name": name, "CreationDate": "2026-10-13T00:00:00Z"}],
        "Owner": {"ID": "abc"},
    }


# --- 리전 변환 ---


@pytest.mark.parametrize(
    ("constraint", "expected"),
    [(None, "us-east-1"), ("", "us-east-1"), ("EU", "eu-west-1"), (TOKYO, TOKYO)],
)
def test_bucket_region(constraint: str | None, expected: str) -> None:
    assert bucket_region(constraint) == expected


# --- 정상 경로 ---


def test_defaults_are_recorded_as_absent(aws: None) -> None:
    _create_bucket("plain")
    snapshot = S3Collector().collect(_scan())

    assert snapshot.errors == ()
    assert snapshot.data["account_public_access_block"] is None
    [bucket] = snapshot.data["buckets"]
    assert bucket["Name"] == "plain"
    assert bucket["Region"] == HOME
    details = snapshot.data["bucket_details"]["plain"]
    assert set(details) == set(BUCKET_DETAILS)
    assert details["public_access_block"] is None
    assert details["policy_status"] is None
    assert details["policy"] is None
    assert details["encryption"] is None
    assert details["logging"] is None
    assert details["ownership_controls"] is None
    assert details["acl"]["Grants"]


def test_configured_bucket(aws: None) -> None:
    client = _create_bucket("configured")
    _create_bucket("log-target")
    client.put_bucket_policy(
        Bucket="log-target",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "logging.s3.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::log-target/*",
                    }
                ],
            }
        ),
    )
    client.put_public_access_block(
        Bucket="configured",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        },
    )
    client.put_bucket_policy(
        Bucket="configured",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::configured/*",
                    }
                ],
            }
        ),
    )
    client.put_bucket_encryption(
        Bucket="configured",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    client.put_bucket_ownership_controls(
        Bucket="configured",
        OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
    )
    client.put_bucket_logging(
        Bucket="configured",
        BucketLoggingStatus={
            "LoggingEnabled": {"TargetBucket": "log-target", "TargetPrefix": "x/"}
        },
    )

    details = S3Collector().collect(_scan()).data["bucket_details"]["configured"]
    assert details["public_access_block"]["BlockPublicPolicy"] is False
    assert details["policy_status"]["IsPublic"] is True
    assert '"Principal"' in details["policy"]
    assert (
        details["encryption"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        == "AES256"
    )
    assert details["ownership_controls"]["Rules"][0]["ObjectOwnership"] == "BucketOwnerEnforced"
    assert details["logging"]["TargetBucket"] == "log-target"


def test_account_public_access_block(aws: None) -> None:
    boto3.client("s3control", region_name=HOME).put_public_access_block(
        AccountId=ACCOUNT,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    snapshot = S3Collector().collect(_scan())
    assert snapshot.data["account_public_access_block"]["BlockPublicPolicy"] is True


def test_buckets_in_all_regions_regardless_of_scan_regions(aws: None) -> None:
    # --regions는 S3 버킷에 적용하지 않는다. 다른 리전의 공개 버킷을 놓치지 않기 위해서다 (ADR-021)
    _create_bucket("seoul")
    _create_bucket("tokyo", region=TOKYO)
    snapshot = S3Collector().collect(_scan(regions=(HOME,)))
    regions = {b["Name"]: b["Region"] for b in snapshot.data["buckets"]}
    assert regions == {"seoul": HOME, "tokyo": TOKYO}
    assert set(snapshot.data["bucket_details"]) == {"seoul", "tokyo"}
    assert snapshot.regions == (TOKYO, HOME)


def test_no_buckets(aws: None) -> None:
    snapshot = S3Collector().collect(_scan())
    assert snapshot.data["buckets"] == []
    assert snapshot.data["bucket_details"] == {}


def test_snapshot_round_trips_through_store(aws: None, tmp_path: Path) -> None:
    _create_bucket("plain")
    scan = _scan()
    snapshot = S3Collector().collect(scan)
    writer = SnapshotStore(tmp_path / ".kompass").begin(scan)
    writer.write(snapshot)
    assert load_scan(writer.finish())[1]["s3"] == snapshot


# --- 오류 경로 ---


def test_bucket_detail_failure_is_missing_key_with_resource(aws: None) -> None:
    _create_bucket("denied")
    session = read_only_session()
    client = session.client("s3", region_name=HOME)
    with Stubber(client) as stub:
        stub.add_response("list_buckets", _listing("denied"))
        stub.add_response("get_bucket_location", {"LocationConstraint": HOME})
        stub.add_client_error("get_public_access_block", service_error_code="AccessDenied")
        stub.add_client_error("get_bucket_policy_status", service_error_code="NoSuchBucketPolicy")
        stub.add_client_error("get_bucket_policy", service_error_code="NoSuchBucketPolicy")
        stub.add_client_error(
            "get_bucket_encryption",
            service_error_code="ServerSideEncryptionConfigurationNotFoundError",
        )
        stub.add_response("get_bucket_logging", {})
        stub.add_client_error(
            "get_bucket_ownership_controls", service_error_code="OwnershipControlsNotFoundError"
        )
        stub.add_response("get_bucket_acl", {"Grants": [], "Owner": {"ID": "abc"}})
        snapshot = S3Collector().collect(_scan(StubbingSession(session, {("s3", HOME): client})))

    details = snapshot.data["bucket_details"]["denied"]
    assert "public_access_block" not in details  # 수집 실패
    assert details["policy_status"] is None  # 설정 없음
    [error] = snapshot.errors
    assert error.operation == "s3:GetPublicAccessBlock"
    assert error.resource == "denied"
    assert error.region == HOME


def test_location_failure_records_error_and_continues(aws: None) -> None:
    _create_bucket("unknown-region")
    session = read_only_session()
    client = session.client("s3", region_name=HOME)
    real = session.client("s3", region_name=HOME)
    with Stubber(client) as stub:
        stub.add_response("list_buckets", _listing("unknown-region"))
        stub.add_client_error("get_bucket_location", service_error_code="AccessDenied")
        for method, absent in [
            ("get_public_access_block", "NoSuchPublicAccessBlockConfiguration"),
            ("get_bucket_policy_status", "NoSuchBucketPolicy"),
            ("get_bucket_policy", "NoSuchBucketPolicy"),
            ("get_bucket_encryption", "ServerSideEncryptionConfigurationNotFoundError"),
        ]:
            stub.add_client_error(method, service_error_code=absent)
        stub.add_response("get_bucket_logging", {})
        stub.add_client_error(
            "get_bucket_ownership_controls", service_error_code="OwnershipControlsNotFoundError"
        )
        acl = real.get_bucket_acl(Bucket="unknown-region")
        stub.add_response("get_bucket_acl", {"Grants": acl["Grants"], "Owner": acl["Owner"]})
        snapshot = S3Collector().collect(_scan(StubbingSession(session, {("s3", HOME): client})))

    [bucket] = snapshot.data["buckets"]
    assert bucket["Region"] is None
    assert set(snapshot.data["bucket_details"]["unknown-region"]) == set(BUCKET_DETAILS)
    [error] = snapshot.errors
    assert error.operation == "s3:GetBucketLocation"
    assert error.resource == "unknown-region"


def test_list_buckets_failure_leaves_buckets_missing(aws: None) -> None:
    session = read_only_session()
    client = session.client("s3", region_name=HOME)
    with Stubber(client) as stub:
        stub.add_client_error("list_buckets", service_error_code="AccessDenied")
        snapshot = S3Collector().collect(_scan(StubbingSession(session, {("s3", HOME): client})))
    assert "buckets" not in snapshot.data
    assert "bucket_details" not in snapshot.data
    assert "account_public_access_block" in snapshot.data
    assert snapshot.errors[0].operation == "s3:ListBuckets"
