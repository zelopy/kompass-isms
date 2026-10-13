"""CloudTrail collector 테스트.

정상 경로는 moto로, moto가 흉내 내지 못하는 오류 경로는 특정 client만 Stubber로 바꿔치기한다.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from kompass.aws.guard import read_only_session
from kompass.aws.session import ScanContext
from kompass.collectors.cloudtrail import CloudTrailCollector
from kompass.snapshots import SnapshotStore, load_scan
from tests.collectors.stubbing import StubbingSession

ACCOUNT = "123456789012"
HOME = "ap-northeast-2"
BUCKET = "kompass-trail-logs"


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


@pytest.fixture
def setup(aws: None) -> Any:
    """테스트 데이터 준비용. 가드가 없다."""
    session = boto3.Session()
    session.client("s3", region_name=HOME).create_bucket(
        Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": HOME}
    )
    return session


def _scan(session: Any = None) -> ScanContext:
    return ScanContext(
        session=session or read_only_session(),
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region=HOME,
        regions=(HOME,),
    )


def _create_trail(setup: Any, name: str, region: str = HOME, logging: bool = True) -> str:
    client = setup.client("cloudtrail", region_name=region)
    arn: str = client.create_trail(Name=name, S3BucketName=BUCKET, IsMultiRegionTrail=True)[
        "TrailARN"
    ]
    if logging:
        client.start_logging(Name=name)
    return arn


# --- 정상 경로 ---


def test_collects_trail_status_and_selectors(setup: Any) -> None:
    arn = _create_trail(setup, "main")
    snapshot = CloudTrailCollector().collect(_scan())

    assert snapshot.service == "cloudtrail"
    assert snapshot.account_id == ACCOUNT
    assert snapshot.errors == ()
    [trail] = snapshot.data["trails"]
    assert trail["TrailARN"] == arn
    assert trail["IsMultiRegionTrail"] is True
    assert snapshot.data["status"][arn]["IsLogging"] is True
    assert "EventSelectors" in snapshot.data["event_selectors"][arn]


def test_no_trails_is_empty_not_missing(setup: Any) -> None:
    # "추적 없음"(빈 목록)과 "수집 실패"(키 없음)를 구분한다
    snapshot = CloudTrailCollector().collect(_scan())
    assert snapshot.data == {"trails": [], "status": {}, "event_selectors": {}}
    assert snapshot.errors == ()


def test_shadow_trail_from_other_region_is_collected_in_its_home_region(setup: Any) -> None:
    arn = _create_trail(setup, "us-trail", region="us-east-1")
    snapshot = CloudTrailCollector().collect(_scan())
    [trail] = snapshot.data["trails"]
    assert trail["HomeRegion"] == "us-east-1"
    assert snapshot.data["status"][arn]["IsLogging"] is True
    assert snapshot.regions == ("ap-northeast-2", "us-east-1")


def test_stopped_trail_is_recorded_as_data(setup: Any) -> None:
    arn = _create_trail(setup, "stopped", logging=False)
    snapshot = CloudTrailCollector().collect(_scan())
    assert snapshot.data["status"][arn]["IsLogging"] is False


def test_collected_at_is_utc(setup: Any) -> None:
    before = datetime.now(UTC)
    snapshot = CloudTrailCollector().collect(_scan())
    assert before <= snapshot.collected_at <= datetime.now(UTC)


def test_snapshot_round_trips_through_store(setup: Any, tmp_path: Path) -> None:
    _create_trail(setup, "main")
    scan = _scan()
    snapshot = CloudTrailCollector().collect(scan)
    writer = SnapshotStore(tmp_path / ".kompass").begin(scan)
    writer.write(snapshot)
    assert load_scan(writer.finish())[1]["cloudtrail"] == snapshot


# --- 오류 경로 ---


def test_describe_failure_leaves_trails_missing(setup: Any) -> None:
    session = read_only_session()
    client = session.client("cloudtrail", region_name=HOME)
    with Stubber(client) as stub:
        stub.add_client_error("describe_trails", service_error_code="AccessDeniedException")
        snapshot = CloudTrailCollector().collect(
            _scan(StubbingSession(session, {("cloudtrail", HOME): client}))
        )
    assert "trails" not in snapshot.data
    [error] = snapshot.errors
    assert error.operation == "cloudtrail:DescribeTrails"
    assert error.region == HOME


def test_status_failure_is_recorded_per_trail(setup: Any) -> None:
    # 조직 추적을 멤버 계정에서 조회할 때처럼 상태만 실패하는 경우.
    # 그 추적만 오류로 남기고 다른 수집은 계속한다
    arn = _create_trail(setup, "org-like")
    session = read_only_session()
    real = session.client("cloudtrail", region_name=HOME)
    trails = real.describe_trails(includeShadowTrails=True)["trailList"]
    selectors = real.get_event_selectors(TrailName=arn)
    selectors.pop("ResponseMetadata")

    client = session.client("cloudtrail", region_name=HOME)
    with Stubber(client) as stub:
        stub.add_response("describe_trails", {"trailList": trails})
        stub.add_client_error("get_trail_status", service_error_code="TrailNotFoundException")
        stub.add_response("get_event_selectors", selectors)
        snapshot = CloudTrailCollector().collect(
            _scan(StubbingSession(session, {("cloudtrail", HOME): client}))
        )

    assert arn not in snapshot.data["status"]
    assert arn in snapshot.data["event_selectors"]
    [error] = snapshot.errors
    assert error.operation == "cloudtrail:GetTrailStatus"
    assert error.resource == arn
    assert error.error_code == "TrailNotFoundException"
