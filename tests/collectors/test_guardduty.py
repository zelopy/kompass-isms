"""GuardDuty collector 테스트 (탐지기 + GuardDuty 결과용 EventBridge 규칙)."""

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
from kompass.collectors.guardduty import GuardDutyCollector
from kompass.snapshots import SnapshotStore, load_scan
from tests.collectors.stubbing import StubbingSession

ACCOUNT = "123456789012"
HOME = "ap-northeast-2"
OTHER = "us-east-1"


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


def _scan(regions: tuple[str, ...] = (HOME,), session: Any = None) -> ScanContext:
    return ScanContext(
        session=session or read_only_session(),
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region=HOME,
        regions=regions,
    )


def _build(region: str = HOME) -> str:
    detector: str = boto3.client("guardduty", region_name=region).create_detector(Enable=True)[
        "DetectorId"
    ]
    events = boto3.client("events", region_name=region)
    topic = boto3.client("sns", region_name=region).create_topic(Name="alerts")["TopicArn"]
    events.put_rule(
        Name="guardduty-findings",
        EventPattern=json.dumps({"source": ["aws.guardduty"]}),
        State="ENABLED",
    )
    events.put_targets(Rule="guardduty-findings", Targets=[{"Id": "1", "Arn": topic}])
    events.put_rule(Name="other", EventPattern=json.dumps({"source": ["aws.ec2"]}))
    return detector


def test_collects_detectors_and_guardduty_rules(aws: None) -> None:
    detector = _build()
    snapshot = GuardDutyCollector().collect(_scan())
    assert snapshot.service == "guardduty" and snapshot.errors == ()
    region = snapshot.data["regions"][HOME]
    [item] = region["detectors"]
    assert item["DetectorId"] == detector and item["Status"] == "ENABLED"
    [rule] = region["event_rules"]  # GuardDuty와 무관한 규칙은 저장하지 않는다
    assert rule["Name"] == "guardduty-findings"
    assert rule["Targets"][0]["Arn"].endswith(":alerts")


def test_region_without_guardduty(aws: None) -> None:
    _build(OTHER)
    snapshot = GuardDutyCollector().collect(_scan())
    assert snapshot.data["regions"][HOME] == {"detectors": [], "event_rules": []}


def test_snapshot_round_trips_through_store(aws: None, tmp_path: Path) -> None:
    _build()
    scan = _scan()
    snapshot = GuardDutyCollector().collect(scan)
    writer = SnapshotStore(tmp_path / ".kompass").begin(scan)
    writer.write(snapshot)
    assert load_scan(writer.finish())[1]["guardduty"] == snapshot


def test_failures_are_recorded_and_keys_missing(aws: None) -> None:
    session = read_only_session()
    guardduty = session.client("guardduty", region_name=HOME)
    events = session.client("events", region_name=HOME)
    with Stubber(guardduty) as gd_stub, Stubber(events) as ev_stub:
        gd_stub.add_response("list_detectors", {"DetectorIds": ["d1"]})
        gd_stub.add_client_error("get_detector", service_error_code="AccessDeniedException")
        ev_stub.add_response(
            "list_rules",
            {
                "Rules": [
                    {
                        "Name": "gd",
                        "State": "ENABLED",
                        "EventPattern": json.dumps({"source": ["aws.guardduty"]}),
                    }
                ]
            },
        )
        ev_stub.add_client_error("list_targets_by_rule", service_error_code="AccessDeniedException")
        overrides = {("guardduty", HOME): guardduty, ("events", HOME): events}
        snapshot = GuardDutyCollector().collect(_scan(session=StubbingSession(session, overrides)))

    region = snapshot.data["regions"][HOME]
    assert region["detectors"] == [{"DetectorId": "d1"}]  # 상세가 없으면 ID만 남는다
    assert region["event_rules"][0]["Name"] == "gd" and "Targets" not in region["event_rules"][0]
    assert {(e.operation, e.resource) for e in snapshot.errors} == {
        ("guardduty:GetDetector", "d1"),
        ("events:ListTargetsByRule", "gd"),
    }
