"""GD-001 GuardDuty 미활성화, GD-002 GuardDuty 결과 알림 미설정."""

import json
from datetime import UTC, datetime
from typing import Any

from kompass.config import Settings
from kompass.models import CollectError, Finding, Snapshot, Status
from kompass.rules.guardduty.gd_001_detector_enabled import Gd001DetectorEnabled
from kompass.rules.guardduty.gd_002_finding_alerts import Gd002FindingAlerts

REGION = "ap-northeast-2"
GD001 = Gd001DetectorEnabled()
GD002 = Gd002FindingAlerts()


def detector(detector_id: str = "d1", status: str | None = "ENABLED") -> dict[str, Any]:
    item: dict[str, Any] = {"DetectorId": detector_id}
    if status is not None:
        item.update({"Status": status, "FindingPublishingFrequency": "SIX_HOURS", "Features": []})
    return item


def rule(
    name: str = "gd", state: str = "ENABLED", targets: list[str] | None = None
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "Name": name,
        "State": state,
        "EventPattern": json.dumps({"source": ["aws.guardduty"]}),
        "EventBusName": "default",
    }
    if targets is not None:
        item["Targets"] = [{"Id": str(n), "Arn": arn} for n, arn in enumerate(targets)]
    return item


SNS = "arn:aws:sns:ap-northeast-2:123456789012:alerts"


def _run(rule_obj: Any, data: dict[str, Any], *errors: CollectError) -> Finding:
    snapshot = Snapshot(
        service="guardduty",
        account_id="123456789012",
        regions=(REGION,),
        collected_at=datetime(2026, 10, 16, tzinfo=UTC),
        data={"regions": {REGION: data}},
        errors=errors,
    )
    [finding] = rule_obj.evaluate(snapshot, Settings())
    assert finding.region == REGION and finding.resource == "account"
    return finding  # type: ignore[no-any-return]


def _error(operation: str, resource: str | None = None) -> CollectError:
    return CollectError(
        operation=operation,
        region=REGION,
        error_code="AccessDenied",
        message="no",
        resource=resource,
    )


# --- GD-001 ---


def test_gd001_pass_when_enabled() -> None:
    finding = _run(GD001, {"detectors": [detector()], "event_rules": []})
    assert finding.status == Status.PASS
    assert finding.evidence["detectors"][0]["status"] == "ENABLED"


def test_gd001_fail_without_detector() -> None:
    assert _run(GD001, {"detectors": [], "event_rules": []}).status == Status.FAIL


def test_gd001_fail_when_disabled() -> None:
    finding = _run(GD001, {"detectors": [detector(status="DISABLED")], "event_rules": []})
    assert finding.status == Status.FAIL


def test_gd001_error_when_list_failed() -> None:
    finding = _run(GD001, {"event_rules": []}, _error("guardduty:ListDetectors"))
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["operation"] == "guardduty:ListDetectors"


def test_gd001_error_when_detail_failed() -> None:
    error = _error("guardduty:GetDetector", "d1")
    finding = _run(GD001, {"detectors": [detector(status=None)], "event_rules": []}, error)
    assert finding.status == Status.ERROR


def test_gd001_enabled_detector_wins_over_unknown() -> None:
    data = {"detectors": [detector("d1", status=None), detector("d2")], "event_rules": []}
    assert _run(GD001, data).status == Status.PASS


# --- GD-002 ---


def test_gd002_pass_with_enabled_rule_and_target() -> None:
    finding = _run(GD002, {"detectors": [detector()], "event_rules": [rule(targets=[SNS])]})
    assert finding.status == Status.PASS
    assert finding.evidence["rules"][0]["targets"] == [SNS]


def test_gd002_fail_without_rule() -> None:
    assert _run(GD002, {"detectors": [detector()], "event_rules": []}).status == Status.FAIL


def test_gd002_fail_when_rule_disabled_or_without_targets() -> None:
    rules = [rule("off", state="DISABLED", targets=[SNS]), rule("empty", targets=[])]
    assert _run(GD002, {"detectors": [detector()], "event_rules": rules}).status == Status.FAIL


def test_gd002_not_applicable_when_guardduty_disabled() -> None:
    finding = _run(GD002, {"detectors": [], "event_rules": []})
    assert finding.status == Status.NOT_APPLICABLE


def test_gd002_error_when_rules_missing() -> None:
    finding = _run(GD002, {"detectors": [detector()]}, _error("events:ListRules"))
    assert finding.status == Status.ERROR


def test_gd002_error_when_targets_unknown() -> None:
    error = _error("events:ListTargetsByRule", "gd")
    finding = _run(GD002, {"detectors": [detector()], "event_rules": [rule()]}, error)
    assert finding.status == Status.ERROR


def test_gd002_error_when_detector_state_unknown() -> None:
    error = _error("guardduty:GetDetector", "d1")
    data = {"detectors": [detector(status=None)], "event_rules": [rule(targets=[SNS])]}
    assert _run(GD002, data, error).status == Status.ERROR
