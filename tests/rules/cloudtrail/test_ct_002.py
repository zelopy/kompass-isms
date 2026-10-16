"""CT-002 CloudTrail 로그 버킷 보존 기간 부족."""

from datetime import UTC, datetime
from typing import Any

import pytest

from kompass.config import LogsSettings, Settings
from kompass.models import CollectError, Finding, Snapshot, Status
from kompass.rules.cloudtrail.ct_002_log_bucket_retention import Ct002LogBucketRetention

RULE = Ct002LogBucketRetention()
BUCKET = "trail-logs"


def _trail(name: str = "main", bucket: str = BUCKET, prefix: str | None = None) -> dict[str, Any]:
    trail: dict[str, Any] = {
        "Name": name,
        "TrailARN": f"arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/{name}",
        "S3BucketName": bucket,
        "HomeRegion": "ap-northeast-2",
    }
    if prefix:
        trail["S3KeyPrefix"] = prefix
    return trail


def _expire(
    days: int | None = None, prefix: str | None = "AWSLogs/", **extra: Any
) -> dict[str, Any]:
    rule: dict[str, Any] = {"ID": "expire", "Status": "Enabled", **extra}
    if prefix is not None:
        rule["Filter"] = {"Prefix": prefix}
    if days is not None:
        rule["Expiration"] = {"Days": days}
    return rule


def _run(
    trails: list[dict[str, Any]] | None,
    lifecycles: dict[str, Any],
    *errors: CollectError,
    settings: Settings | None = None,
) -> list[Finding]:
    data: dict[str, Any] = {"status": {}, "event_selectors": {}, "bucket_lifecycles": lifecycles}
    if trails is not None:
        data["trails"] = trails
    snapshot = Snapshot(
        service="cloudtrail",
        account_id="123456789012",
        regions=("ap-northeast-2",),
        collected_at=datetime(2026, 10, 16, tzinfo=UTC),
        data=data,
        errors=errors,
    )
    return RULE.evaluate(snapshot, settings or Settings())


def _one(*args: Any, **kwargs: Any) -> Finding:
    [finding] = _run(*args, **kwargs)
    return finding


def test_pass_without_lifecycle() -> None:
    finding = _one([_trail()], {BUCKET: None})
    assert finding.status == Status.PASS and finding.resource == BUCKET


def test_pass_when_expiration_meets_minimum() -> None:
    assert _one([_trail()], {BUCKET: [_expire(400)]}).status == Status.PASS


def test_fail_when_expiration_is_short() -> None:
    finding = _one([_trail()], {BUCKET: [_expire(30)]})
    assert finding.status == Status.FAIL
    assert finding.evidence["short_rules"][0]["expiration_days"] == 30


def test_threshold_from_settings() -> None:
    settings = Settings(logs=LogsSettings(min_retention_days=30))
    assert _one([_trail()], {BUCKET: [_expire(30)]}, settings=settings).status == Status.PASS


@pytest.mark.parametrize(
    ("rule", "status"),
    [
        (_expire(30, prefix="other/"), Status.PASS),  # 추적 로그 경로와 겹치지 않음
        (_expire(30, prefix=""), Status.FAIL),  # 버킷 전체
        (_expire(30, prefix=None), Status.FAIL),  # 필터 없음 = 버킷 전체
        (_expire(30, prefix="AWSLogs/123456789012/CloudTrail/"), Status.FAIL),  # 더 좁은 경로
        (_expire(30, Status="Disabled"), Status.PASS),
        (
            {"ID": "date", "Status": "Enabled", "Expiration": {"Date": "2027-01-01T00:00:00Z"}},
            Status.FAIL,
        ),
        (
            {
                "ID": "noncurrent",
                "Status": "Enabled",
                "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
            },
            Status.PASS,
        ),
    ],
)
def test_rule_scope(rule: dict[str, Any], status: Status) -> None:
    assert _one([_trail()], {BUCKET: [rule]}).status == status


def test_trail_key_prefix_is_respected() -> None:
    trails = [_trail(prefix="ct")]
    assert _one(trails, {BUCKET: [_expire(30, prefix="AWSLogs/")]}).status == Status.PASS
    assert _one(trails, {BUCKET: [_expire(30, prefix="ct/AWSLogs/")]}).status == Status.FAIL


def test_one_finding_per_bucket() -> None:
    trails = [_trail("a"), _trail("b"), _trail("c", bucket="other")]
    findings = _run(trails, {BUCKET: None, "other": [_expire(30)]})
    assert {f.resource: f.status for f in findings} == {BUCKET: Status.PASS, "other": Status.FAIL}


def test_no_trails_is_not_applicable() -> None:
    assert _one([], {}).status == Status.NOT_APPLICABLE


def test_error_when_trails_missing() -> None:
    error = CollectError(
        operation="cloudtrail:DescribeTrails", region="ap-northeast-2", error_code="X", message="m"
    )
    finding = _one(None, {}, error)
    assert finding.status == Status.ERROR and finding.resource == "account"


def test_error_when_lifecycle_not_collected() -> None:
    error = CollectError(
        operation="s3:GetBucketLocation",
        region="ap-northeast-2",
        error_code="AccessDenied",
        message="m",
        resource=BUCKET,
    )
    finding = _one([_trail()], {}, error)
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["error_code"] == "AccessDenied"
