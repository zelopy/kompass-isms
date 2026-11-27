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
    status: dict[str, Any] | None = None,
) -> list[Finding]:
    data: dict[str, Any] = {
        "status": status or {},
        "event_selectors": {},
        "bucket_lifecycles": lifecycles,
    }
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


def _bucket_error(code: str, operation: str = "s3:GetBucketLocation") -> CollectError:
    return CollectError(
        operation=operation,
        region="ap-northeast-2",
        error_code=code,
        message="m",
        resource=BUCKET,
    )


def _status(trail: dict[str, Any], is_logging: bool) -> dict[str, Any]:
    return {trail["TrailARN"]: {"IsLogging": is_logging}}


def test_error_when_lifecycle_not_collected() -> None:
    finding = _one([_trail()], {}, _bucket_error("AccessDenied"))
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["error_code"] == "AccessDenied"


def test_error_message_names_error_code() -> None:
    # 확인 불가의 원인이 권한인지 보고서 요약에서 바로 보이게 한다 (ADR-056)
    finding = _one([_trail()], {}, _bucket_error("AccessDenied"))
    assert "(AccessDenied)" in finding.message


@pytest.mark.parametrize(
    "operation", ["s3:GetBucketLocation", "s3:GetBucketLifecycleConfiguration"]
)
def test_fail_when_bucket_does_not_exist(operation: str) -> None:
    # NoSuchBucket은 버킷이 없다는 확정된 사실이다. 로그를 보존할 곳이 없으므로 FAIL (ADR-056)
    finding = _one([_trail()], {}, _bucket_error("NoSuchBucket", operation))
    assert finding.status == Status.FAIL
    assert "존재하지 않음" in finding.message
    assert finding.evidence["errors"][0]["error_code"] == "NoSuchBucket"


def test_no_such_bucket_wins_over_other_errors() -> None:
    errors = (_bucket_error("NoSuchBucket"), _bucket_error("AccessDenied"))
    assert _one([_trail()], {}, *errors).status == Status.FAIL


def test_errors_of_other_buckets_are_ignored() -> None:
    other = CollectError(
        operation="s3:GetBucketLocation",
        region="ap-northeast-2",
        error_code="NoSuchBucket",
        message="m",
        resource="other",
    )
    assert _one([_trail()], {}, other).status == Status.ERROR


def test_evidence_lists_trails_and_logging_state() -> None:
    a, b, c = _trail("a"), _trail("b"), _trail("c")
    status = {**_status(a, True), **_status(b, False)}  # c는 상태를 수집하지 못함
    finding = _one([a, b, c], {BUCKET: None}, status=status)
    assert finding.evidence["trails"] == [
        {"trail": "a", "is_logging": True},
        {"trail": "b", "is_logging": False},
        {"trail": "c", "is_logging": None},
    ]
    assert "로깅 중지" not in finding.message


@pytest.mark.parametrize(
    ("lifecycles", "errors", "status"),
    [
        ({BUCKET: None}, (), Status.PASS),
        ({BUCKET: [_expire(30)]}, (), Status.FAIL),
        ({}, (_bucket_error("NoSuchBucket"),), Status.FAIL),
        ({}, (_bucket_error("AccessDenied"),), Status.ERROR),
    ],
)
def test_message_marks_bucket_used_only_by_stopped_trails(
    lifecycles: dict[str, Any], errors: tuple[CollectError, ...], status: Status
) -> None:
    trail = _trail()
    finding = _one([trail], lifecycles, *errors, status=_status(trail, False))
    assert finding.status == status
    assert finding.message.endswith("(로깅 중지된 추적만 사용)")


def test_unknown_logging_state_is_not_marked_stopped() -> None:
    # 상태를 모르는 추적이 섞이면 중지되었다고 단정하지 않는다
    a, b = _trail("a"), _trail("b")
    finding = _one([a, b], {BUCKET: None}, status=_status(a, False))
    assert "로깅 중지" not in finding.message
