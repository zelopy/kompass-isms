"""LOG-001 보안 로그 보존 기간 부족."""

from datetime import UTC, datetime
from typing import Any

from kompass.config import LogsSettings, Settings
from kompass.models import CollectError, Finding, Snapshot, Status
from kompass.rules.logs.log_001_security_log_retention import Log001SecurityLogRetention

RULE = Log001SecurityLogRetention()
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"


def group(name: str, days: int | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "logGroupName": name,
        "logGroupArn": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{name}",
    }
    if days is not None:
        item["retentionInDays"] = days
    return item


def trail(
    name: str, log_group: str, region: str = REGION, account: str = ACCOUNT
) -> dict[str, Any]:
    return {
        "trail": name,
        "log_group_arn": f"arn:aws:logs:{region}:{account}:log-group:{log_group}:*",
    }


def _run(
    groups: list[dict[str, Any]] | None,
    *,
    flows: list[dict[str, Any]] | None = None,
    trails: list[dict[str, Any]] | None = None,
    errors: tuple[CollectError, ...] = (),
    settings: Settings | None = None,
) -> list[Finding]:
    region: dict[str, Any] = {"flow_log_groups": flows or []}
    if groups is not None:
        region["log_groups"] = groups
    data: dict[str, Any] = {"regions": {REGION: region}}
    if trails is not None or not errors:
        data["trail_log_groups"] = trails or []
    snapshot = Snapshot(
        service="logs",
        account_id=ACCOUNT,
        regions=(REGION,),
        collected_at=datetime(2026, 10, 16, tzinfo=UTC),
        data=data,
        errors=errors,
    )
    return RULE.evaluate(snapshot, settings or Settings())


def _statuses(findings: list[Finding]) -> dict[str, Status]:
    return {f.resource: f.status for f in findings}


def test_security_groups_are_judged_and_others_ignored() -> None:
    groups = [
        group("trail-logs", 400),
        group("flow-logs", 30),
        group("/aws/rds/instance/db/postgresql"),  # 영구 보관
        group("/aws/lambda/app", 7),  # 보안 로그 아님
    ]
    findings = _run(
        groups,
        flows=[{"flow_log_id": "fl-1", "log_group": "flow-logs"}],
        trails=[trail("main", "trail-logs")],
    )
    assert _statuses(findings) == {
        "trail-logs": Status.PASS,
        "flow-logs": Status.FAIL,
        "/aws/rds/instance/db/postgresql": Status.PASS,
    }
    flow = next(f for f in findings if f.resource == "flow-logs")
    assert (
        flow.evidence["retention_days"] == 30 and flow.evidence["sources"][0]["type"] == "flow_log"
    )


def test_threshold_and_prefixes_from_settings() -> None:
    settings = Settings(
        logs=LogsSettings(min_retention_days=30, security_log_group_prefixes=("/aws/lambda/",))
    )
    findings = _run([group("/aws/lambda/app", 30), group("/aws/rds/x", 1)], settings=settings)
    assert _statuses(findings) == {"/aws/lambda/app": Status.PASS}


def test_missing_referenced_group_fails() -> None:
    findings = _run([], trails=[trail("main", "deleted-group")])
    assert _statuses(findings) == {"deleted-group": Status.FAIL}


def test_trail_group_in_other_region_or_account_is_ignored() -> None:
    trails = [trail("a", "x", region="us-east-1"), trail("b", "y", account="999999999999")]
    [finding] = _run([group("x", 1), group("y", 1)], trails=trails)
    assert finding.status == Status.NOT_APPLICABLE and finding.resource == "account"
    assert finding.evidence["log_groups"] == 2


def test_error_when_log_groups_missing() -> None:
    error = CollectError(
        operation="logs:DescribeLogGroups", region=REGION, error_code="AccessDenied", message="m"
    )
    [finding] = _run(None, errors=(error,), trails=[])
    assert finding.status == Status.ERROR


def test_error_when_trail_sources_missing() -> None:
    error = CollectError(
        operation="cloudtrail:DescribeTrails", region=REGION, error_code="AccessDenied", message="m"
    )
    [finding] = _run([group("/aws/rds/x", 400)], errors=(error,))
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["operation"] == "cloudtrail:DescribeTrails"
