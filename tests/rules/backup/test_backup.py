"""BKP-001 백업 계획 미설정, BKP-002 보존 기간 부족, BKP-003 최근 백업 없음."""

from datetime import UTC, datetime
from typing import Any

import pytest

from kompass.config import BackupSettings, Settings
from kompass.models import CollectError, Finding, Snapshot, Status
from kompass.rules.backup.bkp_001_backup_plan import Bkp001BackupPlan
from kompass.rules.backup.bkp_002_retention import Bkp002Retention
from kompass.rules.backup.bkp_003_recent_backup import Bkp003RecentBackup

REGION = "ap-northeast-2"
ACCOUNT = "123456789012"
COLLECTED = datetime(2026, 10, 18, tzinfo=UTC)
TABLE = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/orders"
VAULT = f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:main"
BKP001 = Bkp001BackupPlan()
BKP002 = Bkp002Retention()
BKP003 = Bkp003RecentBackup()

UNSET: Any = object()  # 키를 넣지 않음 (수집 실패)


def backup_rule(name: str = "daily", **lifecycle: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "RuleName": name,
        "TargetBackupVaultName": "main",
        "ScheduleExpression": "cron(0 5 ? * * *)",
    }
    if lifecycle:
        item["Lifecycle"] = lifecycle
    return item


def selection(name: str = "tables", detail: bool = True, **fields: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"SelectionId": f"id-{name}", "SelectionName": name}
    if detail:
        item["BackupSelection"] = {
            "SelectionName": name,
            "IamRoleArn": f"arn:aws:iam::{ACCOUNT}:role/backup",
            "Resources": [TABLE],
            **fields,
        }
    return item


def plan(
    name: str = "daily",
    rules: Any = UNSET,
    selections: Any = UNSET,
) -> dict[str, Any]:
    item: dict[str, Any] = {"BackupPlanId": f"id-{name}", "BackupPlanName": name}
    if rules is not None:
        item["BackupPlan"] = {
            "BackupPlanName": name,
            "Rules": [backup_rule(DeleteAfterDays=35)] if rules is UNSET else rules,
        }
    if selections is not None:
        item["Selections"] = [selection()] if selections is UNSET else selections
    return item


def protected(arn: str = TABLE, last: str | None = "2026-10-17T05:00:00Z") -> dict[str, Any]:
    item: dict[str, Any] = {
        "ResourceArn": arn,
        "ResourceType": "DynamoDB",
        "ResourceName": "orders",
        "LastBackupVaultArn": VAULT,
    }
    if last is not None:
        item["LastBackupTime"] = last
    return item


def _snapshot(data: dict[str, Any], *errors: CollectError) -> Snapshot:
    return Snapshot(
        service="backup",
        account_id=ACCOUNT,
        regions=(REGION,),
        collected_at=COLLECTED,
        data={"regions": {REGION: data}},
        errors=errors,
    )


def _run(
    rule: Any, data: dict[str, Any], *errors: CollectError, settings: Settings | None = None
) -> list[Finding]:
    findings: list[Finding] = rule.evaluate(_snapshot(data, *errors), settings or Settings())
    assert all(f.region == REGION for f in findings)
    return findings


def _one(rule: Any, data: dict[str, Any], *errors: CollectError, **kwargs: Any) -> Finding:
    [finding] = _run(rule, data, *errors, **kwargs)
    return finding


def _error(operation: str, resource: str | None = None) -> CollectError:
    return CollectError(
        operation=operation,
        region=REGION,
        error_code="AccessDeniedException",
        message="no",
        resource=resource,
    )


# --- BKP-001 ---


def test_bkp001_pass_with_rule_and_selection() -> None:
    finding = _one(BKP001, {"plans": [plan()], "protected_resources": []})
    assert finding.status == Status.PASS and finding.resource == "account"
    [evidence] = finding.evidence["plans"]
    assert evidence["backup_plan"] == "daily"
    assert evidence["rules"] == [
        {
            "rule_name": "daily",
            "schedule": "cron(0 5 ? * * *)",
            "vault": "main",
            "delete_after_days": 35,
        }
    ]
    assert evidence["selections"] == [
        {"selection": "tables", "resources": 1, "not_resources": 0, "tags": 0, "conditions": 0}
    ]


def test_bkp001_pass_when_one_of_several_plans_is_complete() -> None:
    plans = [plan("empty", rules=[], selections=[]), plan()]
    assert _one(BKP001, {"plans": plans}).status == Status.PASS


def test_bkp001_review_without_plans() -> None:
    finding = _one(BKP001, {"plans": [], "protected_resources": []})
    assert finding.status == Status.REVIEW
    assert finding.evidence["plans"] == []


@pytest.mark.parametrize(
    "item",
    [
        plan(selections=[]),  # 백업 대상 선택 없음
        plan(rules=[]),  # 규칙 없음
        plan(rules=None, selections=[]),  # 상세는 몰라도 선택이 없으니 대상이 없다
    ],
)
def test_bkp001_fail_when_no_plan_backs_anything_up(item: dict[str, Any]) -> None:
    errors = [] if "BackupPlan" in item else [_error("backup:GetBackupPlan", "daily")]
    assert _one(BKP001, {"plans": [item]}, *errors).status == Status.FAIL


def test_bkp001_error_when_plans_not_collected() -> None:
    finding = _one(BKP001, {"protected_resources": []}, _error("backup:ListBackupPlans"))
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["operation"] == "backup:ListBackupPlans"


@pytest.mark.parametrize(
    ("item", "operation"),
    [
        (plan(rules=None), "backup:GetBackupPlan"),
        (plan(selections=None), "backup:ListBackupSelections"),
    ],
)
def test_bkp001_error_when_completeness_unknown(item: dict[str, Any], operation: str) -> None:
    finding = _one(BKP001, {"plans": [item]}, _error(operation, "daily"))
    assert finding.status == Status.ERROR
    assert [e["operation"] for e in finding.evidence["errors"]] == [operation]


def test_bkp001_selection_detail_missing_still_counts_as_selection() -> None:
    finding = _one(BKP001, {"plans": [plan(selections=[selection(detail=False)])]})
    assert finding.status == Status.PASS
    [evidence] = finding.evidence["plans"]
    assert evidence["selections"] == [
        {
            "selection": "tables",
            "resources": None,
            "not_resources": None,
            "tags": None,
            "conditions": None,
        }
    ]


def test_bkp001_counts_tag_and_condition_selections() -> None:
    tagged = selection(
        "tagged",
        Resources=[],
        ListOfTags=[
            {"ConditionType": "STRINGEQUALS", "ConditionKey": "backup", "ConditionValue": "y"}
        ],
        Conditions={
            "StringEquals": [{"ConditionKey": "aws:ResourceTag/env", "ConditionValue": "p"}]
        },
    )
    finding = _one(BKP001, {"plans": [plan(selections=[tagged])]})
    [evidence] = finding.evidence["plans"]
    assert evidence["selections"] == [
        {"selection": "tagged", "resources": 0, "not_resources": 0, "tags": 1, "conditions": 1}
    ]


# --- BKP-002 ---


def test_bkp002_pass_when_retention_meets_minimum() -> None:
    finding = _one(BKP002, {"plans": [plan()]})
    assert finding.status == Status.PASS and finding.resource == "backup-plan:daily"
    assert finding.evidence["min_retention_days"] == 7
    assert finding.evidence["short_rules"] == []


def test_bkp002_pass_when_retention_is_unlimited() -> None:
    assert _one(BKP002, {"plans": [plan(rules=[backup_rule()])]}).status == Status.PASS


def test_bkp002_fail_when_any_rule_is_short() -> None:
    rules = [backup_rule("long", DeleteAfterDays=35), backup_rule("short", DeleteAfterDays=1)]
    finding = _one(BKP002, {"plans": [plan(rules=rules)]})
    assert finding.status == Status.FAIL
    assert finding.evidence["short_rules"] == ["short"]


def test_bkp002_uses_configured_minimum() -> None:
    settings = Settings(backup=BackupSettings(min_retention_days=90))
    assert _one(BKP002, {"plans": [plan()]}, settings=settings).status == Status.FAIL


def test_bkp002_review_when_deleted_after_copy() -> None:
    rule = backup_rule(DeleteAfterDays=35, DeleteAfterEvent="DELETE_AFTER_COPY")
    rule["CopyActions"] = [
        {"DestinationBackupVaultArn": VAULT, "Lifecycle": {"DeleteAfterDays": 365}}
    ]
    finding = _one(BKP002, {"plans": [plan(rules=[rule])]})
    assert finding.status == Status.REVIEW
    [evidence] = finding.evidence["rules"]
    assert evidence["delete_after_event"] == "DELETE_AFTER_COPY"
    assert evidence["copy_actions"] == [{"destination_vault": VAULT, "delete_after_days": 365}]


def test_bkp002_one_finding_per_plan() -> None:
    plans = [plan("a"), plan("b", rules=[backup_rule(DeleteAfterDays=3)])]
    statuses = {f.resource: f.status for f in _run(BKP002, {"plans": plans})}
    assert statuses == {"backup-plan:a": Status.PASS, "backup-plan:b": Status.FAIL}


def test_bkp002_not_applicable() -> None:
    assert _one(BKP002, {"plans": []}).status == Status.NOT_APPLICABLE
    finding = _one(BKP002, {"plans": [plan(rules=[])]})
    assert finding.status == Status.NOT_APPLICABLE and finding.resource == "backup-plan:daily"


def test_bkp002_error_when_plans_not_collected() -> None:
    finding = _one(BKP002, {}, _error("backup:ListBackupPlans"))
    assert finding.status == Status.ERROR and finding.resource == "account"


def test_bkp002_error_when_plan_detail_missing() -> None:
    finding = _one(BKP002, {"plans": [plan(rules=None)]}, _error("backup:GetBackupPlan", "daily"))
    assert finding.status == Status.ERROR and finding.resource == "backup-plan:daily"
    assert finding.evidence["errors"][0]["resource"] == "daily"


# --- BKP-003 ---


def test_bkp003_pass_with_recent_backup() -> None:
    finding = _one(BKP003, {"plans": [plan()], "protected_resources": [protected()]})
    assert finding.status == Status.PASS and finding.resource == TABLE
    assert finding.evidence == {
        "resource_type": "DynamoDB",
        "resource_name": "orders",
        "last_backup_time": "2026-10-17T05:00:00Z",
        "days_since_backup": 0,
        "max_backup_age_days": 7,
        "last_backup_vault": VAULT,
    }


def test_bkp003_fail_with_stale_backup() -> None:
    finding = _one(BKP003, {"protected_resources": [protected(last="2026-10-01T00:00:00Z")]})
    assert finding.status == Status.FAIL and finding.evidence["days_since_backup"] == 17


def test_bkp003_boundary_and_configured_limit() -> None:
    data = {"protected_resources": [protected(last="2026-10-11T00:00:00Z")]}  # 정확히 7일
    assert _one(BKP003, data).status == Status.PASS
    settings = Settings(backup=BackupSettings(max_backup_age_days=1))
    assert _one(BKP003, data, settings=settings).status == Status.FAIL


def test_bkp003_does_not_need_plans_when_resources_exist() -> None:
    # 계획 목록을 수집하지 못해도 보호 리소스는 판정할 수 있다
    finding = _one(BKP003, {"protected_resources": [protected()]}, _error("backup:ListBackupPlans"))
    assert finding.status == Status.PASS


def test_bkp003_fail_when_plan_has_selection_but_nothing_backed_up() -> None:
    finding = _one(BKP003, {"plans": [plan()], "protected_resources": []})
    assert finding.status == Status.FAIL and finding.resource == "account"
    assert finding.evidence["plans_with_selections"] == ["daily"]


@pytest.mark.parametrize("plans", [[], [plan(selections=[])]])
def test_bkp003_not_applicable_without_selections(plans: list[dict[str, Any]]) -> None:
    finding = _one(BKP003, {"plans": plans, "protected_resources": []})
    assert finding.status == Status.NOT_APPLICABLE and finding.resource == "account"


def test_bkp003_error_when_resources_not_collected() -> None:
    finding = _one(BKP003, {"plans": [plan()]}, _error("backup:ListProtectedResources"))
    assert finding.status == Status.ERROR and finding.resource == "account"


@pytest.mark.parametrize(
    ("data", "operation"),
    [
        ({"protected_resources": []}, "backup:ListBackupPlans"),
        (
            {"plans": [plan(selections=None)], "protected_resources": []},
            "backup:ListBackupSelections",
        ),
    ],
)
def test_bkp003_error_when_empty_result_cannot_be_judged(
    data: dict[str, Any], operation: str
) -> None:
    finding = _one(BKP003, data, _error(operation, "daily"))
    assert finding.status == Status.ERROR and finding.resource == "account"
    assert [e["operation"] for e in finding.evidence["errors"]] == [operation]


def test_bkp003_error_when_last_backup_time_missing() -> None:
    finding = _one(BKP003, {"protected_resources": [protected(last=None)]})
    assert finding.status == Status.ERROR and finding.resource == TABLE
