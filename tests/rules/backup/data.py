"""AWS Backup 룰 테스트용 가짜 데이터. collector(kompass/collectors/backup.py)가 저장하는 형태다.

계획은 `ListBackupPlans` 항목에 `BackupPlan`(규칙)·`Selections`를 붙인 형태, 보호 리소스는
`ListProtectedResources` 항목 형태다. 수집에 실패한 부분은 키가 없다.
"""

from datetime import UTC, datetime
from typing import Any

from kompass.models import CollectError, Snapshot

REGION = "ap-northeast-2"
ACCOUNT = "123456789012"
COLLECTED = datetime(2026, 10, 18, tzinfo=UTC)
TABLE = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/orders"
VAULT = f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:main"

UNSET: Any = object()  # 기본값을 쓴다 (None은 키를 넣지 않음 = 수집 실패)


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


def protected(
    arn: str = TABLE,
    last: str | None = "2026-10-17T05:00:00Z",
    resource_type: str = "DynamoDB",
    name: str = "orders",
    vault: str = VAULT,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "ResourceArn": arn,
        "ResourceType": resource_type,
        "ResourceName": name,
        "LastBackupVaultArn": vault,
    }
    if last is not None:
        item["LastBackupTime"] = last
    return item


def snapshot(regions: dict[str, dict[str, Any]], errors: tuple[CollectError, ...] = ()) -> Snapshot:
    return Snapshot(
        service="backup",
        account_id=ACCOUNT,
        regions=tuple(regions),
        collected_at=COLLECTED,
        data={"regions": regions},
        errors=errors,
    )
