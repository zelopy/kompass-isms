"""AWS Backup collector 테스트 (계획·선택·보호 리소스).

moto 5.2.4는 선택과 보호 리소스 API가 없어 backup client를 모두 Stubber로 만든다 (ADR-054).
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from botocore.stub import Stubber
from moto import mock_aws

from kompass.aws.guard import read_only_session
from kompass.aws.session import ScanContext
from kompass.collectors.backup import BackupCollector
from kompass.snapshots import SnapshotStore, load_scan
from tests.collectors.stubbing import StubbingSession

ACCOUNT = "123456789012"
HOME = "ap-northeast-2"
PLAN_ID = "11111111-2222-3333-4444-555555555555"
SELECTION_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TABLE_ARN = f"arn:aws:dynamodb:{HOME}:{ACCOUNT}:table/orders"
VAULT_ARN = f"arn:aws:backup:{HOME}:{ACCOUNT}:backup-vault:main"
CREATED = datetime(2026, 10, 1, tzinfo=UTC)
LAST_BACKUP = datetime(2026, 10, 17, 5, 0, tzinfo=UTC)


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


def _scan(session: Any) -> ScanContext:
    return ScanContext(
        session=session,
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region=HOME,
        regions=(HOME,),
    )


def _plan_item() -> dict[str, Any]:
    return {
        "BackupPlanId": PLAN_ID,
        "BackupPlanName": "daily",
        "BackupPlanArn": f"arn:aws:backup:{HOME}:{ACCOUNT}:backup-plan:{PLAN_ID}",
        "VersionId": "v1",
        "CreationDate": CREATED,
    }


def _plan_detail() -> dict[str, Any]:
    return {
        "BackupPlanId": PLAN_ID,
        "VersionId": "v1",
        "BackupPlan": {
            "BackupPlanName": "daily",
            "Rules": [
                {
                    "RuleName": "daily-35d",
                    "TargetBackupVaultName": "main",
                    "ScheduleExpression": "cron(0 5 ? * * *)",
                    "Lifecycle": {"DeleteAfterDays": 35},
                }
            ],
        },
    }


def _selection_item() -> dict[str, Any]:
    return {
        "SelectionId": SELECTION_ID,
        "SelectionName": "tables",
        "BackupPlanId": PLAN_ID,
        "IamRoleArn": f"arn:aws:iam::{ACCOUNT}:role/backup",
    }


def _selection_detail() -> dict[str, Any]:
    return {
        "SelectionId": SELECTION_ID,
        "BackupPlanId": PLAN_ID,
        "BackupSelection": {
            "SelectionName": "tables",
            "IamRoleArn": f"arn:aws:iam::{ACCOUNT}:role/backup",
            "Resources": [TABLE_ARN],
        },
    }


def _protected() -> dict[str, Any]:
    return {
        "ResourceArn": TABLE_ARN,
        "ResourceType": "DynamoDB",
        "LastBackupTime": LAST_BACKUP,
        "ResourceName": "orders",
        "LastBackupVaultArn": VAULT_ARN,
    }


def _collect(add_responses: Any) -> Any:
    session = read_only_session()
    backup = session.client("backup", region_name=HOME)
    with Stubber(backup) as stub:
        add_responses(stub)
        snapshot = BackupCollector().collect(
            _scan(StubbingSession(session, {("backup", HOME): backup}))
        )
        stub.assert_no_pending_responses()
    return snapshot


def _full(stub: Stubber) -> None:
    stub.add_response("list_backup_plans", {"BackupPlansList": [_plan_item()]})
    stub.add_response("get_backup_plan", _plan_detail(), {"BackupPlanId": PLAN_ID})
    stub.add_response(
        "list_backup_selections",
        {"BackupSelectionsList": [_selection_item()]},
        {"BackupPlanId": PLAN_ID},
    )
    stub.add_response(
        "get_backup_selection",
        _selection_detail(),
        {"BackupPlanId": PLAN_ID, "SelectionId": SELECTION_ID},
    )
    stub.add_response("list_protected_resources", {"Results": [_protected()]})


def test_collects_plans_selections_and_protected_resources(aws: None) -> None:
    snapshot = _collect(_full)
    assert snapshot.service == "backup" and snapshot.errors == ()
    region = snapshot.data["regions"][HOME]
    [plan] = region["plans"]
    assert plan["BackupPlanName"] == "daily"
    assert plan["BackupPlan"]["Rules"][0]["Lifecycle"] == {"DeleteAfterDays": 35}
    [selection] = plan["Selections"]
    assert selection["SelectionName"] == "tables"
    assert selection["BackupSelection"]["Resources"] == [TABLE_ARN]
    [resource] = region["protected_resources"]
    assert resource["ResourceArn"] == TABLE_ARN
    assert resource["LastBackupTime"] == "2026-10-17T05:00:00Z"  # ISO 8601 문자열 (ADR-019)


def test_region_without_backup(aws: None) -> None:
    def empty(stub: Stubber) -> None:
        stub.add_response("list_backup_plans", {"BackupPlansList": []})
        stub.add_response("list_protected_resources", {"Results": []})

    region = _collect(empty).data["regions"][HOME]
    assert region == {"plans": [], "protected_resources": []}


def test_snapshot_round_trips_through_store(aws: None, tmp_path: Path) -> None:
    snapshot = _collect(_full)
    scan = _scan(read_only_session())
    writer = SnapshotStore(tmp_path / ".kompass").begin(scan)
    writer.write(snapshot)
    assert load_scan(writer.finish())[1]["backup"] == snapshot


def test_detail_failures_are_recorded_and_keys_missing(aws: None) -> None:
    other = {**_plan_item(), "BackupPlanId": "other-id", "BackupPlanName": "weekly"}

    def failing(stub: Stubber) -> None:
        stub.add_response("list_backup_plans", {"BackupPlansList": [_plan_item(), other]})
        # daily: 상세 거부, 선택 상세 거부
        stub.add_client_error("get_backup_plan", service_error_code="AccessDeniedException")
        stub.add_response("list_backup_selections", {"BackupSelectionsList": [_selection_item()]})
        stub.add_client_error("get_backup_selection", service_error_code="AccessDeniedException")
        # weekly: 선택 목록 거부
        stub.add_response("get_backup_plan", {**_plan_detail(), "BackupPlanId": "other-id"})
        stub.add_client_error("list_backup_selections", service_error_code="AccessDeniedException")
        stub.add_client_error(
            "list_protected_resources", service_error_code="AccessDeniedException"
        )

    snapshot = _collect(failing)
    region = snapshot.data["regions"][HOME]
    daily, weekly = region["plans"]
    assert "BackupPlan" not in daily
    assert daily["Selections"] == [_selection_item()]  # 상세가 없으면 목록 항목만 남는다
    assert "BackupPlan" in weekly and "Selections" not in weekly
    assert "protected_resources" not in region
    assert {(e.operation, e.resource) for e in snapshot.errors} == {
        ("backup:GetBackupPlan", "daily"),
        ("backup:GetBackupSelection", "daily/tables"),
        ("backup:ListBackupSelections", "weekly"),
        ("backup:ListProtectedResources", None),
    }


def test_plan_list_failure_skips_plan_details(aws: None) -> None:
    def failing(stub: Stubber) -> None:
        stub.add_client_error("list_backup_plans", service_error_code="AccessDeniedException")
        stub.add_response("list_protected_resources", {"Results": [_protected()]})

    snapshot = _collect(failing)
    region = snapshot.data["regions"][HOME]
    assert "plans" not in region and len(region["protected_resources"]) == 1
    assert [e.operation for e in snapshot.errors] == ["backup:ListBackupPlans"]
