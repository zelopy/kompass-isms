"""AWS Backup collector: 백업 계획·리소스 선택·보호 리소스 (BKP-001~003, ADR-054).

수집 데이터 (`Snapshot.data`):
- `regions.<리전>.plans`: `ListBackupPlans` 항목. `GetBackupPlan` 응답의 `BackupPlan`(규칙)과,
  `ListBackupSelections` 항목에 `GetBackupSelection` 응답의 `BackupSelection`을 더한
  `Selections`를 붙인다. 상세나 선택 목록 조회에 실패하면 그 키가 없고, 선택 상세 조회에 실패한
  선택은 목록 항목만 남는다 (오류의 resource=계획 이름, 선택은 `<계획 이름>/<선택 이름>`).
- `regions.<리전>.protected_resources`: `ListProtectedResources` 항목 (마지막 백업 시각).
목록 조회에 실패한 종류는 키가 없다.
"""

from datetime import UTC, datetime
from typing import Any

from kompass.aws.session import ScanContext
from kompass.collectors.base import CallRecorder
from kompass.models import Snapshot


class BackupCollector:
    service = "backup"

    def collect(self, scan: ScanContext) -> Snapshot:
        collected_at = datetime.now(UTC)
        recorder = CallRecorder()
        regions: dict[str, dict[str, Any]] = {}
        for region in scan.regions:
            collected: dict[str, Any] = {}
            backup = scan.session.client("backup", region_name=region)
            plans = recorder.paginate(backup, "list_backup_plans", "BackupPlansList")
            if plans is not None:
                collected["plans"] = [self._plan(recorder, backup, plan) for plan in plans]
            protected = recorder.paginate(backup, "list_protected_resources", "Results")
            if protected is not None:
                collected["protected_resources"] = protected
            regions[region] = collected

        return Snapshot(
            service=self.service,
            account_id=scan.account_id,
            regions=scan.regions,
            collected_at=collected_at,
            data={"regions": regions},
            errors=tuple(recorder.errors),
        )

    @classmethod
    def _plan(cls, recorder: CallRecorder, client: Any, plan: dict[str, Any]) -> dict[str, Any]:
        plan_id, name = plan["BackupPlanId"], plan["BackupPlanName"]
        result = dict(plan)
        detail = recorder.call(client, "get_backup_plan", resource=name, BackupPlanId=plan_id)
        if isinstance(detail, dict) and "BackupPlan" in detail:
            result["BackupPlan"] = detail["BackupPlan"]
        selections = recorder.paginate(
            client,
            "list_backup_selections",
            "BackupSelectionsList",
            resource=name,
            BackupPlanId=plan_id,
        )
        if selections is not None:
            result["Selections"] = [
                cls._selection(recorder, client, name, selection) for selection in selections
            ]
        return result

    @staticmethod
    def _selection(
        recorder: CallRecorder, client: Any, plan_name: str, selection: dict[str, Any]
    ) -> dict[str, Any]:
        detail = recorder.call(
            client,
            "get_backup_selection",
            resource=f"{plan_name}/{selection['SelectionName']}",
            BackupPlanId=selection["BackupPlanId"],
            SelectionId=selection["SelectionId"],
        )
        if isinstance(detail, dict) and "BackupSelection" in detail:
            return {**selection, "BackupSelection": detail["BackupSelection"]}
        return selection
