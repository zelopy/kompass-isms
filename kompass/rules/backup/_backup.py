"""BKP-001~003 공통: 백업 계획·선택 읽기와 리전 finding (ADR-054).

collector 규약: 계획의 `BackupPlan`·`Selections` 키가 없으면 수집 실패다.
"""

from typing import Any

from kompass.models import Finding, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence

PLAN_OPERATIONS = ("backup:ListBackupPlans", "backup:GetBackupPlan")
SELECTION_OPERATIONS = ("backup:ListBackupSelections", "backup:GetBackupSelection")
PROTECTED_OPERATIONS = ("backup:ListProtectedResources",)


def plan_rules(plan: dict[str, Any]) -> list[dict[str, Any]] | None:
    """계획의 규칙. 상세를 수집하지 못했으면 None."""
    detail = plan.get("BackupPlan")
    return None if detail is None else list(detail.get("Rules", []))


def plan_selections(plan: dict[str, Any]) -> list[dict[str, Any]] | None:
    """계획의 리소스 선택. 선택 목록을 수집하지 못했으면 None."""
    selections = plan.get("Selections")
    return None if selections is None else list(selections)


def plan_name(plan: dict[str, Any]) -> str:
    return str(plan["BackupPlanName"])


def region_errors(
    snapshot: Snapshot, region: str, operations: tuple[str, ...]
) -> list[dict[str, Any]]:
    return errors_evidence(
        [e for e in snapshot.errors if e.region == region and e.operation in operations]
    )


class BackupRule(BaseRule):
    service = "backup"

    def region_finding(
        self,
        snapshot: Snapshot,
        region: str,
        status: Status,
        message: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return self.finding(
            snapshot,
            resource=ACCOUNT_RESOURCE,
            region=region,
            status=status,
            message=message,
            evidence=evidence,
        )
