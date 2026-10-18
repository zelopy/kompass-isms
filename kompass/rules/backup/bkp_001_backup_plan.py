"""BKP-001 AWS Backup 백업 계획 미설정 (KISA CA-18, docs/RULES.md).

리전마다 규칙과 리소스 선택을 모두 가진 계획이 있으면 PASS. 계획이 없으면 다른 수단으로 백업할
수 있으므로 REVIEW다 (ADR-054).
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.backup._backup import (
    PLAN_OPERATIONS,
    SELECTION_OPERATIONS,
    BackupRule,
    plan_name,
    plan_rules,
    plan_selections,
    region_errors,
)

_CONDITION_KEYS = ("StringEquals", "StringNotEquals", "StringLike", "StringNotLike")


def _count(values: Any) -> int:
    return len(values) if isinstance(values, list) else 0


def _selection_evidence(selection: dict[str, Any]) -> dict[str, Any]:
    detail = selection.get("BackupSelection")
    if detail is None:
        counts: dict[str, int | None] = dict.fromkeys(
            ("resources", "not_resources", "tags", "conditions")
        )
    else:
        conditions = detail.get("Conditions") or {}
        counts = {
            "resources": _count(detail.get("Resources")),
            "not_resources": _count(detail.get("NotResources")),
            "tags": _count(detail.get("ListOfTags")),
            "conditions": sum(_count(conditions.get(key)) for key in _CONDITION_KEYS),
        }
    return {"selection": selection.get("SelectionName"), **counts}


def plan_evidence(plan: dict[str, Any]) -> dict[str, Any]:
    rules = plan_rules(plan)
    selections = plan_selections(plan)
    return {
        "backup_plan": plan_name(plan),
        "rules": None
        if rules is None
        else [
            {
                "rule_name": rule.get("RuleName"),
                "schedule": rule.get("ScheduleExpression"),
                "vault": rule.get("TargetBackupVaultName"),
                "delete_after_days": (rule.get("Lifecycle") or {}).get("DeleteAfterDays"),
            }
            for rule in rules
        ],
        "selections": None if selections is None else [_selection_evidence(s) for s in selections],
    }


def _complete(plan: dict[str, Any]) -> bool:
    return bool(plan_rules(plan)) and bool(plan_selections(plan))


def _unknown(plan: dict[str, Any]) -> bool:
    """수집하지 못한 부분 때문에 완전한 계획인지 알 수 없다."""
    rules, selections = plan_rules(plan), plan_selections(plan)
    return (rules is None and selections != []) or (selections is None and rules != [])


class Bkp001BackupPlan(BackupRule):
    id: ClassVar[str] = "BKP-001"
    title: ClassVar[str] = "AWS Backup 백업 계획 미설정"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        for region, data in snapshot.data.get("regions", {}).items():
            plans = data.get("plans")
            if plans is None:
                findings.append(
                    self.region_finding(
                        snapshot,
                        region,
                        Status.ERROR,
                        "AWS Backup 백업 계획 목록을 수집하지 못함",
                        {"errors": region_errors(snapshot, region, PLAN_OPERATIONS)},
                    )
                )
                continue
            evidence: dict[str, Any] = {"plans": [plan_evidence(p) for p in plans]}
            if not plans:
                status = Status.REVIEW
                message = "AWS Backup 백업 계획이 없음. 다른 수단의 백업 여부 확인 필요"
            elif any(_complete(p) for p in plans):
                status, message = Status.PASS, "규칙과 백업 대상이 지정된 백업 계획이 있음"
            elif any(_unknown(p) for p in plans):
                status, message = Status.ERROR, "백업 계획의 규칙이나 백업 대상을 수집하지 못함"
                evidence["errors"] = region_errors(
                    snapshot, region, PLAN_OPERATIONS + SELECTION_OPERATIONS
                )
            else:
                status, message = Status.FAIL, "백업 계획에 규칙이나 백업 대상 선택이 없음"
            findings.append(self.region_finding(snapshot, region, status, message, evidence))
        return findings
