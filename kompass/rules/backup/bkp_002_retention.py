"""BKP-002 AWS Backup 보존 기간 부족 (KISA CA-18, docs/RULES.md).

계획마다 규칙의 `Lifecycle.DeleteAfterDays`를 `backup.min_retention_days`와 비교한다. 값이 없으면
무기한 보관이다. 복사 뒤 원본을 지우는 규칙(`DeleteAfterEvent`)은 REVIEW다.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.backup._backup import (
    PLAN_OPERATIONS,
    BackupRule,
    plan_name,
    plan_rules,
    region_errors,
)
from kompass.rules.base import errors_evidence, errors_for


def _rule_evidence(rule: dict[str, Any]) -> dict[str, Any]:
    lifecycle = rule.get("Lifecycle") or {}
    return {
        "rule_name": rule.get("RuleName"),
        "delete_after_days": lifecycle.get("DeleteAfterDays"),
        "move_to_cold_storage_after_days": lifecycle.get("MoveToColdStorageAfterDays"),
        "delete_after_event": lifecycle.get("DeleteAfterEvent"),
        "continuous_backup": rule.get("EnableContinuousBackup", False),
        "copy_actions": [
            {
                "destination_vault": action.get("DestinationBackupVaultArn"),
                "delete_after_days": (action.get("Lifecycle") or {}).get("DeleteAfterDays"),
            }
            for action in rule.get("CopyActions", [])
        ],
    }


class Bkp002Retention(BackupRule):
    id: ClassVar[str] = "BKP-002"
    title: ClassVar[str] = "AWS Backup 보존 기간 부족"
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
            elif not plans:
                findings.append(
                    self.region_finding(
                        snapshot, region, Status.NOT_APPLICABLE, "AWS Backup 백업 계획이 없음", {}
                    )
                )
            else:
                findings.extend(self._judge(snapshot, settings, region, p) for p in plans)
        return findings

    def _judge(
        self, snapshot: Snapshot, settings: Settings, region: str, plan: dict[str, Any]
    ) -> Finding:
        name = plan_name(plan)
        # 조치 명령(update-backup-plan)은 계획 이름이 아니라 ID를 받는다
        plan_id = plan.get("BackupPlanId")
        minimum = settings.backup.min_retention_days
        rules = plan_rules(plan)

        def result(status: Status, message: str, evidence: dict[str, Any]) -> Finding:
            return self.finding(
                snapshot,
                resource=f"backup-plan:{name}",
                region=region,
                status=status,
                message=message,
                evidence=evidence,
            )

        if rules is None:
            errors = [
                e for e in errors_for(snapshot, "backup:GetBackupPlan", name) if e.region == region
            ]
            return result(
                Status.ERROR,
                f"백업 계획 상세를 수집하지 못함: {name}",
                {"backup_plan_id": plan_id, "errors": errors_evidence(errors)},
            )
        if not rules:
            return result(Status.NOT_APPLICABLE, f"백업 계획에 규칙이 없음: {name}", {})
        evidence_rules = [_rule_evidence(rule) for rule in rules]
        short = [
            r["rule_name"]
            for r in evidence_rules
            if r["delete_after_days"] is not None and r["delete_after_days"] < minimum
        ]
        evidence = {
            "backup_plan_id": plan_id,
            "min_retention_days": minimum,
            "rules": evidence_rules,
            "short_rules": short,
        }
        if short:
            return result(
                Status.FAIL, f"보존 기간이 {minimum}일보다 짧은 백업 규칙이 있음: {name}", evidence
            )
        if any(r["delete_after_event"] for r in evidence_rules):
            return result(
                Status.REVIEW,
                f"복사 뒤 원본 복구 지점을 삭제하는 규칙이 있어 복사본 보존 기간 확인 필요: {name}",
                evidence,
            )
        return result(Status.PASS, f"백업 보존 기간이 {minimum}일 이상임: {name}", evidence)
