"""GD-002 GuardDuty 결과 알림 미설정 (KISA CA-19, docs/RULES.md).

GuardDuty가 활성화된 리전에서, 기본 이벤트 버스에 GuardDuty 결과를 대상으로 보내는 활성 규칙이
있는지 본다. 알림이 실제로 담당자에게 전달되는지는 사람이 확인한다.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.guardduty._guardduty import (
    DetectorState,
    GuardDutyRule,
    detector_state,
    region_errors,
)

_ENABLED = "ENABLED"


class Gd002FindingAlerts(GuardDutyRule):
    id: ClassVar[str] = "GD-002"
    title: ClassVar[str] = "GuardDuty 결과 알림 미설정"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        return [
            self._judge(snapshot, region, data)
            for region, data in snapshot.data.get("regions", {}).items()
        ]

    def _judge(self, snapshot: Snapshot, region: str, data: dict[str, Any]) -> Finding:
        missing = tuple(kind for kind in ("detectors", "event_rules") if kind not in data)
        if missing:
            return self.region_finding(
                snapshot,
                region,
                Status.ERROR,
                "GuardDuty 알림 판정에 필요한 데이터를 수집하지 못함",
                {"errors": region_errors(snapshot, region, missing)},
            )
        state = detector_state(data["detectors"])
        if state == DetectorState.UNKNOWN:
            return self.region_finding(
                snapshot,
                region,
                Status.ERROR,
                "GuardDuty 탐지기 상태를 수집하지 못함",
                {"errors": region_errors(snapshot, region, ("detectors",))},
            )
        if state == DetectorState.DISABLED:
            return self.region_finding(
                snapshot, region, Status.NOT_APPLICABLE, "GuardDuty가 활성화되지 않음 (GD-001)", {}
            )

        rules = data["event_rules"]
        evidence: dict[str, Any] = {
            "rules": [
                {
                    "name": r.get("Name"),
                    "state": r.get("State"),
                    "targets": [t.get("Arn") for t in r["Targets"]] if "Targets" in r else None,
                }
                for r in rules
            ]
        }
        if any(r.get("State") == _ENABLED and r.get("Targets") for r in rules):
            return self.region_finding(
                snapshot, region, Status.PASS, "GuardDuty 결과 알림 규칙 설정됨", evidence
            )
        if any(r.get("State") == _ENABLED and "Targets" not in r for r in rules):
            evidence["errors"] = region_errors(snapshot, region, ("event_rules",))
            return self.region_finding(
                snapshot, region, Status.ERROR, "알림 규칙의 대상을 수집하지 못함", evidence
            )
        return self.region_finding(
            snapshot, region, Status.FAIL, "GuardDuty 결과를 보내는 활성 알림 규칙이 없음", evidence
        )
