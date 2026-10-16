"""GD-001 GuardDuty 미활성화 (KISA CA-19, docs/RULES.md)."""

from typing import ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.guardduty._guardduty import (
    DetectorState,
    GuardDutyRule,
    detector_evidence,
    detector_state,
    region_errors,
)


class Gd001DetectorEnabled(GuardDutyRule):
    id: ClassVar[str] = "GD-001"
    title: ClassVar[str] = "GuardDuty 미활성화"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        for region, data in snapshot.data.get("regions", {}).items():
            detectors = data.get("detectors")
            if detectors is None:
                findings.append(
                    self.region_finding(
                        snapshot,
                        region,
                        Status.ERROR,
                        "GuardDuty 탐지기 목록을 수집하지 못함",
                        {"errors": region_errors(snapshot, region, ("detectors",))},
                    )
                )
                continue
            evidence = {"detectors": detector_evidence(detectors)}
            state = detector_state(detectors)
            if state == DetectorState.ENABLED:
                status, message = Status.PASS, "GuardDuty 활성화됨"
            elif state == DetectorState.UNKNOWN:
                status, message = Status.ERROR, "GuardDuty 탐지기 상태를 수집하지 못함"
                evidence["errors"] = region_errors(snapshot, region, ("detectors",))
            elif detectors:
                status, message = Status.FAIL, "GuardDuty 탐지기가 비활성화됨"
            else:
                status, message = Status.FAIL, "GuardDuty 탐지기가 없음"
            findings.append(self.region_finding(snapshot, region, status, message, evidence))
        return findings
