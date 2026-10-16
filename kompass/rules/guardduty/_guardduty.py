"""GD-001~002 공통: 리전별 GuardDuty 탐지기 상태 판별 (ADR-041)."""

from enum import Enum
from typing import Any

from kompass.models import Finding, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence

OPERATIONS = {
    "detectors": ("guardduty:ListDetectors", "guardduty:GetDetector"),
    "event_rules": ("events:ListRules", "events:ListTargetsByRule"),
}
_ENABLED = "ENABLED"


class DetectorState(Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"  # 탐지기가 없거나 모두 꺼짐
    UNKNOWN = "unknown"  # 활성 탐지기가 없고 상세를 모르는 탐지기가 있음


def detector_state(detectors: list[dict[str, Any]]) -> DetectorState:
    if any(d.get("Status") == _ENABLED for d in detectors):
        return DetectorState.ENABLED
    if any("Status" not in d for d in detectors):
        return DetectorState.UNKNOWN
    return DetectorState.DISABLED


def detector_evidence(detectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "detector_id": d.get("DetectorId"),
            "status": d.get("Status"),
            "finding_publishing_frequency": d.get("FindingPublishingFrequency"),
            "features": [
                {"name": f.get("Name"), "status": f.get("Status")} for f in d.get("Features", [])
            ],
        }
        for d in detectors
    ]


def region_errors(snapshot: Snapshot, region: str, kinds: tuple[str, ...]) -> list[dict[str, Any]]:
    operations = {op for kind in kinds for op in OPERATIONS[kind]}
    return errors_evidence(
        [e for e in snapshot.errors if e.region == region and e.operation in operations]
    )


class GuardDutyRule(BaseRule):
    service = "guardduty"

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
