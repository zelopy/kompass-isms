"""GuardDuty collector: 탐지기와 GuardDuty 결과용 EventBridge 규칙 (GD-001~002, ADR-041).

수집 데이터 (`Snapshot.data`):
- `regions.<리전>.detectors`: 탐지기 목록. `GetDetector` 응답에 `DetectorId`를 더한 것이며,
  상세 조회에 실패한 탐지기는 `{"DetectorId": ...}`만 남는다 (오류는 `errors`, resource=탐지기 ID).
- `regions.<리전>.event_rules`: 기본 이벤트 버스의 규칙 중 이벤트 패턴의 `source`에
  `aws.guardduty`가 있는 것. 규칙마다 `Targets`(`ListTargetsByRule` 결과)를 더하며, 대상 조회에
  실패한 규칙은 `Targets` 키가 없다 (오류의 resource=규칙 이름).
목록 조회에 실패한 종류는 키가 없다. GuardDuty 알림 경로는 EventBridge에 있지만 룰은 스냅샷
하나만 보므로(ADR-015) 같은 스냅샷에 담는다.
"""

import json
from datetime import UTC, datetime
from typing import Any

from kompass.aws.session import ScanContext
from kompass.collectors.base import CallRecorder
from kompass.models import Snapshot

GUARDDUTY_SOURCE = "aws.guardduty"


def is_guardduty_rule(rule: dict[str, Any]) -> bool:
    """이벤트 패턴의 source에 aws.guardduty가 있는가. 패턴이 없거나 해석할 수 없으면 False."""
    try:
        pattern = json.loads(rule.get("EventPattern") or "{}")
    except json.JSONDecodeError:
        return False
    source = pattern.get("source") if isinstance(pattern, dict) else None
    return isinstance(source, list) and GUARDDUTY_SOURCE in source


class GuardDutyCollector:
    service = "guardduty"

    def collect(self, scan: ScanContext) -> Snapshot:
        collected_at = datetime.now(UTC)
        recorder = CallRecorder()
        regions: dict[str, dict[str, Any]] = {}
        for region in scan.regions:
            collected: dict[str, Any] = {}
            guardduty = scan.session.client("guardduty", region_name=region)
            detector_ids = recorder.paginate(guardduty, "list_detectors", "DetectorIds")
            if detector_ids is not None:
                collected["detectors"] = [
                    self._detector(recorder, guardduty, detector_id) for detector_id in detector_ids
                ]
            events = scan.session.client("events", region_name=region)
            rules = recorder.paginate(events, "list_rules", "Rules")
            if rules is not None:
                collected["event_rules"] = [
                    self._rule(recorder, events, rule) for rule in rules if is_guardduty_rule(rule)
                ]
            regions[region] = collected

        return Snapshot(
            service=self.service,
            account_id=scan.account_id,
            regions=scan.regions,
            collected_at=collected_at,
            data={"regions": regions},
            errors=tuple(recorder.errors),
        )

    @staticmethod
    def _detector(recorder: CallRecorder, client: Any, detector_id: str) -> dict[str, Any]:
        detail = recorder.call(client, "get_detector", resource=detector_id, DetectorId=detector_id)
        if not isinstance(detail, dict):
            return {"DetectorId": detector_id}
        return {"DetectorId": detector_id, **detail}

    @staticmethod
    def _rule(recorder: CallRecorder, client: Any, rule: dict[str, Any]) -> dict[str, Any]:
        name = rule["Name"]
        targets = recorder.paginate(
            client, "list_targets_by_rule", "Targets", resource=name, Rule=name
        )
        return rule if targets is None else {**rule, "Targets": targets}
