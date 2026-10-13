"""CloudTrail collector (CT-001).

수집 데이터 (`Snapshot.data`):
- `trails`: `DescribeTrails(includeShadowTrails=True)`의 `trailList`. 빈 목록은 "추적 없음",
  키가 없으면 수집 실패다.
- `status`: 추적 ARN → `GetTrailStatus` 응답 (`IsLogging`, `LatestDeliveryError` 등)
- `event_selectors`: 추적 ARN → `GetEventSelectors` 응답 (기본 또는 고급 이벤트 선택기)

추적 목록은 기본 리전 한 곳에서만 조회한다. 멀티 리전 추적은 모든 리전에서 섀도 추적으로
보이고, CT-001은 멀티 리전 추적만 보기 때문이다. 다른 리전의 단일 리전 추적은 수집하지 않는다.
상태와 선택기는 추적의 홈 리전에서 ARN으로 조회한다. 섀도 추적은 ARN 지정이 필요하고,
조직 추적도 홈 리전 호출이 가장 확실하다. 추적 하나의 조회가 실패하면 그 추적만 오류로
기록하고(`resource`=추적 ARN) 나머지는 계속 수집한다.
"""

from datetime import UTC, datetime
from typing import Any

from kompass.aws.session import ScanContext
from kompass.collectors.base import CallRecorder
from kompass.models import Snapshot


class CloudTrailCollector:
    service = "cloudtrail"

    def collect(self, scan: ScanContext) -> Snapshot:
        collected_at = datetime.now(UTC)
        recorder = CallRecorder()
        clients: dict[str, Any] = {}

        def client(region: str) -> Any:
            if region not in clients:
                clients[region] = scan.session.client("cloudtrail", region_name=region)
            return clients[region]

        data: dict[str, Any] = {}
        described = recorder.call(
            client(scan.home_region), "describe_trails", includeShadowTrails=True
        )
        if isinstance(described, dict):
            trails: list[dict[str, Any]] = described.get("trailList", [])
            status: dict[str, Any] = {}
            selectors: dict[str, Any] = {}
            for trail in trails:
                arn = trail["TrailARN"]
                home = client(trail.get("HomeRegion", scan.home_region))
                trail_status = recorder.call(home, "get_trail_status", resource=arn, Name=arn)
                if isinstance(trail_status, dict):
                    status[arn] = trail_status
                trail_selectors = recorder.call(
                    home, "get_event_selectors", resource=arn, TrailName=arn
                )
                if isinstance(trail_selectors, dict):
                    selectors[arn] = trail_selectors
            data = {"trails": trails, "status": status, "event_selectors": selectors}

        return Snapshot(
            service=self.service,
            account_id=scan.account_id,
            regions=tuple(sorted(clients)),
            collected_at=collected_at,
            data=data,
            errors=tuple(recorder.errors),
        )
