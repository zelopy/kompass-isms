"""RDS collector: DB 인스턴스와 DB 클러스터 (RDS-001~004, ADR-039).

수집 데이터 (`Snapshot.data`):
- `regions.<리전>.<종류>`: 리전별 Describe 결과 목록. 종류는 `RESOURCE_KINDS`.
  수집에 실패한 종류는 키가 없다(오류는 `errors`에 리전과 함께 기록). 빈 목록은 "리소스 없음"이다.

점검 리전은 `ScanContext.regions`다 (ADR-021). DocumentDB·Neptune도 같은 API로 조회되지만
걸러 내지 않고 그대로 저장한다. 대상 엔진 판단은 룰이 한다.
"""

from datetime import UTC, datetime
from typing import Any

from kompass.aws.session import ScanContext
from kompass.collectors.base import CallRecorder
from kompass.models import Snapshot

# 데이터 키 → (paginate 메서드, 응답 목록 키)
RESOURCE_KINDS: dict[str, tuple[str, str]] = {
    "db_instances": ("describe_db_instances", "DBInstances"),
    "db_clusters": ("describe_db_clusters", "DBClusters"),
}


class RdsCollector:
    service = "rds"

    def collect(self, scan: ScanContext) -> Snapshot:
        collected_at = datetime.now(UTC)
        recorder = CallRecorder()
        regions: dict[str, dict[str, Any]] = {}
        for region in scan.regions:
            client = scan.session.client("rds", region_name=region)
            collected: dict[str, Any] = {}
            for kind, (method, result_key) in RESOURCE_KINDS.items():
                items = recorder.paginate(client, method, result_key)
                if items is not None:
                    collected[kind] = items
            regions[region] = collected

        return Snapshot(
            service=self.service,
            account_id=scan.account_id,
            regions=scan.regions,
            collected_at=collected_at,
            data={"regions": regions},
            errors=tuple(recorder.errors),
        )
