"""EC2 collector: 보안그룹과 VPC 네트워크 (SG-001~004, VPC-001~002).

수집 데이터 (`Snapshot.data`):
- `regions.<리전>.<종류>`: 리전별 Describe 결과 목록. 종류는 `RESOURCE_KINDS`.
  수집에 실패한 종류는 키가 없다(오류는 `errors`에 리전과 함께 기록). 빈 목록은 "리소스 없음"이다.

점검 리전은 `ScanContext.regions`다 (ADR-021). 리전 전체가 막혀도(SCP 등) 다른 리전은
계속 수집한다. 보안그룹 규칙이 참조하는 접두사 목록(prefix list)의 내용은 수집하지 않는다.
"""

from datetime import UTC, datetime
from typing import Any

from kompass.aws.session import ScanContext
from kompass.collectors.base import CallRecorder
from kompass.models import Snapshot

# 데이터 키 → (paginate 메서드, 응답 목록 키)
RESOURCE_KINDS: dict[str, tuple[str, str]] = {
    "security_groups": ("describe_security_groups", "SecurityGroups"),
    "vpcs": ("describe_vpcs", "Vpcs"),
    "subnets": ("describe_subnets", "Subnets"),
    "route_tables": ("describe_route_tables", "RouteTables"),
    "network_interfaces": ("describe_network_interfaces", "NetworkInterfaces"),
}


class Ec2Collector:
    service = "ec2"

    def collect(self, scan: ScanContext) -> Snapshot:
        collected_at = datetime.now(UTC)
        recorder = CallRecorder()
        regions: dict[str, dict[str, Any]] = {}
        for region in scan.regions:
            client = scan.session.client("ec2", region_name=region)
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
