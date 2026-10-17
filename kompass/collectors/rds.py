"""RDS collector: DB 인스턴스와 DB 클러스터, SSL 강제 파라미터 (RDS-001~005, ADR-039·051).

수집 데이터 (`Snapshot.data`):
- `regions.<리전>.<종류>`: 리전별 Describe 결과 목록. 종류는 `RESOURCE_KINDS`.
  수집에 실패한 종류는 키가 없다(오류는 `errors`에 리전과 함께 기록). 빈 목록은 "리소스 없음"이다.
- `regions.<리전>.db_parameter_groups`·`db_cluster_parameter_groups`: 인스턴스·클러스터가 쓰는
  파라미터 그룹 이름 → `SSL_PARAMETERS`에 있는 파라미터 이름 → `Parameters` 항목. 그룹에 그
  파라미터가 없으면 이름이 빠진다. 수집에 실패한 그룹은 키가 없다 (오류의 resource=그룹 이름).
  인스턴스·클러스터 목록을 수집하지 못했으면 그 사전도 없다.

점검 리전은 `ScanContext.regions`다 (ADR-021). DocumentDB·Neptune도 같은 API로 조회되지만
걸러 내지 않고 그대로 저장한다. 대상 엔진 판단은 룰이 한다. 파라미터 그룹은 수백 개 파라미터를
가지므로 SSL 강제 판정에 쓰는 것만 남긴다 (`DescribeDBParameters`의 `Filters`는 지원되지 않음).
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
SSL_PARAMETERS = frozenset({"rds.force_ssl", "require_secure_transport"})


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
            if "db_instances" in collected:
                names = {
                    group["DBParameterGroupName"]
                    for item in collected["db_instances"]
                    for group in item.get("DBParameterGroups", [])
                    if group.get("DBParameterGroupName")
                }
                collected["db_parameter_groups"] = _parameters(
                    recorder, client, "describe_db_parameters", "DBParameterGroupName", names
                )
            if "db_clusters" in collected:
                names = {
                    item["DBClusterParameterGroup"]
                    for item in collected["db_clusters"]
                    if item.get("DBClusterParameterGroup")
                }
                collected["db_cluster_parameter_groups"] = _parameters(
                    recorder,
                    client,
                    "describe_db_cluster_parameters",
                    "DBClusterParameterGroupName",
                    names,
                )
            regions[region] = collected

        return Snapshot(
            service=self.service,
            account_id=scan.account_id,
            regions=scan.regions,
            collected_at=collected_at,
            data={"regions": regions},
            errors=tuple(recorder.errors),
        )


def _parameters(
    recorder: CallRecorder, client: Any, method: str, name_param: str, names: set[str]
) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for name in sorted(names):
        items = recorder.paginate(client, method, "Parameters", resource=name, **{name_param: name})
        if items is not None:
            groups[name] = {
                p["ParameterName"]: p for p in items if p["ParameterName"] in SSL_PARAMETERS
            }
    return groups
