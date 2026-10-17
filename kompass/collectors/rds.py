"""RDS collector: DB 인스턴스와 DB 클러스터, SSL 강제 파라미터, 수동 스냅샷 공유 속성
(RDS-001~006, ADR-039·051·053).

수집 데이터 (`Snapshot.data`):
- `regions.<리전>.<종류>`: 리전별 Describe 결과 목록. 종류는 `RESOURCE_KINDS`.
  수집에 실패한 종류는 키가 없다(오류는 `errors`에 리전과 함께 기록). 빈 목록은 "리소스 없음"이다.
- `regions.<리전>.db_parameter_groups`·`db_cluster_parameter_groups`: 인스턴스·클러스터가 쓰는
  파라미터 그룹 이름 → `SSL_PARAMETERS`에 있는 파라미터 이름 → `Parameters` 항목. 그룹에 그
  파라미터가 없으면 이름이 빠진다. 수집에 실패한 그룹은 키가 없다 (오류의 resource=그룹 이름).
  인스턴스·클러스터 목록을 수집하지 못했으면 그 사전도 없다.
- `regions.<리전>.db_snapshots`·`db_cluster_snapshots`: 계정이 소유한 수동 스냅샷 목록
  (`SnapshotType=manual`). 자동 스냅샷은 공유할 수 없고, 다른 계정이 공유한 스냅샷은 기본값으로
  조회되지 않는다. 수집에 실패한 종류는 키가 없다.
- `regions.<리전>.db_snapshot_attributes`·`db_cluster_snapshot_attributes`: 스냅샷 식별자 →
  공유 속성 목록(`DBSnapshotAttributes`·`DBClusterSnapshotAttributes`). 수집에 실패한 스냅샷은
  키가 없다 (오류의 resource=스냅샷 식별자). 스냅샷 목록을 수집하지 못했으면 그 사전도 없다.

점검 리전은 `ScanContext.regions`다 (ADR-021). DocumentDB·Neptune도 같은 API로 조회되지만
걸러 내지 않고 그대로 저장한다. 대상 엔진 판단은 룰이 한다. 파라미터 그룹은 수백 개 파라미터를
가지므로 SSL 강제 판정에 쓰는 것만 남긴다 (`DescribeDBParameters`의 `Filters`는 지원되지 않음).
"""

from datetime import UTC, datetime
from typing import Any, NamedTuple

from kompass.aws.session import ScanContext
from kompass.collectors.base import CallRecorder
from kompass.models import Snapshot

# 데이터 키 → (paginate 메서드, 응답 목록 키)
RESOURCE_KINDS: dict[str, tuple[str, str]] = {
    "db_instances": ("describe_db_instances", "DBInstances"),
    "db_clusters": ("describe_db_clusters", "DBClusters"),
}
SSL_PARAMETERS = frozenset({"rds.force_ssl", "require_secure_transport"})


class SnapshotKind(NamedTuple):
    """수동 스냅샷 종류 하나의 목록·공유 속성 조회 방법."""

    method: str  # 목록 paginate 메서드
    result_key: str
    id_field: str
    attributes_key: str  # 공유 속성 데이터 키
    attributes_method: str
    attributes_result_key: str
    attributes_list_key: str


# 스냅샷 데이터 키 → 조회 방법
SNAPSHOT_KINDS: dict[str, SnapshotKind] = {
    "db_snapshots": SnapshotKind(
        "describe_db_snapshots",
        "DBSnapshots",
        "DBSnapshotIdentifier",
        "db_snapshot_attributes",
        "describe_db_snapshot_attributes",
        "DBSnapshotAttributesResult",
        "DBSnapshotAttributes",
    ),
    "db_cluster_snapshots": SnapshotKind(
        "describe_db_cluster_snapshots",
        "DBClusterSnapshots",
        "DBClusterSnapshotIdentifier",
        "db_cluster_snapshot_attributes",
        "describe_db_cluster_snapshot_attributes",
        "DBClusterSnapshotAttributesResult",
        "DBClusterSnapshotAttributes",
    ),
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
            for kind, spec in SNAPSHOT_KINDS.items():
                snapshots = recorder.paginate(
                    client, spec.method, spec.result_key, SnapshotType="manual"
                )
                if snapshots is not None:
                    collected[kind] = snapshots
                    collected[spec.attributes_key] = _snapshot_attributes(
                        recorder, client, spec, [item[spec.id_field] for item in snapshots]
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


def _snapshot_attributes(
    recorder: CallRecorder, client: Any, spec: SnapshotKind, identifiers: list[str]
) -> dict[str, list[Any]]:
    attributes: dict[str, list[Any]] = {}
    for identifier in identifiers:
        response = recorder.call(
            client, spec.attributes_method, resource=identifier, **{spec.id_field: identifier}
        )
        if isinstance(response, dict):
            result = response.get(spec.attributes_result_key, {})
            attributes[identifier] = result.get(spec.attributes_list_key, [])
    return attributes
