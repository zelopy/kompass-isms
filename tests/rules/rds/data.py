"""RDS 룰 테스트용 가짜 데이터. `DescribeDBInstances`·`DescribeDBClusters` 응답 형태를 따른다.

파라미터 그룹은 collector가 저장하는 형태(그룹 이름 → SSL 파라미터 이름 → 파라미터)를 따른다.
스냅샷은 `DescribeDBSnapshots`·`DescribeDBClusterSnapshots` 응답 형태, 공유 속성은 collector가
저장하는 형태(스냅샷 식별자 → `DBSnapshotAttributes`·`DBClusterSnapshotAttributes` 목록)를 따른다.

- 로그 내보내기가 없으면 `EnabledCloudwatchLogsExports` 키가 생략된다
  (실습 계정에서 확인, 2026-10-16)
"""

from datetime import UTC, datetime
from typing import Any

from kompass.models import CollectError, Snapshot

T0 = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
INSTANCE_GROUP = "default.postgres17"
CLUSTER_GROUP = "default.aurora-postgresql17"
FORCE_SSL = "rds.force_ssl"
SECURE_TRANSPORT = "require_secure_transport"


def instance(identifier: str, engine: str = "postgres", **fields: Any) -> dict[str, Any]:
    """값을 None으로 주면 그 키를 뺀다."""
    item: dict[str, Any] = {
        "DBInstanceIdentifier": identifier,
        "Engine": engine,
        "DBInstanceStatus": "available",
        "PubliclyAccessible": False,
        "StorageEncrypted": True,
        "BackupRetentionPeriod": 7,
        "EnabledCloudwatchLogsExports": ["postgresql"],
        "Endpoint": {"Address": f"{identifier}.abc123.{REGION}.rds.amazonaws.com", "Port": 5432},
        "DBSubnetGroup": {"DBSubnetGroupName": "db-subnets", "VpcId": "vpc-1"},
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1", "Status": "active"}],
        "DBParameterGroups": [
            {"DBParameterGroupName": INSTANCE_GROUP, "ParameterApplyStatus": "in-sync"}
        ],
    }
    item.update(fields)
    return {k: v for k, v in item.items() if v is not None}


def cluster(identifier: str, engine: str = "aurora-postgresql", **fields: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "DBClusterIdentifier": identifier,
        "Engine": engine,
        "Status": "available",
        "StorageEncrypted": True,
        "BackupRetentionPeriod": 7,
        "EnabledCloudwatchLogsExports": ["postgresql"],
        "DBClusterMembers": [],
        "DBClusterParameterGroup": CLUSTER_GROUP,
    }
    item.update(fields)
    return {k: v for k, v in item.items() if v is not None}


def parameter(name: str, value: str | None, source: str = "system") -> dict[str, Any]:
    """`DescribeDBParameters` 응답의 파라미터 하나. 값이 None이면 `ParameterValue`를 뺀다."""
    item: dict[str, Any] = {
        "ParameterName": name,
        "ParameterValue": value,
        "Source": source,
        "ApplyType": "dynamic",
        "DataType": "boolean",
    }
    return {k: v for k, v in item.items() if v is not None}


def ssl_group(name: str, value: str | None, source: str = "system") -> dict[str, Any]:
    return {name: parameter(name, value, source)}


def db_snapshot(
    identifier: str, source: str = "orders", engine: str = "postgres", **fields: Any
) -> dict[str, Any]:
    """수동 인스턴스 스냅샷. 값을 None으로 주면 그 키를 뺀다."""
    item: dict[str, Any] = {
        "DBSnapshotIdentifier": identifier,
        "DBInstanceIdentifier": source,
        "Engine": engine,
        "SnapshotType": "manual",
        "Status": "available",
        "Encrypted": True,
        "SnapshotCreateTime": "2026-10-15T03:00:00+00:00",
    }
    item.update(fields)
    return {k: v for k, v in item.items() if v is not None}


def cluster_snapshot(
    identifier: str, source: str = "ledger", engine: str = "aurora-postgresql", **fields: Any
) -> dict[str, Any]:
    """수동 클러스터 스냅샷. 값을 None으로 주면 그 키를 뺀다."""
    item: dict[str, Any] = {
        "DBClusterSnapshotIdentifier": identifier,
        "DBClusterIdentifier": source,
        "Engine": engine,
        "SnapshotType": "manual",
        "Status": "available",
        "StorageEncrypted": True,
        "SnapshotCreateTime": "2026-10-15T03:00:00+00:00",
    }
    item.update(fields)
    return {k: v for k, v in item.items() if v is not None}


def restore(*values: str) -> list[dict[str, Any]]:
    """스냅샷 공유 속성. 값이 없으면 공유하지 않음, `all`이면 공개."""
    return [{"AttributeName": "restore", "AttributeValues": list(values)}]


def region(
    instances: list[dict[str, Any]] | None = None,
    clusters: list[dict[str, Any]] | None = None,
    missing: tuple[str, ...] = (),
    parameter_groups: dict[str, dict[str, Any]] | None = None,
    cluster_parameter_groups: dict[str, dict[str, Any]] | None = None,
    snapshots: list[dict[str, Any]] | None = None,
    cluster_snapshots: list[dict[str, Any]] | None = None,
    snapshot_attributes: dict[str, list[dict[str, Any]]] | None = None,
    cluster_snapshot_attributes: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """파라미터 그룹을 주지 않으면 기본 그룹(SSL 강제 켬)을 넣는다.

    스냅샷 공유 속성을 주지 않으면 모든 스냅샷을 공유하지 않은 것으로 넣는다.
    """
    snapshots = snapshots or []
    cluster_snapshots = cluster_snapshots or []
    data: dict[str, Any] = {
        "db_instances": instances or [],
        "db_clusters": clusters or [],
        "db_parameter_groups": (
            {INSTANCE_GROUP: ssl_group(FORCE_SSL, "1")}
            if parameter_groups is None
            else parameter_groups
        ),
        "db_cluster_parameter_groups": (
            {CLUSTER_GROUP: ssl_group(FORCE_SSL, "1")}
            if cluster_parameter_groups is None
            else cluster_parameter_groups
        ),
        "db_snapshots": snapshots,
        "db_cluster_snapshots": cluster_snapshots,
        "db_snapshot_attributes": (
            {s["DBSnapshotIdentifier"]: restore() for s in snapshots}
            if snapshot_attributes is None
            else snapshot_attributes
        ),
        "db_cluster_snapshot_attributes": (
            {s["DBClusterSnapshotIdentifier"]: restore() for s in cluster_snapshots}
            if cluster_snapshot_attributes is None
            else cluster_snapshot_attributes
        ),
    }
    for kind in missing:
        del data[kind]
    return data


def snapshot(regions: dict[str, dict[str, Any]], errors: tuple[CollectError, ...] = ()) -> Snapshot:
    return Snapshot(
        service="rds",
        account_id=ACCOUNT,
        regions=tuple(regions),
        collected_at=T0,
        data={"regions": regions},
        errors=errors,
    )


def collect_error(
    operation: str, region_name: str = REGION, resource: str | None = None
) -> CollectError:
    return CollectError(
        operation=operation,
        region=region_name,
        error_code="AccessDenied",
        message="no",
        resource=resource,
    )
