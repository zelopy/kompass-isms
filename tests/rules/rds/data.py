"""RDS 룰 테스트용 가짜 데이터. `DescribeDBInstances`·`DescribeDBClusters` 응답 형태를 따른다.

- 로그 내보내기가 없으면 `EnabledCloudwatchLogsExports` 키가 생략된다 (실습 계정 확인 대상)
"""

from datetime import UTC, datetime
from typing import Any

from kompass.models import CollectError, Snapshot

T0 = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"


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
    }
    item.update(fields)
    return {k: v for k, v in item.items() if v is not None}


def region(
    instances: list[dict[str, Any]] | None = None,
    clusters: list[dict[str, Any]] | None = None,
    missing: tuple[str, ...] = (),
) -> dict[str, Any]:
    data = {"db_instances": instances or [], "db_clusters": clusters or []}
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


def collect_error(operation: str, region_name: str = REGION) -> CollectError:
    return CollectError(
        operation=operation, region=region_name, error_code="AccessDenied", message="no"
    )
