"""RDS-005 데이터베이스 SSL 연결 미강제. 공통 동작(대상 선정·리전 오류)은 test_rds.py."""

from typing import Any

import pytest

from kompass.config import Settings
from kompass.models import Finding, Status
from kompass.rules.rds.rds_005_ssl_enforcement import Rds005SslEnforcement
from tests.rules.rds.data import (
    CLUSTER_GROUP,
    FORCE_SSL,
    INSTANCE_GROUP,
    REGION,
    SECURE_TRANSPORT,
    cluster,
    collect_error,
    instance,
    region,
    snapshot,
    ssl_group,
)

RDS005 = Rds005SslEnforcement()


def _run(data: dict[str, Any], **kwargs: Any) -> list[Finding]:
    return RDS005.evaluate(snapshot({REGION: data}, **kwargs), Settings())


def _one(data: dict[str, Any], **kwargs: Any) -> Finding:
    [finding] = _run(data, **kwargs)
    return finding


def _mysql(identifier: str, group: str) -> dict[str, Any]:
    return instance(
        identifier,
        engine="mysql",
        DBParameterGroups=[{"DBParameterGroupName": group, "ParameterApplyStatus": "in-sync"}],
    )


# --- PASS ---


def test_postgres_force_ssl_on_is_pass() -> None:
    finding = _one(region([instance("orders")]))
    assert finding.status == Status.PASS
    assert finding.evidence["parameter_group"] == INSTANCE_GROUP
    assert finding.evidence["parameter"] == FORCE_SSL and finding.evidence["value"] == "1"


@pytest.mark.parametrize("value", ["1", "ON", "on"])
def test_mysql_require_secure_transport_on_is_pass(value: str) -> None:
    data = region(
        [_mysql("shop", "mysql-strict")],
        parameter_groups={"mysql-strict": ssl_group(SECURE_TRANSPORT, value, source="user")},
    )
    assert _one(data).status == Status.PASS


def test_cluster_uses_cluster_parameter_group() -> None:
    # Aurora는 SSL 강제가 클러스터 파라미터 그룹 설정이다. 소속 인스턴스 그룹은 보지 않는다
    data = region(
        [instance("ledger-1", engine="aurora-postgresql", DBClusterIdentifier="ledger")],
        [cluster("ledger")],
        parameter_groups={},
    )
    finding = _one(data)
    assert finding.resource == "cluster:ledger" and finding.status == Status.PASS
    assert finding.evidence["parameter_group"] == CLUSTER_GROUP


def test_sqlserver_uses_force_ssl() -> None:
    data = region(
        [instance("erp", engine="sqlserver-se")],
        parameter_groups={INSTANCE_GROUP: ssl_group(FORCE_SSL, "1")},
    )
    assert _one(data).status == Status.PASS


# --- FAIL ---


@pytest.mark.parametrize("value", ["0", "OFF"])
def test_ssl_off_is_fail(value: str) -> None:
    data = region(
        [_mysql("shop", "mysql-loose")],
        parameter_groups={"mysql-loose": ssl_group(SECURE_TRANSPORT, value, source="user")},
    )
    finding = _one(data)
    assert finding.status == Status.FAIL and finding.evidence["value"] == value


def test_value_missing_means_engine_default_off() -> None:
    # 값이 없는 파라미터는 엔진 기본값(강제 안 함)이다
    data = region(
        [_mysql("shop", "default.mysql8.0")],
        parameter_groups={
            "default.mysql8.0": ssl_group(SECURE_TRANSPORT, None, source="engine-default")
        },
    )
    finding = _one(data)
    assert finding.status == Status.FAIL
    assert finding.evidence["value"] is None and finding.evidence["source"] == "engine-default"


def test_cluster_with_ssl_off_is_fail() -> None:
    data = region(
        clusters=[cluster("ledger", engine="aurora-mysql", DBClusterParameterGroup="aur")],
        cluster_parameter_groups={"aur": ssl_group(SECURE_TRANSPORT, "OFF", source="user")},
    )
    finding = _one(data)
    assert finding.resource == "cluster:ledger" and finding.status == Status.FAIL


# --- ERROR ---


def test_failed_parameter_group_is_error() -> None:
    error = collect_error("rds:DescribeDBParameters", resource=INSTANCE_GROUP)
    finding = _one(region([instance("orders")], parameter_groups={}), errors=(error,))
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["error_code"] == "AccessDenied"


def test_failed_cluster_parameter_group_is_error() -> None:
    error = collect_error("rds:DescribeDBClusterParameters", resource=CLUSTER_GROUP)
    data = region(clusters=[cluster("ledger")], cluster_parameter_groups={})
    finding = _one(data, errors=(error,))
    assert finding.status == Status.ERROR and len(finding.evidence["errors"]) == 1


def test_snapshot_without_parameter_groups_is_error() -> None:
    # 파라미터 그룹을 수집하기 전에 만든 스냅샷
    data = region([instance("orders")])
    del data["db_parameter_groups"]
    assert _one(data).status == Status.ERROR


def test_instance_without_parameter_group_is_error() -> None:
    assert _one(region([instance("orders", DBParameterGroups=[])])).status == Status.ERROR


def test_cluster_without_parameter_group_is_error() -> None:
    data = region(clusters=[cluster("ledger", DBClusterParameterGroup=None)])
    assert _one(data).status == Status.ERROR


def test_parameter_absent_from_group_is_error() -> None:
    data = region([instance("orders")], parameter_groups={INSTANCE_GROUP: {}})
    assert _one(data).status == Status.ERROR


def test_unknown_value_is_error() -> None:
    data = region(
        [instance("orders")], parameter_groups={INSTANCE_GROUP: ssl_group(FORCE_SSL, "maybe")}
    )
    assert _one(data).status == Status.ERROR


# --- REVIEW ---


@pytest.mark.parametrize("engine", ["oracle-ee", "db2-se", "custom-sqlserver-ee"])
def test_engine_without_ssl_parameter_is_review(engine: str) -> None:
    finding = _one(region([instance("legacy", engine=engine)], parameter_groups={}))
    assert finding.status == Status.REVIEW and finding.evidence["engine"] == engine
