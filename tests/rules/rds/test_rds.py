"""RDS-001~005 룰 테스트. 공통 동작(대상 선정·오류)과 룰별 판정."""

from typing import Any

import pytest

from kompass.config import RdsSettings, Settings
from kompass.models import Finding, Status
from kompass.rules.base import BaseRule
from kompass.rules.rds.rds_001_storage_encryption import Rds001StorageEncryption
from kompass.rules.rds.rds_002_public_access import Rds002PublicAccess
from kompass.rules.rds.rds_003_log_exports import Rds003LogExports
from kompass.rules.rds.rds_004_backup_retention import Rds004BackupRetention
from kompass.rules.rds.rds_005_ssl_enforcement import Rds005SslEnforcement
from tests.rules.rds.data import REGION, cluster, collect_error, instance, region, snapshot

RDS001 = Rds001StorageEncryption()
RDS002 = Rds002PublicAccess()
RDS003 = Rds003LogExports()
RDS004 = Rds004BackupRetention()
RDS005 = Rds005SslEnforcement()
ALL = (RDS001, RDS002, RDS003, RDS004, RDS005)
CLUSTER_LEVEL = (RDS001, RDS003, RDS004, RDS005)


def _run(
    rule: BaseRule, data: dict[str, Any], settings: Settings | None = None, **kwargs: Any
) -> list[Finding]:
    return rule.evaluate(snapshot({REGION: data}, **kwargs), settings or Settings())


def _one(rule: BaseRule, data: dict[str, Any], settings: Settings | None = None) -> Finding:
    [finding] = _run(rule, data, settings)
    return finding


# --- 공통: 대상·오류 ---


@pytest.mark.parametrize("rule", ALL, ids=lambda r: r.id)
def test_no_databases_is_not_applicable(rule: BaseRule) -> None:
    finding = _one(rule, region())
    assert finding.status == Status.NOT_APPLICABLE and finding.resource == "account"


@pytest.mark.parametrize("rule", ALL, ids=lambda r: r.id)
def test_non_relational_engines_are_excluded(rule: BaseRule) -> None:
    data = region(
        [instance("graph-1", engine="neptune", DBClusterIdentifier="graph")],
        [cluster("graph", engine="neptune"), cluster("docs", engine="docdb")],
    )
    finding = _one(rule, data)
    assert finding.status == Status.NOT_APPLICABLE
    assert finding.evidence["excluded"]


@pytest.mark.parametrize("rule", ALL, ids=lambda r: r.id)
def test_missing_instances_list_is_error(rule: BaseRule) -> None:
    error = collect_error("rds:DescribeDBInstances")
    [finding] = _run(rule, region(missing=("db_instances",)), errors=(error,))
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["error_code"] == "AccessDenied"


@pytest.mark.parametrize("rule", CLUSTER_LEVEL, ids=lambda r: r.id)
def test_missing_clusters_list_is_error_for_cluster_level_rules(rule: BaseRule) -> None:
    error = collect_error("rds:DescribeDBClusters")
    data = region([instance("orders")], missing=("db_clusters",))
    [finding] = _run(rule, data, errors=(error,))
    assert finding.status == Status.ERROR


def test_public_access_does_not_need_clusters_list() -> None:
    finding = _one(RDS002, region([instance("orders")], missing=("db_clusters",)))
    assert finding.status == Status.PASS


@pytest.mark.parametrize("rule", CLUSTER_LEVEL, ids=lambda r: r.id)
def test_cluster_members_are_judged_by_cluster(rule: BaseRule) -> None:
    data = region(
        [instance("ledger-1", engine="aurora-postgresql", DBClusterIdentifier="ledger")],
        [cluster("ledger")],
    )
    finding = _one(rule, data)
    assert finding.resource == "cluster:ledger" and finding.status == Status.PASS
    assert finding.evidence["db_identifier"] == "ledger"


def test_public_access_judges_cluster_members_per_instance() -> None:
    data = region(
        [instance("ledger-1", engine="aurora-postgresql", DBClusterIdentifier="ledger")],
        [cluster("ledger")],
    )
    finding = _one(RDS002, data)
    assert finding.resource == "ledger-1" and finding.evidence["db_cluster"] == "ledger"


# --- RDS-001 스토리지 암호화 ---


def test_rds001_pass_and_fail() -> None:
    data = region(
        [instance("enc"), instance("plain", StorageEncrypted=False)],
        [cluster("aur", StorageEncrypted=False)],
    )
    statuses = {f.resource: f.status for f in _run(RDS001, data)}
    assert statuses == {"enc": Status.PASS, "plain": Status.FAIL, "cluster:aur": Status.FAIL}


def test_rds001_missing_field_is_error() -> None:
    assert _one(RDS001, region([instance("x", StorageEncrypted=None)])).status == Status.ERROR


# --- RDS-002 퍼블릭 접근 ---


def test_rds002_pass_and_fail() -> None:
    data = region([instance("pub", PubliclyAccessible=True), instance("priv")])
    findings = {f.resource: f for f in _run(RDS002, data)}
    assert findings["pub"].status == Status.FAIL and findings["priv"].status == Status.PASS
    assert findings["pub"].evidence["security_groups"] == ["sg-1"]
    assert findings["pub"].evidence["endpoint"].startswith("pub.")


def test_rds002_missing_field_is_error() -> None:
    # 데이터가 없다고 비공개로 보지 않는다 (원칙 3)
    assert _one(RDS002, region([instance("x", PubliclyAccessible=None)])).status == Status.ERROR


# --- RDS-003 로그 내보내기 ---


def test_rds003_pass_with_exports() -> None:
    finding = _one(RDS003, region([instance("x", EnabledCloudwatchLogsExports=["postgresql"])]))
    assert finding.status == Status.PASS and finding.evidence["log_exports"] == ["postgresql"]


@pytest.mark.parametrize("exports", [[], None])
def test_rds003_fail_without_exports(exports: list[str] | None) -> None:
    # 내보내기가 없으면 응답에서 키가 빠진다
    finding = _one(RDS003, region([instance("x", EnabledCloudwatchLogsExports=exports)]))
    assert finding.status == Status.FAIL and finding.evidence["log_exports"] == []


# --- RDS-004 자동 백업 ---


@pytest.mark.parametrize(("days", "status"), [(0, Status.FAIL), (6, Status.FAIL), (7, Status.PASS)])
def test_rds004_retention_threshold(days: int, status: Status) -> None:
    assert _one(RDS004, region([instance("x", BackupRetentionPeriod=days)])).status == status


def test_rds004_threshold_from_settings() -> None:
    settings = Settings(rds=RdsSettings(min_backup_retention_days=1))
    finding = _one(RDS004, region(clusters=[cluster("aur", BackupRetentionPeriod=1)]), settings)
    assert finding.status == Status.PASS and finding.evidence["min_backup_retention_days"] == 1


def test_rds004_read_replica_is_not_applicable() -> None:
    replica = instance("r", BackupRetentionPeriod=0, ReadReplicaSourceDBInstanceIdentifier="src")
    assert _one(RDS004, region([replica])).status == Status.NOT_APPLICABLE


def test_rds004_missing_field_is_error() -> None:
    finding = _one(RDS004, region([instance("x", BackupRetentionPeriod=None)]))
    assert finding.status == Status.ERROR
