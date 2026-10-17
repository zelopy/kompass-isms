"""RDS-006 데이터베이스 스냅샷 공개."""

from typing import Any

from kompass.config import Settings
from kompass.models import Finding, Status
from kompass.rules.base import ACCOUNT_RESOURCE
from kompass.rules.rds.rds_006_public_snapshot import Rds006PublicSnapshot
from tests.rules.rds.data import (
    REGION,
    cluster_snapshot,
    collect_error,
    db_snapshot,
    region,
    restore,
    snapshot,
)

RDS006 = Rds006PublicSnapshot()
OTHER_ACCOUNT = "210987654321"


def _run(data: dict[str, Any], **kwargs: Any) -> list[Finding]:
    return RDS006.evaluate(snapshot({REGION: data}, **kwargs), Settings())


def _one(data: dict[str, Any], **kwargs: Any) -> Finding:
    [finding] = _run(data, **kwargs)
    return finding


# --- PASS ---


def test_unshared_snapshot_is_pass() -> None:
    finding = _one(region(snapshots=[db_snapshot("orders-before-migration")]))
    assert finding.status == Status.PASS
    assert finding.resource == "orders-before-migration" and finding.region == REGION
    assert finding.evidence["snapshot"] == "orders-before-migration"
    assert finding.evidence["db_identifier"] == "orders"
    assert finding.evidence["encrypted"] is True
    assert finding.evidence["shared_accounts"] == []


def test_snapshot_shared_with_specific_account_is_pass() -> None:
    # 특정 계정 공유는 공개가 아니다. 조직 안의 계정인지는 룰이 알 수 없으므로 evidence에 남긴다
    data = region(
        snapshots=[db_snapshot("orders-copy")],
        snapshot_attributes={"orders-copy": restore(OTHER_ACCOUNT)},
    )
    finding = _one(data)
    assert finding.status == Status.PASS
    assert finding.evidence["shared_accounts"] == [OTHER_ACCOUNT]


def test_cluster_snapshot_uses_prefixed_resource() -> None:
    finding = _one(region(cluster_snapshots=[cluster_snapshot("ledger-final")]))
    assert finding.status == Status.PASS
    assert finding.resource == "cluster-snapshot:ledger-final"
    assert finding.evidence["kind"] == "cluster_snapshot"
    assert finding.evidence["db_cluster"] == "ledger"


# --- FAIL ---


def test_public_snapshot_is_fail() -> None:
    data = region(
        snapshots=[db_snapshot("orders-public", Encrypted=False)],
        snapshot_attributes={"orders-public": restore("all")},
    )
    finding = _one(data)
    assert finding.status == Status.FAIL
    assert finding.evidence["public"] is True and finding.evidence["encrypted"] is False


def test_public_cluster_snapshot_is_fail() -> None:
    data = region(
        cluster_snapshots=[cluster_snapshot("ledger-public", StorageEncrypted=False)],
        cluster_snapshot_attributes={"ledger-public": restore("all", OTHER_ACCOUNT)},
    )
    finding = _one(data)
    assert finding.status == Status.FAIL
    assert finding.evidence["shared_accounts"] == [OTHER_ACCOUNT]


def test_each_snapshot_is_judged() -> None:
    data = region(
        snapshots=[db_snapshot("a"), db_snapshot("b")],
        cluster_snapshots=[cluster_snapshot("c")],
        snapshot_attributes={"a": restore(), "b": restore("all")},
    )
    statuses = {f.resource: f.status for f in _run(data)}
    assert statuses == {
        "a": Status.PASS,
        "b": Status.FAIL,
        "cluster-snapshot:c": Status.PASS,
    }


# --- ERROR ---


def test_snapshot_list_failure_is_region_error() -> None:
    error = collect_error("rds:DescribeDBSnapshots")
    finding = _one(region(missing=("db_snapshots",)), errors=(error,))
    assert finding.status == Status.ERROR and finding.resource == ACCOUNT_RESOURCE
    assert [e["operation"] for e in finding.evidence["errors"]] == ["rds:DescribeDBSnapshots"]


def test_cluster_snapshot_list_failure_is_region_error() -> None:
    data = region(snapshots=[db_snapshot("a")], missing=("db_cluster_snapshots",))
    finding = _one(data, errors=(collect_error("rds:DescribeDBClusterSnapshots"),))
    assert finding.status == Status.ERROR and finding.resource == ACCOUNT_RESOURCE


def test_attribute_failure_is_snapshot_error() -> None:
    error = collect_error("rds:DescribeDBSnapshotAttributes", resource="orders-copy")
    data = region(snapshots=[db_snapshot("orders-copy")], snapshot_attributes={})
    finding = _one(data, errors=(error,))
    assert finding.status == Status.ERROR and finding.resource == "orders-copy"
    assert finding.evidence["errors"][0]["resource"] == "orders-copy"


def test_cluster_attribute_failure_is_snapshot_error() -> None:
    error = collect_error("rds:DescribeDBClusterSnapshotAttributes", resource="ledger-final")
    data = region(
        cluster_snapshots=[cluster_snapshot("ledger-final")], cluster_snapshot_attributes={}
    )
    finding = _one(data, errors=(error,))
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["operation"] == "rds:DescribeDBClusterSnapshotAttributes"


def test_missing_restore_attribute_is_error() -> None:
    # 공유 속성 응답에 restore가 없으면 공유 여부를 알 수 없다. 데이터가 없다고 PASS로 보지 않는다
    data = region(snapshots=[db_snapshot("orders-copy")], snapshot_attributes={"orders-copy": []})
    assert _one(data).status == Status.ERROR


# --- 해당 없음·대상 제외 ---


def test_no_snapshots_is_not_applicable() -> None:
    finding = _one(region())
    assert finding.status == Status.NOT_APPLICABLE and finding.resource == ACCOUNT_RESOURCE


def test_non_relational_snapshots_are_excluded() -> None:
    data = region(
        cluster_snapshots=[
            cluster_snapshot("docs-final", source="docs", engine="docdb"),
            cluster_snapshot("graph-final", source="graph", engine="neptune"),
        ],
    )
    finding = _one(data)
    assert finding.status == Status.NOT_APPLICABLE
    assert finding.evidence["excluded"] == [
        "cluster-snapshot:docs-final",
        "cluster-snapshot:graph-final",
    ]


def test_snapshots_do_not_need_database_lists() -> None:
    # 원본 데이터베이스를 지운 뒤 남은 스냅샷도 판정한다. 인스턴스 목록 실패와는 무관하다
    data = region(snapshots=[db_snapshot("orders-final")], missing=("db_instances", "db_clusters"))
    assert _one(data).status == Status.PASS
