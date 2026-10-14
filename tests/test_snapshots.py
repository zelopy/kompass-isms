"""스냅샷 저장·로드 테스트."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from kompass.aws.session import ScanContext
from kompass.models import CollectError, Snapshot
from kompass.snapshots import (
    STORE_ENV,
    IncompleteScanError,
    SnapshotIntegrityError,
    SnapshotStore,
    default_store_root,
    load_scan,
)

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
T0 = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)


def _scan(account_id: str = ACCOUNT) -> ScanContext:
    return ScanContext(
        session=None,
        account_id=account_id,
        partition="aws",
        caller_arn=f"arn:aws:iam::{account_id}:user/security_manager",
        home_region="ap-northeast-2",
        regions=("ap-northeast-2",),
    )


def _snapshot(service: str = "cloudtrail", account_id: str = ACCOUNT, **data: Any) -> Snapshot:
    return Snapshot(
        service=service,
        account_id=account_id,
        regions=("ap-northeast-2",),
        collected_at=T0,
        data=data or {"trails": [{"Name": "t", "CreateDate": T0}]},
        errors=(
            CollectError(
                operation="cloudtrail:GetTrailStatus",
                region="ap-northeast-2",
                error_code="AccessDenied",
                message="권한 없음",
                resource="arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/t",
            ),
        ),
    )


@pytest.fixture
def store(tmp_path: Path) -> SnapshotStore:
    return SnapshotStore(tmp_path / ".kompass")


def _write_scan(store: SnapshotStore, *snapshots: Snapshot, started_at: datetime = T0) -> Path:
    writer = store.begin(_scan(snapshots[0].account_id if snapshots else ACCOUNT), started_at)
    for snapshot in snapshots:
        writer.write(snapshot)
    return writer.finish()


# --- 저장·로드 왕복 ---


def test_round_trip(store: SnapshotStore) -> None:
    original = _snapshot()
    manifest, snapshots = load_scan(_write_scan(store, original))
    assert snapshots == {"cloudtrail": original}
    assert manifest.account_id == ACCOUNT
    assert manifest.caller_arn.endswith("user/security_manager")
    assert manifest.regions == ("ap-northeast-2",)
    assert manifest.started_at == T0
    assert manifest.format_version == 1
    assert set(manifest.snapshots) == {"cloudtrail"}


def test_layout_includes_account_and_scan_id(store: SnapshotStore) -> None:
    path = _write_scan(store, _snapshot())
    assert path.parent == store.root / "snapshots" / ACCOUNT
    assert path.name.startswith("20261013T120000Z-")
    assert sorted(p.name for p in path.iterdir()) == ["cloudtrail.json", "scan.json"]


def test_files_are_utf8(store: SnapshotStore) -> None:
    path = _write_scan(store, _snapshot())
    assert "권한 없음" in (path / "cloudtrail.json").read_text(encoding="utf-8")


def test_root_gets_gitignore(store: SnapshotStore) -> None:
    # 저장소 밖에서 실행해도 실제 계정 데이터가 커밋되지 않게 한다 (원칙 4)
    _write_scan(store, _snapshot())
    assert (store.root / ".gitignore").read_text(encoding="utf-8").strip() == "*"


def test_existing_gitignore_is_kept(store: SnapshotStore) -> None:
    store.root.mkdir(parents=True)
    (store.root / ".gitignore").write_text("custom\n", encoding="utf-8")
    _write_scan(store, _snapshot())
    assert (store.root / ".gitignore").read_text(encoding="utf-8") == "custom\n"


def test_same_second_scans_do_not_collide(store: SnapshotStore) -> None:
    first = _write_scan(store, _snapshot())
    second = _write_scan(store, _snapshot())
    assert first != second
    assert load_scan(first)[1] == load_scan(second)[1]


def test_no_temp_files_left(store: SnapshotStore) -> None:
    path = _write_scan(store, _snapshot())
    assert not list(path.glob("*.tmp"))


# --- 쓰기 규칙 ---


def test_duplicate_service_rejected(store: SnapshotStore) -> None:
    writer = store.begin(_scan(), T0)
    writer.write(_snapshot())
    with pytest.raises(ValueError, match="cloudtrail"):
        writer.write(_snapshot())


def test_other_account_snapshot_rejected(store: SnapshotStore) -> None:
    writer = store.begin(_scan(), T0)
    with pytest.raises(ValueError, match=OTHER_ACCOUNT):
        writer.write(_snapshot(account_id=OTHER_ACCOUNT))


def test_write_after_finish_rejected(store: SnapshotStore) -> None:
    writer = store.begin(_scan(), T0)
    writer.write(_snapshot())
    writer.finish()
    with pytest.raises(RuntimeError):
        writer.write(_snapshot(service="iam"))


@pytest.mark.parametrize("service", ["../evil", "a/b", "", "Cloud Trail"])
def test_unsafe_service_name_rejected(store: SnapshotStore, service: str) -> None:
    writer = store.begin(_scan(), T0)
    with pytest.raises(ValueError):
        writer.write(_snapshot(service=service))


# --- 미완료·손상 감지 ---


def test_unfinished_scan_cannot_be_loaded(store: SnapshotStore) -> None:
    writer = store.begin(_scan(), T0)
    writer.write(_snapshot())
    with pytest.raises(IncompleteScanError):
        load_scan(writer.path)


def test_modified_snapshot_detected(store: SnapshotStore) -> None:
    path = _write_scan(store, _snapshot())
    file = path / "cloudtrail.json"
    tampered = json.loads(file.read_text(encoding="utf-8"))
    tampered["data"]["trails"][0]["Name"] = "changed"
    file.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(SnapshotIntegrityError, match="cloudtrail"):
        load_scan(path)


def test_missing_snapshot_file_detected(store: SnapshotStore) -> None:
    path = _write_scan(store, _snapshot())
    (path / "cloudtrail.json").unlink()
    with pytest.raises(SnapshotIntegrityError, match="cloudtrail"):
        load_scan(path)


def test_unknown_format_version_rejected(store: SnapshotStore) -> None:
    path = _write_scan(store, _snapshot())
    manifest = json.loads((path / "scan.json").read_text(encoding="utf-8"))
    manifest["format_version"] = 99
    (path / "scan.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        load_scan(path)


# --- 최신 점검 찾기 ---


def test_latest_scan_picks_newest_complete(store: SnapshotStore) -> None:
    _write_scan(store, _snapshot(), started_at=T0)
    newest = _write_scan(store, _snapshot(), started_at=datetime(2026, 10, 14, tzinfo=UTC))
    unfinished = store.begin(_scan(), datetime(2026, 10, 15, tzinfo=UTC))
    unfinished.write(_snapshot())
    assert store.latest_scan() == newest


def test_latest_scan_requires_account_when_ambiguous(store: SnapshotStore) -> None:
    _write_scan(store, _snapshot())
    _write_scan(store, _snapshot(account_id=OTHER_ACCOUNT))
    with pytest.raises(ValueError, match="계정"):
        store.latest_scan()
    other = store.latest_scan(OTHER_ACCOUNT)
    assert other is not None
    assert other.parent.name == OTHER_ACCOUNT


def test_latest_scan_none_when_empty(store: SnapshotStore) -> None:
    assert store.latest_scan() is None
    assert store.latest_scan(ACCOUNT) is None


# --- 기본 저장 위치 (ADR-027) ---


def _project(tmp_path: Path, name: str = "kompass-isms") -> Path:
    root = tmp_path / "repo"
    (root / "lab").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        "\n".join(["[project]", f'name = "{name}"', ""]), encoding="utf-8"
    )
    return root


def test_default_root_is_project_reports_from_subfolder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # lab/ 같은 하위 폴더에서 실행해도 저장소 최상위의 reports/에 모인다
    monkeypatch.delenv(STORE_ENV, raising=False)
    root = _project(tmp_path)
    assert default_store_root(root / "lab") == (root / "reports").resolve()
    assert default_store_root(root) == (root / "reports").resolve()


def test_default_root_ignores_other_projects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(STORE_ENV, raising=False)
    root = _project(tmp_path, name="something-else")
    assert default_store_root(root / "lab") == (root / "lab" / "reports").resolve()


def test_default_root_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(STORE_ENV, str(tmp_path / "custom"))
    assert default_store_root(_project(tmp_path)) == tmp_path / "custom"


def test_store_without_root_uses_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(STORE_ENV, str(tmp_path / "custom"))
    assert SnapshotStore().root == tmp_path / "custom"


def test_manifest_records_excluded_regions(store: SnapshotStore) -> None:
    scan = ScanContext(
        session=None,
        account_id=ACCOUNT,
        partition="aws",
        caller_arn="arn:aws:iam::123456789012:user/x",
        home_region="ap-northeast-2",
        regions=("ap-northeast-2",),
        excluded_regions=(("eu-west-1", "AccessDenied: scp"),),
    )
    writer = store.begin(scan, T0)
    writer.write(_snapshot())
    manifest, _ = load_scan(writer.finish())
    assert manifest.excluded_regions == {"eu-west-1": "AccessDenied: scp"}
