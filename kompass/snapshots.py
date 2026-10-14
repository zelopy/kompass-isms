"""스냅샷 저장·로드 (ADR-003, ADR-022, ADR-027).

저장 위치(`<root>`)는 `default_store_root()`가 정한다: `KOMPASS_STORE` 환경 변수, 없으면 kompass
저장소 최상위의 `reports/`, 저장소 밖이면 현재 디렉터리의 `reports/`.

배치: `<root>/snapshots/<account_id>/<scan_id>/`
- `<service>.json`: 서비스별 스냅샷
- `scan.json`: 점검 정보와 스냅샷 파일별 SHA-256. **맨 마지막에** 쓴다.
  이 파일이 없는 폴더는 중단된 점검이므로 불러오지 않는다.

모든 파일은 UTF-8로 쓰고, 임시 파일에 쓴 뒤 이름을 바꿔서 반쯤 쓰인 파일이 남지 않게 한다.
`<root>`에는 모든 파일을 무시하는 `.gitignore`를 둔다. 스냅샷은 실제 계정 데이터다 (원칙 4).
"""

import hashlib
import os
import re
import secrets
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from kompass.aws.session import ScanContext
from kompass.models import ScanManifest, Snapshot

STORE_ENV = "KOMPASS_STORE"
STORE_DIR_NAME = "reports"
_PROJECT_MARKER = 'name = "kompass-isms"'
MANIFEST_NAME = "scan.json"
_SERVICE_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_PRIVATE_DIR_MODE = 0o700  # POSIX 전용. Windows에서는 무시된다


class IncompleteScanError(Exception):
    """`scan.json`이 없는 점검 폴더. 중단된 점검이다."""


class SnapshotIntegrityError(Exception):
    """스냅샷 파일이 없거나 `scan.json`에 기록된 해시와 다르다."""


class ScanWriter:
    """점검 한 번의 스냅샷을 폴더에 쓴다. `finish()`로 `scan.json`을 써야 완료된다."""

    def __init__(self, path: Path, scan: ScanContext, scan_id: str, started_at: datetime):
        self.path = path
        self._scan = scan
        self._scan_id = scan_id
        self._started_at = started_at
        self._hashes: dict[str, str] = {}
        self._finished = False

    def write(self, snapshot: Snapshot) -> None:
        if self._finished:
            raise RuntimeError("이미 완료된 점검에는 스냅샷을 추가할 수 없다")
        if not _SERVICE_NAME.match(snapshot.service):
            raise ValueError(f"파일 이름으로 쓸 수 없는 서비스 이름: {snapshot.service!r}")
        if snapshot.service in self._hashes:
            raise ValueError(f"이미 저장한 서비스: {snapshot.service}")
        if snapshot.account_id != self._scan.account_id:
            raise ValueError(
                f"점검 계정({self._scan.account_id})과 다른 계정의 스냅샷: {snapshot.account_id}"
            )
        content = snapshot.model_dump_json(indent=2)
        self._hashes[snapshot.service] = _write_atomic(
            self.path / f"{snapshot.service}.json", content
        )

    def finish(self, finished_at: datetime | None = None) -> Path:
        """`scan.json`을 써서 점검을 완료한다. 완료된 폴더 경로를 돌려준다."""
        if self._finished:
            raise RuntimeError("이미 완료된 점검이다")
        manifest = ScanManifest(
            scan_id=self._scan_id,
            account_id=self._scan.account_id,
            partition=self._scan.partition,
            caller_arn=self._scan.caller_arn,
            home_region=self._scan.home_region,
            regions=self._scan.regions,
            kompass_version=version("kompass-isms"),
            started_at=self._started_at,
            finished_at=finished_at or datetime.now(UTC),
            snapshots=self._hashes,
            excluded_regions=dict(self._scan.excluded_regions),
        )
        _write_atomic(self.path / MANIFEST_NAME, manifest.model_dump_json(indent=2))
        self._finished = True
        return self.path


def default_store_root(cwd: Path | None = None) -> Path:
    """결과 저장 위치. 어느 폴더에서 실행해도 같은 곳에 모이도록 저장소 최상위를 찾는다."""
    configured = os.environ.get(STORE_ENV)
    if configured:
        return Path(configured)
    start = (cwd or Path.cwd()).resolve()
    for directory in (start, *start.parents):
        pyproject = directory / "pyproject.toml"
        if pyproject.is_file() and _PROJECT_MARKER in pyproject.read_text(
            encoding="utf-8", errors="ignore"
        ):
            return directory / STORE_DIR_NAME
    return start / STORE_DIR_NAME


class SnapshotStore:
    """스냅샷·판정 결과·보고서 저장소. 기본 위치는 `default_store_root()`."""

    def __init__(self, root: Path | None = None):
        self.root = root if root is not None else default_store_root()

    def begin(self, scan: ScanContext, started_at: datetime | None = None) -> ScanWriter:
        """새 점검 폴더를 만든다. 같은 이름의 폴더가 있으면 덮어쓰지 않고 실패한다."""
        started = (started_at or datetime.now(UTC)).astimezone(UTC)
        self._ensure_root()
        account_dir = self.root / "snapshots" / scan.account_id
        account_dir.mkdir(parents=True, exist_ok=True)
        scan_id = f"{started:%Y%m%dT%H%M%SZ}-{secrets.token_hex(2)}"
        path = account_dir / scan_id
        path.mkdir(mode=_PRIVATE_DIR_MODE)
        return ScanWriter(path, scan, scan_id, started)

    def latest_scan(self, account_id: str | None = None) -> Path | None:
        """완료된 점검 중 가장 최근 것의 폴더. 없으면 None.

        계정을 지정하지 않았는데 여러 계정의 점검이 있으면 다른 계정의 결과를 쓰는 실수를
        막기 위해 ValueError를 낸다.
        """
        snapshots_dir = self.root / "snapshots"
        if not snapshots_dir.is_dir():
            return None
        if account_id is None:
            accounts = [p.name for p in snapshots_dir.iterdir() if p.is_dir()]
            if len(accounts) > 1:
                raise ValueError(
                    f"여러 계정의 점검이 있다 ({', '.join(sorted(accounts))}). 계정을 지정해야 한다"
                )
            if not accounts:
                return None
            account_id = accounts[0]
        account_dir = snapshots_dir / account_id
        if not account_dir.is_dir():
            return None
        complete = [p for p in account_dir.iterdir() if (p / MANIFEST_NAME).is_file()]
        if not complete:
            return None
        return max(complete, key=lambda p: _read_manifest(p).started_at)

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=_PRIVATE_DIR_MODE)
        gitignore = self.root / ".gitignore"
        if not gitignore.exists():
            gitignore.write_text("*\n", encoding="utf-8")


def load_scan(path: Path) -> tuple[ScanManifest, dict[str, Snapshot]]:
    """완료된 점검 폴더를 불러온다. 파일 해시를 `scan.json`과 대조한다."""
    if not (path / MANIFEST_NAME).is_file():
        raise IncompleteScanError(f"완료되지 않은 점검 폴더: {path}")
    manifest = _read_manifest(path)
    snapshots: dict[str, Snapshot] = {}
    for service, expected_hash in manifest.snapshots.items():
        file = path / f"{service}.json"
        if not file.is_file():
            raise SnapshotIntegrityError(f"스냅샷 파일이 없다: {service}")
        content = file.read_bytes()
        if hashlib.sha256(content).hexdigest() != expected_hash:
            raise SnapshotIntegrityError(f"스냅샷 파일이 기록과 다르다 (손상 또는 수정): {service}")
        snapshots[service] = Snapshot.model_validate_json(content.decode("utf-8"))
    return manifest, snapshots


def _read_manifest(path: Path) -> ScanManifest:
    return ScanManifest.model_validate_json((path / MANIFEST_NAME).read_text(encoding="utf-8"))


def _write_atomic(path: Path, content: str) -> str:
    """임시 파일에 쓴 뒤 이름을 바꾼다. 쓴 내용의 SHA-256을 돌려준다."""
    data = content.encode("utf-8")
    temp = path.with_name(path.name + ".tmp")
    with open(temp, "wb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temp, path)
    return hashlib.sha256(data).hexdigest()
