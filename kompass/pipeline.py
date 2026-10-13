"""점검 실행 흐름: 수집(collect) → 저장 → 판정(evaluate) → 결과 파일.

CLI는 이 모듈을 호출하기만 한다. 판정은 룰만 하며(원칙 1), 결과 파일에는 어떤 스냅샷을 어떤
기준값과 버전으로 판정했는지 함께 남긴다.
"""

import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from kompass.aws.session import ScanContext
from kompass.collectors.base import Collector
from kompass.collectors.cloudtrail import CloudTrailCollector
from kompass.collectors.ec2 import Ec2Collector
from kompass.collectors.iam import IamCollector
from kompass.collectors.s3 import S3Collector
from kompass.config import Settings
from kompass.models import EvaluationReport, ScanManifest, Snapshot, Status
from kompass.rules.registry import evaluate
from kompass.snapshots import SnapshotStore, load_scan

COLLECTORS: dict[str, Callable[[], Collector]] = {
    "cloudtrail": CloudTrailCollector,
    "ec2": Ec2Collector,
    "iam": IamCollector,
    "s3": S3Collector,
}
FINDINGS_DIR = "findings"

# --fail-on 기준: 이 상태 중 하나라도 있으면 종료 코드 1
FAIL_ON: dict[str, frozenset[Status]] = {
    "fail": frozenset({Status.FAIL}),
    "error": frozenset({Status.FAIL, Status.ERROR}),
    "review": frozenset({Status.FAIL, Status.ERROR, Status.REVIEW}),
}


@dataclass(frozen=True)
class CollectResult:
    scan_path: Path
    errors_by_service: dict[str, int]


def collect(
    scan: ScanContext,
    store: SnapshotStore,
    services: Sequence[str] | None = None,
    on_service: Callable[[str, Snapshot], None] | None = None,
) -> CollectResult:
    """서비스별로 수집해 저장하고 점검을 완료한다.

    세션 단계 실패(`SessionError`)가 나면 `scan.json`을 쓰지 않으므로 그 폴더는 미완료 점검으로
    남고 불러오지 않는다 (ADR-022).
    """
    selected = list(services or COLLECTORS)
    unknown = [s for s in selected if s not in COLLECTORS]
    if unknown:
        raise ValueError(f"알 수 없는 서비스: {', '.join(unknown)}")
    writer = store.begin(scan)
    errors: dict[str, int] = {}
    for service in selected:
        snapshot = COLLECTORS[service]().collect(scan)
        writer.write(snapshot)
        errors[service] = len(snapshot.errors)
        if on_service is not None:
            on_service(service, snapshot)
    return CollectResult(scan_path=writer.finish(), errors_by_service=errors)


def evaluate_scan(scan_path: Path, settings: Settings) -> tuple[ScanManifest, EvaluationReport]:
    """완료된 점검 폴더를 불러와 판정한다. 스냅샷 해시를 대조한다."""
    manifest, snapshots = load_scan(scan_path)
    result = evaluate(snapshots, settings)
    report = EvaluationReport(
        scan_id=manifest.scan_id,
        account_id=manifest.account_id,
        kompass_version=version("kompass-isms"),
        evaluated_at=datetime.now(UTC),
        settings=settings.model_dump(mode="json"),
        skipped_rules=result.skipped,
        findings=result.findings,
    )
    return manifest, report


def default_findings_path(store: SnapshotStore, report: EvaluationReport) -> Path:
    return store.root / FINDINGS_DIR / report.account_id / f"{report.scan_id}.findings.json"


def write_report(report: EvaluationReport, path: Path) -> Path:
    """판정 결과를 UTF-8 JSON으로 쓴다. 임시 파일에 쓴 뒤 이름을 바꾼다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    os.replace(temp, path)
    return path


def exceeds(report: EvaluationReport, fail_on: str | None) -> bool:
    """`--fail-on` 기준에 해당하는 finding이 있는가."""
    if fail_on is None:
        return False
    statuses = FAIL_ON[fail_on]
    return any(f.status in statuses for f in report.findings)
