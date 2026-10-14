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

from pydantic import ValidationError

from kompass.aws.session import ScanContext
from kompass.collectors.base import Collector
from kompass.collectors.cloudtrail import CloudTrailCollector
from kompass.collectors.ec2 import Ec2Collector
from kompass.collectors.iam import IamCollector
from kompass.collectors.s3 import S3Collector
from kompass.config import Settings
from kompass.mappings.data import load_mappings
from kompass.mappings.mapper import build_report
from kompass.models import (
    AuditReport,
    EvaluationReport,
    ExplanationReport,
    ScanManifest,
    Snapshot,
    Status,
)
from kompass.reporters.json_reporter import render_json
from kompass.reporters.markdown_reporter import render_markdown
from kompass.reporters.xlsx_reporter import render_xlsx
from kompass.rules.registry import evaluate
from kompass.snapshots import SnapshotStore, load_scan

COLLECTORS: dict[str, Callable[[], Collector]] = {
    "cloudtrail": CloudTrailCollector,
    "ec2": Ec2Collector,
    "iam": IamCollector,
    "s3": S3Collector,
}
FINDINGS_DIR = "findings"
EXPLANATIONS_DIR = "explanations"
SNAPSHOTS_DIR = "snapshots"

# 보고서 형식 → (파일 확장자, 렌더러)
REPORT_FORMATS: dict[str, tuple[str, Callable[[AuditReport], str | bytes]]] = {
    "md": (".md", render_markdown),
    "xlsx": (".xlsx", render_xlsx),
    "json": (".report.json", render_json),
}

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
        settings=settings.judgment_criteria(),
        skipped_rules=result.skipped,
        findings=result.findings,
    )
    return manifest, report


def default_findings_path(store: SnapshotStore, report: EvaluationReport) -> Path:
    return store.root / FINDINGS_DIR / report.account_id / f"{report.scan_id}.findings.json"


def write_report(report: EvaluationReport | ExplanationReport, path: Path) -> Path:
    """판정·해설 결과를 UTF-8 JSON으로 쓴다. 임시 파일에 쓴 뒤 이름을 바꾼다."""
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


def latest_findings(store: SnapshotStore, account_id: str | None = None) -> Path | None:
    """가장 최근에 판정한 결과 파일. 계정이 여럿인데 지정하지 않으면 ValueError."""
    root = store.root / FINDINGS_DIR
    if not root.is_dir():
        return None
    if account_id is None:
        accounts = [p.name for p in root.iterdir() if p.is_dir()]
        if len(accounts) > 1:
            listed = ", ".join(sorted(accounts))
            raise ValueError(f"여러 계정의 판정 결과가 있다 ({listed}). 계정을 지정해야 한다")
        if not accounts:
            return None
        account_id = accounts[0]
    files = sorted((root / account_id).glob("*.findings.json"))
    if not files:
        return None
    return max(files, key=lambda p: _read_evaluation(p).evaluated_at)


def _read_evaluation(path: Path) -> EvaluationReport:
    return EvaluationReport.model_validate_json(path.read_text(encoding="utf-8"))


def make_report(store: SnapshotStore, findings_path: Path) -> AuditReport:
    """판정 결과에 매핑을 붙여 보고서 데이터를 만든다 (ADR-025).

    해당 점검의 스냅샷을 다시 불러와 해시를 대조한다. 증적이 바뀌었으면 보고서를 만들지 않는다.
    """
    evaluation = _read_evaluation(findings_path)
    scan_path = store.root / SNAPSHOTS_DIR / evaluation.account_id / evaluation.scan_id
    manifest, _ = load_scan(scan_path)
    return build_report(manifest, evaluation, load_mappings())


def write_reports(report: AuditReport, formats: Sequence[str], out_dir: Path) -> list[Path]:
    unknown = [f for f in formats if f not in REPORT_FORMATS]
    if unknown:
        raise ValueError(f"알 수 없는 보고서 형식: {', '.join(unknown)}")
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in dict.fromkeys(formats):
        suffix, render = REPORT_FORMATS[name]
        path = out_dir / f"{report.scan.scan_id}{suffix}"
        content = render(report)
        temp = path.with_name(path.name + ".tmp")
        if isinstance(content, bytes):
            temp.write_bytes(content)
        else:
            temp.write_text(content, encoding="utf-8")
        os.replace(temp, path)
        written.append(path)
    return written


def default_reports_dir(store: SnapshotStore, report: AuditReport) -> Path:
    """사람이 보는 보고서는 저장 위치 바로 아래 계정 폴더에 둔다 (ADR-027)."""
    return store.root / report.scan.account_id


def default_explanations_path(store: SnapshotStore, account_id: str, scan_id: str) -> Path:
    return store.root / EXPLANATIONS_DIR / account_id / f"{scan_id}.explanations.json"


def attach_explanations(
    store: SnapshotStore, report: AuditReport
) -> tuple[AuditReport, str | None]:
    """저장된 해설이 이 판정 결과의 것이면 보고서에 붙인다. (보고서, 경고)를 돌려준다.

    해설 뒤에 다시 판정했으면 finding이 달라졌을 수 있으므로 붙이지 않고 경고한다.
    """
    path = default_explanations_path(store, report.scan.account_id, report.scan.scan_id)
    if not path.is_file():
        return report, None
    try:
        explanations = ExplanationReport.model_validate_json(path.read_bytes())
    except (OSError, ValidationError):
        return report, (
            f"해설 파일({path.name})을 읽을 수 없어 보고서에 붙이지 않았다. "
            "kompass explain을 다시 실행한다"
        )
    try:
        return report.with_explanations(explanations), None
    except ValueError:
        return report, (
            f"해설({path.name})이 이전 판정 결과를 대상으로 해 보고서에 붙이지 않았다. "
            "kompass explain을 다시 실행한다"
        )
