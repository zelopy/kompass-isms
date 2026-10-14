"""kompass 명령줄 진입점.

- `collect`: 점검 세션을 열고 서비스별 설정을 수집해 스냅샷으로 저장한다
- `evaluate`: 저장된 스냅샷을 룰로 판정해 결과 파일(`*.findings.json`)을 쓴다
- `scan`: collect와 evaluate를 이어서 실행한다 (`--report`로 보고서까지)
- `report`: 판정 결과에 KISA·ISMS-P 매핑을 붙여 보고서(Markdown, Excel, JSON)를 만든다
- `explain`: 조치가 필요한 결과를 룰별로 LLM이 해설한다 (참고 자료, 판정은 바꾸지 않는다)

종료 코드: 0 완료(FAIL이 있어도 0), 1 `--fail-on` 기준 해당, 2 사용법·설정 오류,
3 세션 오류, 4 스냅샷 오류, 5 LLM 해설 전부 실패.
"""

import sys
from collections import Counter
from enum import StrEnum
from importlib.metadata import version
from pathlib import Path
from typing import NoReturn

import typer

from kompass.aws.session import ScanContext, SessionError, open_scan
from kompass.config import ConfigError, LlmSettings, Settings, load_settings
from kompass.interpreter.explainer import estimate_explanation, explain_report, select_groups
from kompass.interpreter.llm import ClaudeProvider, LLMError, LLMProvider
from kompass.interpreter.sources import SourceIndexError, SourceLookup, load_index
from kompass.models import AuditReport, EvaluationReport, Snapshot, Status
from kompass.pipeline import (
    COLLECTORS,
    attach_explanations,
    collect,
    default_explanations_path,
    default_findings_path,
    default_reports_dir,
    evaluate_scan,
    exceeds,
    latest_findings,
    make_report,
    write_report,
    write_reports,
)
from kompass.snapshots import (
    IncompleteScanError,
    SnapshotIntegrityError,
    SnapshotStore,
)

EXIT_FAIL_ON = 1
EXIT_USAGE = 2
EXIT_SESSION = 3
EXIT_SNAPSHOT = 4
EXIT_LLM = 5
DEFAULT_CONFIG = Path("kompass.yaml")
_STATUS_ORDER = (Status.FAIL, Status.ERROR, Status.REVIEW, Status.PASS, Status.NOT_APPLICABLE)

app = typer.Typer(
    name="kompass",
    help="AWS 계정을 읽기 전용으로 점검해 KISA·ISMS-P 기준 보고서를 만든다.",
    no_args_is_help=True,
    add_completion=False,
)


class FailOn(StrEnum):
    FAIL = "fail"
    ERROR = "error"
    REVIEW = "review"


class ReportFormat(StrEnum):
    MD = "md"
    XLSX = "xlsx"
    JSON = "json"


DEFAULT_REPORT_FORMATS = (ReportFormat.MD, ReportFormat.XLSX)


def _configure_output() -> None:
    """파이프·파일로 출력할 때 한글이 깨지지 않도록 UTF-8로 맞춘다.

    터미널에 직접 출력할 때는 Python이 이미 유니코드로 쓰므로 건드리지 않는다.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None and not stream.isatty():
            reconfigure(encoding="utf-8")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"kompass {version('kompass-isms')}")
        raise typer.Exit()


def _abort(message: str, code: int) -> NoReturn:
    typer.echo(f"오류: {message}", err=True)
    raise typer.Exit(code)


@app.callback()
def main(
    show_version: bool = typer.Option(
        False,
        "--version",
        help="버전을 출력하고 종료한다.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """AWS 계정을 읽기 전용으로 점검해 KISA·ISMS-P 기준 보고서를 만든다."""
    _configure_output()


# --- 공통 옵션 ---

ProfileOption = typer.Option(None, "--profile", help="AWS CLI 프로필 (SecurityAudit 권한 권장).")
RegionOption = typer.Option(None, "--region", help="기본 호출 리전. 없으면 프로필의 리전.")
RegionsOption = typer.Option(
    None,
    "--regions",
    help=(
        "리전 리소스(EC2·VPC)를 점검할 리전. 쉼표로 구분하거나 여러 번 지정. 없으면 활성 리전 전체."
    ),
)
AccountOption = typer.Option(
    None, "--account-id", help="점검 대상 계정 ID. 실제 계정이 다르면 중단한다."
)
ServiceOption = typer.Option(
    None, "--service", help=f"수집할 서비스 ({', '.join(COLLECTORS)}). 여러 번 지정. 없으면 전체."
)
StoreOption = typer.Option(
    None,
    "--store",
    help="결과 저장 위치. 없으면 KOMPASS_STORE, 그다음 kompass 저장소 최상위의 reports/.",
)
ConfigOption = typer.Option(
    None, "--config", help="판정 기준값 파일. 없으면 현재 디렉터리의 kompass.yaml(있을 때)."
)
OutputOption = typer.Option(
    None, "--output", help="결과 파일 경로. 없으면 <store>/findings/<계정>/<점검 ID>.findings.json."
)
FailOnOption = typer.Option(
    None, "--fail-on", help="이 상태(이상)의 결과가 있으면 종료 코드 1. fail < error < review."
)


def _split_regions(values: list[str] | None) -> list[str] | None:
    if not values:
        return None
    return [r.strip() for value in values for r in value.split(",") if r.strip()]


def _open(
    profile: str | None, region: str | None, regions: list[str] | None, account_id: str | None
) -> ScanContext:
    try:
        scan = open_scan(
            profile=profile,
            region=region,
            regions=_split_regions(regions),
            expected_account_id=account_id,
        )
    except SessionError as exc:
        _abort(str(exc), EXIT_SESSION)
    typer.echo(f"점검 계정: {scan.account_id} ({scan.partition})")
    typer.echo(f"호출자: {scan.caller_arn}")
    typer.echo(f"기본 리전: {scan.home_region}, 점검 리전: {len(scan.regions)}개")
    if scan.excluded_regions:
        names = ", ".join(region for region, _ in scan.excluded_regions)
        typer.echo(
            f"경고: 접근이 거부된 리전 {len(scan.excluded_regions)}개를 점검 범위에서 뺐다 "
            f"(보고서에 범위 밖으로 표시): {names}",
            err=True,
        )
    return scan


def _collect(scan: ScanContext, store: SnapshotStore, services: list[str] | None) -> Path:
    def report(service: str, snapshot: Snapshot) -> None:
        typer.echo(f"  수집 {service}: 수집 실패 {len(snapshot.errors)}건")

    try:
        result = collect(scan, store, services, on_service=report)
    except SessionError as exc:
        _abort(str(exc), EXIT_SESSION)
    except ValueError as exc:
        _abort(str(exc), EXIT_USAGE)
    typer.echo(f"스냅샷: {result.scan_path}")
    return result.scan_path


def _settings(config: Path | None) -> Settings:
    path = config if config is not None else (DEFAULT_CONFIG if DEFAULT_CONFIG.exists() else None)
    try:
        settings = load_settings(path)
    except ConfigError as exc:
        _abort(str(exc), EXIT_USAGE)
    typer.echo(f"판정 기준: {path if path else '기본값'}")
    return settings


def _evaluate(
    scan_path: Path,
    store: SnapshotStore,
    settings: Settings,
    output: Path | None,
    fail_on: FailOn | None,
) -> tuple[Path, bool]:
    """판정해 결과 파일을 쓴다. (결과 파일 경로, `--fail-on` 기준 해당 여부)를 돌려준다."""
    try:
        _, report = evaluate_scan(scan_path, settings)
    except (IncompleteScanError, SnapshotIntegrityError, FileNotFoundError) as exc:
        _abort(str(exc), EXIT_SNAPSHOT)
    path = write_report(report, output or default_findings_path(store, report))
    _print_summary(report)
    typer.echo(f"결과 파일: {path}")
    return path, exceeds(report, fail_on.value if fail_on else None)


def _reports(store: SnapshotStore, findings_path: Path, formats: list[ReportFormat]) -> None:
    report, warning = attach_explanations(store, _audit_report(store, findings_path))
    if warning:
        typer.echo(f"경고: {warning}", err=True)
    paths = write_reports(report, [f.value for f in formats], default_reports_dir(store, report))
    for path in paths:
        typer.echo(f"보고서: {path}")


def _audit_report(store: SnapshotStore, findings_path: Path) -> AuditReport:
    try:
        return make_report(store, findings_path)
    except (IncompleteScanError, SnapshotIntegrityError, FileNotFoundError) as exc:
        _abort(str(exc), EXIT_SNAPSHOT)


def _findings_path(store: SnapshotStore, findings: Path | None, account_id: str | None) -> Path:
    if findings is not None:
        return findings
    try:
        latest = latest_findings(store, account_id)
    except ValueError as exc:
        _abort(str(exc), EXIT_USAGE)
    if latest is None:
        _abort(f"판정 결과가 없다: {store.root}", EXIT_SNAPSHOT)
    typer.echo(f"판정 결과: {latest}")
    return latest


def make_provider(settings: LlmSettings) -> LLMProvider:
    """LLM 공급자를 만든다. 테스트는 이 함수를 바꿔 가짜 공급자를 넣는다."""
    return ClaudeProvider(settings)


def _print_summary(report: EvaluationReport) -> None:
    counts: dict[str, Counter[Status]] = {}
    for finding in report.findings:
        counts.setdefault(finding.rule_id, Counter())[finding.status] += 1
    header = "  ".join(f"{s.value:>6}" for s in _STATUS_ORDER)
    typer.echo(f"\n{'룰':10}{header}")
    for rule_id, counter in counts.items():
        row = "  ".join(f"{counter.get(s, 0):>6}" for s in _STATUS_ORDER)
        typer.echo(f"{rule_id:10}{row}")
    total = Counter(f.status for f in report.findings)
    typer.echo("합계: " + ", ".join(f"{s.value} {total.get(s, 0)}" for s in _STATUS_ORDER))
    if report.skipped_rules:
        typer.echo(f"건너뛴 룰 (스냅샷 없음, PASS 아님): {', '.join(report.skipped_rules)}")


# --- 명령 ---


@app.command("collect")
def collect_command(
    profile: str | None = ProfileOption,
    region: str | None = RegionOption,
    regions: list[str] | None = RegionsOption,
    account_id: str | None = AccountOption,
    service: list[str] | None = ServiceOption,
    store: Path | None = StoreOption,
) -> None:
    """설정을 수집해 스냅샷으로 저장한다."""
    scan = _open(profile, region, regions, account_id)
    _collect(scan, SnapshotStore(store), service)


@app.command("evaluate")
def evaluate_command(
    scan_path: Path | None = typer.Option(
        None, "--scan", help="판정할 점검 폴더. 없으면 가장 최근의 완료된 점검."
    ),
    account_id: str | None = AccountOption,
    store: Path | None = StoreOption,
    config: Path | None = ConfigOption,
    output: Path | None = OutputOption,
    fail_on: FailOn | None = FailOnOption,
) -> None:
    """저장된 스냅샷을 판정해 결과 파일을 쓴다."""
    snapshot_store = SnapshotStore(store)
    if scan_path is None:
        try:
            scan_path = snapshot_store.latest_scan(account_id)
        except ValueError as exc:
            _abort(str(exc), EXIT_USAGE)
        if scan_path is None:
            _abort(f"완료된 점검이 없다: {snapshot_store.root}", EXIT_SNAPSHOT)
        typer.echo(f"점검: {scan_path}")
    _, exceeded = _evaluate(scan_path, snapshot_store, _settings(config), output, fail_on)
    if exceeded:
        raise typer.Exit(EXIT_FAIL_ON)


@app.command("scan")
def scan_command(
    profile: str | None = ProfileOption,
    region: str | None = RegionOption,
    regions: list[str] | None = RegionsOption,
    account_id: str | None = AccountOption,
    service: list[str] | None = ServiceOption,
    store: Path | None = StoreOption,
    config: Path | None = ConfigOption,
    output: Path | None = OutputOption,
    fail_on: FailOn | None = FailOnOption,
    report: list[ReportFormat] | None = typer.Option(
        None, "--report", help="판정 후 이 형식의 보고서도 만든다 (md, xlsx, json). 여러 번 지정."
    ),
) -> None:
    """수집과 판정을 이어서 실행한다."""
    settings = _settings(config)  # 설정 오류는 AWS를 호출하기 전에 드러낸다
    scan = _open(profile, region, regions, account_id)
    snapshot_store = SnapshotStore(store)
    scan_path = _collect(scan, snapshot_store, service)
    findings_path, exceeded = _evaluate(scan_path, snapshot_store, settings, output, fail_on)
    if report:
        _reports(snapshot_store, findings_path, report)
    if exceeded:
        raise typer.Exit(EXIT_FAIL_ON)


@app.command("report")
def report_command(
    findings: Path | None = typer.Option(
        None, "--findings", help="판정 결과 파일. 없으면 가장 최근에 판정한 결과."
    ),
    account_id: str | None = AccountOption,
    store: Path | None = StoreOption,
    formats: list[ReportFormat] | None = typer.Option(
        None, "--format", help="보고서 형식 (md, xlsx, json). 여러 번 지정. 없으면 md와 xlsx."
    ),
) -> None:
    """판정 결과에 KISA·ISMS-P 매핑(과 해설이 있으면 해설)을 붙여 보고서를 만든다."""
    snapshot_store = SnapshotStore(store)
    findings = _findings_path(snapshot_store, findings, account_id)
    _reports(snapshot_store, findings, list(formats or DEFAULT_REPORT_FORMATS))


@app.command("explain")
def explain_command(
    findings: Path | None = typer.Option(
        None, "--findings", help="해설할 판정 결과 파일. 없으면 가장 최근에 판정한 결과."
    ),
    account_id: str | None = AccountOption,
    store: Path | None = StoreOption,
    config: Path | None = ConfigOption,
    dry_run: bool = typer.Option(
        False, "--dry-run", help="해설을 요청하지 않고 대상과 예상 비용만 보여준다."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="비용 확인 없이 진행한다."),
    report: list[ReportFormat] | None = typer.Option(
        None, "--report", help="해설 후 이 형식의 보고서도 다시 만든다 (md, xlsx, json)."
    ),
) -> None:
    """조치가 필요한 결과를 룰별로 묶어 LLM 해설을 만든다. 판정은 바꾸지 않는다.

    LLM에는 계정 ID·IP·ARN·리소스 이름을 가린 값만 보낸다. API 키는 ANTHROPIC_API_KEY.
    """
    settings = _settings(config)
    snapshot_store = SnapshotStore(store)
    findings = _findings_path(snapshot_store, findings, account_id)
    audit = _audit_report(snapshot_store, findings)
    try:
        lookup = SourceLookup(load_index())
    except SourceIndexError as exc:
        _abort(str(exc), EXIT_USAGE)

    groups = select_groups(audit)
    if not groups:
        typer.echo("조치가 필요한 결과(취약·확인 불가·검토 필요)가 없어 해설할 것이 없다.")
        return
    try:
        provider = make_provider(settings.llm)
        estimate = estimate_explanation(audit, provider, lookup)
    except LLMError as exc:
        _abort(str(exc), EXIT_USAGE)
    if estimate.blocked:
        typer.echo(
            f"경고: 마스킹 검증에 실패해 보내지 않을 룰: {', '.join(estimate.blocked)}", err=True
        )
    if not estimate.rules:
        _abort("마스킹 검증을 통과한 룰이 없어 해설을 요청하지 않는다", EXIT_LLM)
    typer.echo(
        f"해설 대상: 룰 {estimate.rules}개, finding {estimate.findings}건 "
        f"(모델 {provider.model}, effort {settings.llm.effort})"
    )
    typer.echo(f"입력 토큰: {estimate.input_tokens:,} (마스킹한 프롬프트 기준)")
    if estimate.cost_usd is None:
        typer.echo("예상 비용: 단가를 모르는 모델")
    else:
        typer.echo(
            f"예상 비용: 약 ${estimate.cost_usd:.2f} "
            f"(출력 룰당 {estimate.assumed_output_tokens // estimate.rules:,} 토큰 가정, "
            "재시도 제외)"
        )
    if dry_run:
        return
    if not yes and not typer.confirm("해설을 요청할까?"):
        typer.echo("취소했다.")
        return

    result = explain_report(
        audit,
        provider,
        lookup,
        effort=settings.llm.effort,
        on_progress=lambda rule_id: typer.echo(f"  해설 {rule_id}"),
    )
    path = write_report(
        result, default_explanations_path(snapshot_store, result.account_id, result.scan_id)
    )
    verified = sum(1 for e in result.explanations if e.verified)
    typer.echo(
        f"해설: 검증됨 {verified}, 검증되지 않음 {len(result.explanations) - verified}, "
        f"실패 {len(result.failures)}"
    )
    for failure in result.failures:
        typer.echo(f"경고: {failure.rule_id} 해설 실패: {failure.error}", err=True)
    cost = f", 비용 약 ${result.estimated_cost_usd:.2f}" if result.estimated_cost_usd else ""
    typer.echo(
        f"토큰: 입력 {result.usage.input_tokens:,}, 출력 {result.usage.output_tokens:,}{cost}"
    )
    typer.echo(f"해설 파일: {path}")
    if report:
        _reports(snapshot_store, findings, report)
    if not result.explanations:
        raise typer.Exit(EXIT_LLM)
