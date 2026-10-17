"""kompass 명령줄 진입점.

- `collect`: 점검 세션을 열고 서비스별 설정을 수집해 스냅샷으로 저장한다
- `evaluate`: 저장된 스냅샷을 룰로 판정해 결과 파일(`*.findings.json`)을 쓴다
- `scan`: collect와 evaluate를 이어서 실행한다 (`--report`로 보고서까지)
- `report`: 판정 결과에 KISA·ISMS-P 매핑을 붙여 보고서(Markdown, Excel, JSON)를 만든다
- `explain`: 조치가 필요한 결과를 룰별로 LLM이 해설한다 (참고 자료, 판정은 바꾸지 않는다)
- `review-evidence`: 담당자가 제출한 증적 문서를 요청별로 LLM이 검토한다 (참고, ADR-049)

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

from kompass.agent.investigator import (
    DEFAULT_MAX_ITERATIONS,
    DEFAULT_MAX_TOTAL_TOKENS,
    investigate_report,
    investigation_groups,
)
from kompass.agent.llm import AgentProvider, ClaudeAgentProvider
from kompass.agent.mcp_server import (
    DEFAULT_MCP_MAX_CALLS,
    McpSession,
    build_server,
    default_log_path,
    serve_stdio,
)
from kompass.agent.toolbox import DEFAULT_MAX_CALLS
from kompass.agent.tools import ToolContext
from kompass.aws.guard import ReadOnlyViolation
from kompass.aws.session import ScanContext, SessionError, open_scan
from kompass.config import ConfigError, LlmSettings, Settings, load_settings
from kompass.interpreter.documents import EvidenceFolderError, load_submission
from kompass.interpreter.evidence_reviewer import (
    estimate_review,
    render_preview,
    review_submission,
)
from kompass.interpreter.explainer import (
    estimate_assessment,
    estimate_explanation,
    explain_report,
    reassess_report,
    select_groups,
)
from kompass.interpreter.llm import PRICES, ClaudeProvider, LLMError, LLMProvider
from kompass.interpreter.masking import MaskingError, load_terms
from kompass.interpreter.sources import SourceIndexError, SourceLookup, load_index
from kompass.mappings.data import load_mappings
from kompass.models import AuditReport, EvaluationReport, Snapshot, Status
from kompass.pipeline import (
    COLLECTORS,
    attach_evidence_reviews,
    attach_explanations,
    attach_investigations,
    collect,
    default_evidence_preview_path,
    default_evidence_review_path,
    default_explanations_path,
    default_findings_path,
    default_investigations_path,
    default_reports_dir,
    evaluate_scan,
    exceeds,
    latest_findings,
    make_report,
    write_report,
    write_reports,
)
from kompass.reporters._format import evidence_summary
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
    help="AWS 계정을 읽기 전용으로 점검해 KISA·ISMS-P 기준 보고서를 만듭니다.",
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
    EVIDENCE = "evidence"  # 담당자 증적 요청서 (xlsx)


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
        help="버전을 출력하고 종료합니다.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """AWS 계정을 읽기 전용으로 점검해 KISA·ISMS-P 기준 보고서를 만듭니다."""
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
    None, "--account-id", help="점검 대상 계정 ID. 실제 계정이 다르면 중단합니다."
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
            f"경고: 접근이 거부된 리전 {len(scan.excluded_regions)}개를 점검 범위에서 뺐습니다 "
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
    report, investigation_warning = attach_investigations(store, report)
    report, review_warning = attach_evidence_reviews(store, report)
    for message in (warning, investigation_warning, review_warning):
        if message:
            typer.echo(f"경고: {message}", err=True)
    paths = write_reports(report, [f.value for f in formats], default_reports_dir(store, report))
    for path in paths:
        typer.echo(f"보고서: {path}")


def _audit_report(store: SnapshotStore, findings_path: Path) -> AuditReport:
    try:
        return make_report(store, findings_path)
    except (IncompleteScanError, SnapshotIntegrityError, FileNotFoundError) as exc:
        _abort(str(exc), EXIT_SNAPSHOT)


def _findings_path(
    store: SnapshotStore, findings: Path | None, account_id: str | None, *, err: bool = False
) -> Path:
    if findings is not None:
        return findings
    try:
        latest = latest_findings(store, account_id)
    except ValueError as exc:
        _abort(str(exc), EXIT_USAGE)
    if latest is None:
        _abort(f"판정 결과가 없습니다: {store.root}", EXIT_SNAPSHOT)
    typer.echo(f"판정 결과: {latest}", err=err)
    return latest


def make_provider(settings: LlmSettings) -> LLMProvider:
    """LLM 공급자를 만든다. 테스트는 이 함수를 바꿔 가짜 공급자를 넣는다."""
    return ClaudeProvider(settings)


def make_agent_provider(settings: LlmSettings) -> AgentProvider:
    """에이전트 공급자를 만든다. 테스트는 이 함수를 바꿔 가짜 에이전트를 넣는다."""
    return ClaudeAgentProvider(settings)


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
    """설정을 수집해 스냅샷으로 저장합니다."""
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
    """저장된 스냅샷을 판정해 결과 파일을 씁니다."""
    snapshot_store = SnapshotStore(store)
    if scan_path is None:
        try:
            scan_path = snapshot_store.latest_scan(account_id)
        except ValueError as exc:
            _abort(str(exc), EXIT_USAGE)
        if scan_path is None:
            _abort(f"완료된 점검이 없습니다: {snapshot_store.root}", EXIT_SNAPSHOT)
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
        None,
        "--report",
        help="판정 후 이 형식의 보고서도 만듭니다 (md, xlsx, json, evidence). 여러 번 지정.",
    ),
) -> None:
    """수집과 판정을 이어서 실행합니다."""
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
        None,
        "--format",
        help="보고서 형식 (md, xlsx, json, evidence). 여러 번 지정. 없으면 md와 xlsx.",
    ),
) -> None:
    """판정 결과에 KISA·ISMS-P 매핑(해설이 있으면 해설도)을 붙여 보고서를 만듭니다."""
    snapshot_store = SnapshotStore(store)
    findings = _findings_path(snapshot_store, findings, account_id)
    _reports(snapshot_store, findings, list(formats or DEFAULT_REPORT_FORMATS))


@app.command("evidence")
def evidence_command(
    findings: Path | None = typer.Option(
        None, "--findings", help="판정 결과 파일. 없으면 가장 최근에 판정한 결과."
    ),
    account_id: str | None = AccountOption,
    store: Path | None = StoreOption,
) -> None:
    """자동 점검만으로 확인할 수 없는 항목에 대해 담당자에게 보낼 증적 요청서(xlsx)를 만듭니다.

    요청 목록은 매핑 데이터로 정해지며 LLM과 AWS를 호출하지 않습니다.
    """
    snapshot_store = SnapshotStore(store)
    findings = _findings_path(snapshot_store, findings, account_id)
    report = _audit_report(snapshot_store, findings)
    if not report.evidence_requests:
        typer.echo("증적을 요청할 항목이 없습니다.")
        return
    typer.echo(f"증적 요청: {evidence_summary(report)}")
    if any(not g.verified for g in report.evidence_requests):
        typer.echo("참고: 요청 문구는 원문 대조 확인 전 초안입니다.")
    paths = write_reports(
        report, [ReportFormat.EVIDENCE.value], default_reports_dir(snapshot_store, report)
    )
    for path in paths:
        typer.echo(f"요청서: {path}")


@app.command("explain")
def explain_command(
    findings: Path | None = typer.Option(
        None, "--findings", help="해설할 판정 결과 파일. 없으면 가장 최근에 판정한 결과."
    ),
    account_id: str | None = AccountOption,
    store: Path | None = StoreOption,
    config: Path | None = ConfigOption,
    dry_run: bool = typer.Option(
        False, "--dry-run", help="해설을 요청하지 않고 대상과 예상 비용만 보여줍니다."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="비용 확인 없이 진행합니다."),
    no_assessment: bool = typer.Option(
        False, "--no-assessment", help="룰을 엮은 종합 위험 평가(LLM 1회 추가)를 하지 않습니다."
    ),
    assessment_only: bool = typer.Option(
        False,
        "--assessment-only",
        help="저장된 룰별 해설을 그대로 두고 종합 위험 평가만 다시 만듭니다 (LLM 1회).",
    ),
    report: list[ReportFormat] | None = typer.Option(
        None,
        "--report",
        help="해설 후 이 형식의 보고서도 다시 만듭니다 (md, xlsx, json, evidence).",
    ),
) -> None:
    """조치가 필요한 결과를 룰별로 묶어 LLM 해설을 만듭니다. 판정은 바꾸지 않습니다.

    LLM에는 계정 ID·IP·ARN·리소스 이름을 가린 값만 보냅니다.
    API 키는 환경 변수 ANTHROPIC_API_KEY에서 읽습니다.
    """
    if assessment_only and no_assessment:
        _abort("--assessment-only와 --no-assessment는 함께 쓸 수 없습니다", EXIT_USAGE)
    settings = _settings(config)
    snapshot_store = SnapshotStore(store)
    findings = _findings_path(snapshot_store, findings, account_id)
    audit = _audit_report(snapshot_store, findings)
    if assessment_only:
        _reassess(snapshot_store, findings, audit, settings, dry_run=dry_run, yes=yes,
                  report=report)  # fmt: skip
        return
    try:
        lookup = SourceLookup(load_index())
    except SourceIndexError as exc:
        _abort(str(exc), EXIT_USAGE)

    groups = select_groups(audit)
    if not groups:
        typer.echo("조치가 필요한 결과(취약·확인 불가·검토 필요)가 없어 해설할 것이 없습니다.")
        return
    try:
        provider = make_provider(settings.llm)
        estimate = estimate_explanation(audit, provider, lookup, assess=not no_assessment)
    except LLMError as exc:
        _abort(str(exc), EXIT_USAGE)
    if estimate.blocked:
        typer.echo(
            f"경고: 마스킹 검증에 실패해 보내지 않을 룰: {', '.join(estimate.blocked)}", err=True
        )
    if not estimate.rules:
        _abort("마스킹 검증을 통과한 룰이 없어 해설을 요청하지 않습니다", EXIT_LLM)
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
    if not yes and not typer.confirm("해설을 요청하시겠습니까?"):
        typer.echo("취소했습니다.")
        return

    result = explain_report(
        audit,
        provider,
        lookup,
        effort=settings.llm.effort,
        assess=not no_assessment,
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
    if result.assessment is not None:
        status = "검증됨" if result.assessment.verified else "검증되지 않음"
        typer.echo(
            f"종합 평가: {status} (시나리오 {len(result.assessment.assessment.scenarios)}개)"
        )
    elif result.assessment_failure:
        typer.echo(f"경고: 종합 평가 실패: {result.assessment_failure}", err=True)
    for failure in result.failures:
        typer.echo(f"경고: {failure.rule_id} 해설 실패: {failure.error}", err=True)
    cost = (
        f", 비용 약 ${result.estimated_cost_usd:.2f}"
        if result.estimated_cost_usd is not None
        else ""
    )
    typer.echo(
        f"토큰: 입력 {result.usage.input_tokens:,}, 출력 {result.usage.output_tokens:,}{cost}"
    )
    typer.echo(f"해설 파일: {path}")
    if report:
        _reports(snapshot_store, findings, report)
    if not result.explanations:
        raise typer.Exit(EXIT_LLM)


def _reassess(
    store: SnapshotStore,
    findings: Path,
    audit: AuditReport,
    settings: Settings,
    *,
    dry_run: bool,
    yes: bool,
    report: list[ReportFormat] | None,
) -> None:
    """`explain --assessment-only`: 같은 판정 결과의 저장된 해설에 종합 평가만 다시 만든다."""
    attached, warning = attach_explanations(store, audit)
    existing = attached.explanations
    if existing is None:
        _abort(
            warning or "저장된 해설이 없습니다. 먼저 --assessment-only 없이 실행해 주십시오",
            EXIT_USAGE,
        )
    if not existing.explanations:
        _abort("저장된 룰별 해설이 없어 종합 평가를 만들 수 없습니다", EXIT_USAGE)
    try:
        provider = make_provider(settings.llm)
        estimate = estimate_assessment(audit, existing.explanations, provider)
    except LLMError as exc:
        _abort(str(exc), EXIT_USAGE)
    except MaskingError as exc:
        _abort(str(exc), EXIT_LLM)
    typer.echo(
        f"종합 평가 대상: 룰 {estimate.rules}개, finding {estimate.findings}건 "
        f"(모델 {provider.model}, effort {settings.llm.effort})"
    )
    typer.echo(f"입력 토큰: {estimate.input_tokens:,} (마스킹한 프롬프트 기준)")
    if estimate.cost_usd is not None:
        typer.echo(
            f"예상 비용: 약 ${estimate.cost_usd:.2f} "
            f"(출력 {estimate.assumed_output_tokens:,} 토큰 가정)"
        )
    if dry_run:
        return
    if not yes and not typer.confirm("종합 평가를 요청하시겠습니까?"):
        typer.echo("취소했습니다.")
        return
    result = reassess_report(audit, existing, provider)
    path = write_report(result, default_explanations_path(store, result.account_id, result.scan_id))
    if result.assessment is None:
        typer.echo(f"경고: 종합 평가 실패: {result.assessment_failure}", err=True)
    else:
        status = "검증됨" if result.assessment.verified else "검증되지 않음"
        typer.echo(
            f"종합 평가: {status} (시나리오 {len(result.assessment.assessment.scenarios)}개)"
        )
    typer.echo(f"해설 파일: {path}")
    if report:
        _reports(store, findings, report)
    if result.assessment is None:
        raise typer.Exit(EXIT_LLM)


def run() -> None:
    """콘솔 스크립트 진입점. 최상위 `--help`도 UTF-8로 나가도록 출력 설정을 먼저 한다."""
    _configure_output()
    app()


@app.command("investigate")
def investigate_command(
    findings: Path | None = typer.Option(
        None, "--findings", help="조사할 판정 결과 파일. 없으면 가장 최근에 판정한 결과."
    ),
    profile: str | None = ProfileOption,
    region: str | None = RegionOption,
    account_id: str | None = AccountOption,
    store: Path | None = StoreOption,
    config: Path | None = ConfigOption,
    dry_run: bool = typer.Option(
        False, "--dry-run", help="조사하지 않고 대상과 최대 비용만 보여줍니다."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="비용 확인 없이 진행합니다."),
    max_calls: int = typer.Option(
        DEFAULT_MAX_CALLS, "--max-calls", min=1, help="룰 하나의 도구 호출 상한."
    ),
    max_tokens: int = typer.Option(
        DEFAULT_MAX_TOTAL_TOKENS, "--max-tokens", min=10_000, help="룰 하나의 토큰 상한(입력+출력)."
    ),
    report: list[ReportFormat] | None = typer.Option(
        None,
        "--report",
        help="조사 후 이 형식의 보고서도 다시 만듭니다 (md, xlsx, json, evidence).",
    ),
) -> None:
    """취약·검토 필요 결과를 에이전트가 읽기 전용 도구로 추가 조사합니다. 판정은 바꾸지 않습니다.

    AWS는 읽기 전용 가드가 걸린 점검 세션으로만 조회하고, LLM에는 식별정보를 가린 값만 보냅니다.
    """
    settings = _settings(config)
    snapshot_store = SnapshotStore(store)
    findings = _findings_path(snapshot_store, findings, account_id)
    audit = _audit_report(snapshot_store, findings)
    groups = investigation_groups(audit)
    if not groups:
        typer.echo("취약·검토 필요 결과가 없어 조사할 것이 없습니다.")
        return
    typer.echo(
        f"조사 대상: 룰 {len(groups)}개, finding {sum(len(g.findings) for g in groups)}건 "
        f"(모델 {settings.llm.model}, effort {settings.llm.effort})"
    )
    typer.echo(f"룰당 상한: 도구 호출 {max_calls}회, 토큰 {max_tokens:,}")
    price = PRICES.get(settings.llm.model)
    if price is not None:
        ceiling = len(groups) * max_tokens * price.input_per_mtok / 1_000_000
        typer.echo(
            f"최대 비용: 약 ${ceiling:.2f} (토큰 상한을 모두 입력 단가로 계산, 보통 이보다 적음)"
        )
    if dry_run:
        return
    if not yes and not typer.confirm("추가 조사를 요청하시겠습니까?"):
        typer.echo("취소했습니다.")
        return

    # 판정 결과와 같은 계정·리전 범위로 읽기 전용 점검 세션을 연다
    scan = _open(profile, region, list(audit.scan.regions), audit.scan.account_id)
    try:
        provider = make_agent_provider(settings.llm)
    except LLMError as exc:
        _abort(str(exc), EXIT_USAGE)
    try:
        result = investigate_report(
            audit,
            provider,
            ToolContext(scan),
            effort=settings.llm.effort,
            max_calls=max_calls,
            max_iterations=DEFAULT_MAX_ITERATIONS,
            max_total_tokens=max_tokens,
            on_progress=lambda rule_id: typer.echo(f"  조사 {rule_id}"),
        )
    except ReadOnlyViolation as exc:
        _abort(f"읽기 전용 가드가 호출을 차단해 조사를 중단했습니다: {exc}", EXIT_SESSION)
    path = write_report(
        result, default_investigations_path(snapshot_store, result.account_id, result.scan_id)
    )
    verified = sum(1 for i in result.investigations if i.verified)
    calls = sum(len(i.tool_calls) for i in result.investigations)
    typer.echo(
        f"조사: 근거 검증됨 {verified}, 검증되지 않음 {len(result.investigations) - verified}, "
        f"실패 {len(result.failures)}, 도구 호출 {calls}회"
    )
    for failure in result.failures:
        typer.echo(f"경고: {failure.rule_id} 조사 실패: {failure.error}", err=True)
    cost = (
        f", 비용 약 ${result.estimated_cost_usd:.2f}"
        if result.estimated_cost_usd is not None
        else ""
    )
    typer.echo(
        f"토큰: 입력 {result.usage.input_tokens:,}, 출력 {result.usage.output_tokens:,}{cost}"
    )
    typer.echo(f"조사 파일: {path}")
    if report:
        _reports(snapshot_store, findings, report)
    if not result.investigations:
        raise typer.Exit(EXIT_LLM)


@app.command("review-evidence")
def review_evidence_command(
    evidence_dir: Path = typer.Option(
        ...,
        "--dir",
        help="증적 폴더. 요청 ID 폴더(예: CA-02-1) 아래에 제출 파일을 둡니다.",
    ),
    terms: Path | None = typer.Option(
        None,
        "--terms",
        help="마스킹 사전 (UTF-8, 한 줄에 하나). 직원 이름 등 LLM에 보내지 않을 용어.",
    ),
    findings: Path | None = typer.Option(
        None, "--findings", help="증적을 요청한 판정 결과 파일. 없으면 가장 최근에 판정한 결과."
    ),
    account_id: str | None = AccountOption,
    store: Path | None = StoreOption,
    config: Path | None = ConfigOption,
    dry_run: bool = typer.Option(
        False, "--dry-run", help="검토를 요청하지 않고 미리보기 파일과 예상 비용만 만듭니다."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="미리보기·비용 확인 없이 진행합니다."),
    report: list[ReportFormat] | None = typer.Option(
        None,
        "--report",
        help="검토 후 이 형식의 보고서도 다시 만듭니다 (md, xlsx, json, evidence).",
    ),
) -> None:
    """제출된 증적 문서를 요청별로 LLM이 검토합니다. 판정·항목 결과는 바꾸지 않습니다.

    PDF·xlsx·텍스트 파일에서 뽑은 텍스트만 보내며, 원본 파일은 보내지 않습니다.

    식별정보(계정 ID·IP·ARN·리소스 이름)와 개인정보, 마스킹 사전의 용어를 가린 뒤 보냅니다.
    보내기 전에 마스킹한 내용을 미리보기 파일로 확인해 주십시오.
    """
    settings = _settings(config)
    snapshot_store = SnapshotStore(store)
    findings = _findings_path(snapshot_store, findings, account_id)
    audit = _audit_report(snapshot_store, findings)
    catalog = load_mappings().evidence
    try:
        lookup = SourceLookup(load_index())
        dictionary = load_terms(terms) if terms is not None else ()
        submission = load_submission(
            evidence_dir, [r.id for item in catalog.values() for r in item.requests]
        )
    except (SourceIndexError, MaskingError, EvidenceFolderError) as exc:
        _abort(str(exc), EXIT_USAGE)

    for ignored in submission.ignored:
        typer.echo(f"경고: 요청 ID 폴더가 아니어서 읽지 않음: {ignored}", err=True)
    for file in submission.files:
        if file.problem:
            typer.echo(f"사람이 검토할 파일: {file.path} ({file.problem})")
    if terms is None:
        typer.echo(
            "경고: 마스킹 사전이 없습니다. 직원 이름 등은 가려지지 않을 수 있으니 "
            "--terms로 사전을 지정해 주십시오",
            err=True,
        )
    try:
        provider = make_provider(settings.llm)
        estimate = estimate_review(audit, submission, catalog, provider, lookup, terms=dictionary)
    except LLMError as exc:
        _abort(str(exc), EXIT_USAGE)
    if estimate.blocked:
        typer.echo(
            f"경고: 마스킹 검증에 실패해 보내지 않을 요청: {', '.join(estimate.blocked)}", err=True
        )
    if not estimate.requests:
        typer.echo("텍스트를 읽을 수 있는 제출 문서가 없어 검토할 것이 없습니다.")
        return
    preview_path = default_evidence_preview_path(
        snapshot_store, audit.scan.account_id, audit.scan.scan_id
    )
    preview_path.parent.mkdir(parents=True, exist_ok=True)
    preview_path.write_text(
        render_preview(audit, submission, catalog, lookup, terms=dictionary), encoding="utf-8"
    )
    masked = ", ".join(f"{kind} {count}" for kind, count in estimate.masked.items())
    typer.echo(
        f"검토 대상: 요청 {estimate.requests}개, 문서 {estimate.documents}개 "
        f"(모델 {provider.model}, effort {settings.llm.effort})"
    )
    typer.echo(f"가린 값: {masked or '없음'}")
    typer.echo(f"전송 미리보기: {preview_path}")
    typer.echo(f"입력 토큰: {estimate.input_tokens:,} (마스킹한 프롬프트 기준)")
    if estimate.cost_usd is None:
        typer.echo("예상 비용: 단가를 모르는 모델")
    else:
        typer.echo(
            f"예상 비용: 약 ${estimate.cost_usd:.2f} "
            f"(출력 요청당 {estimate.assumed_output_tokens // estimate.requests:,} 토큰 가정, "
            "재시도 제외)"
        )
    if dry_run:
        return
    if not yes and not typer.confirm(
        "미리보기에서 가려지지 않은 이름·연락처가 없음을 확인하셨습니까? 검토를 요청하시겠습니까?"
    ):
        typer.echo("취소했습니다.")
        return

    result = review_submission(
        audit,
        submission,
        catalog,
        provider,
        lookup,
        terms=dictionary,
        effort=settings.llm.effort,
        on_progress=lambda request_id: typer.echo(f"  검토 {request_id}"),
    )
    path = write_report(
        result, default_evidence_review_path(snapshot_store, result.account_id, result.scan_id)
    )
    verified = sum(1 for r in result.reviews if r.verified)
    typer.echo(
        f"검토: 발췌 검증됨 {verified}, 검증되지 않음 {len(result.reviews) - verified}, "
        f"실패 {len(result.failures)}, 사람이 검토할 파일 {len(result.unreadable)}개"
    )
    for failure in result.failures:
        typer.echo(f"경고: {failure.request_id} 검토 실패: {failure.error}", err=True)
    cost = (
        f", 비용 약 ${result.estimated_cost_usd:.2f}"
        if result.estimated_cost_usd is not None
        else ""
    )
    typer.echo(
        f"토큰: 입력 {result.usage.input_tokens:,}, 출력 {result.usage.output_tokens:,}{cost}"
    )
    typer.echo(f"검토 파일: {path}")
    if report:
        _reports(snapshot_store, findings, report)
    if not result.reviews:
        raise typer.Exit(EXIT_LLM)


@app.command("mcp")
def mcp_command(
    findings: Path | None = typer.Option(
        None, "--findings", help="노출할 판정 결과 파일. 없으면 가장 최근에 판정한 결과."
    ),
    profile: str | None = ProfileOption,
    region: str | None = RegionOption,
    account_id: str | None = AccountOption,
    store: Path | None = StoreOption,
    max_calls: int = typer.Option(
        DEFAULT_MCP_MAX_CALLS, "--max-calls", min=1, help="세션 하나의 AWS 조사 도구 호출 상한."
    ),
) -> None:
    """판정 결과와 읽기 전용 조사 도구를 MCP 서버(stdio)로 노출합니다.

    MCP 클라이언트(Claude Code 등)가 이 명령을 실행합니다. 식별정보는 가린 값만 내보내고,
    AWS는 판정 결과와 같은 계정의 읽기 전용 점검 세션으로만 조회합니다. 표준 출력은 MCP
    통신에 쓰므로 안내 메시지는 표준 오류로 출력합니다.
    """
    snapshot_store = SnapshotStore(store)
    findings = _findings_path(snapshot_store, findings, account_id, err=True)
    audit = _audit_report(snapshot_store, findings)
    try:
        scan = open_scan(
            profile=profile,
            region=region,
            regions=list(audit.scan.regions),
            expected_account_id=audit.scan.account_id,
        )
    except SessionError as exc:
        _abort(str(exc), EXIT_SESSION)
    log_path = default_log_path(snapshot_store.root, audit)
    typer.echo(f"MCP 서버: 계정 {scan.account_id}, 점검 {audit.scan.scan_id}", err=True)
    typer.echo(f"호출 로그: {log_path}", err=True)
    session = McpSession(audit, ToolContext(scan), log_path, max_calls=max_calls)
    serve_stdio(build_server(session))
