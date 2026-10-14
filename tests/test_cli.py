"""CLI 테스트. moto와 임시 AWS 설정 파일만 쓴다 (tests/conftest.py)."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import boto3
import pytest
from moto import mock_aws
from typer.testing import CliRunner

from kompass.cli import EXIT_FAIL_ON, EXIT_LLM, EXIT_SESSION, EXIT_SNAPSHOT, EXIT_USAGE, app
from kompass.interpreter.llm import LLMError
from kompass.interpreter.sources import INDEX_ENV
from kompass.mappings.data import load_mappings
from kompass.models import ExplanationReport, SourceEntry, SourceIndex
from tests.conftest import AwsFiles
from tests.interpreter.fakes import FakeProvider, cite_first_source

runner = CliRunner()
REGION = "ap-northeast-2"


@pytest.fixture
def aws(isolated_aws_env: AwsFiles) -> Iterator[None]:
    isolated_aws_env.config.write_text(f"[profile audit]\nregion = {REGION}\n", encoding="utf-8")
    isolated_aws_env.credentials.write_text(
        "[audit]\naws_access_key_id = testing\naws_secret_access_key = testing\n", encoding="utf-8"
    )
    with mock_aws():
        yield


@pytest.fixture
def store(tmp_path: Path) -> Path:
    return tmp_path / ".kompass"


@pytest.fixture(autouse=True)
def no_default_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 현재 디렉터리의 kompass.yaml이 테스트에 섞이지 않게 한다
    monkeypatch.chdir(tmp_path)


def _open_ssh_group() -> None:
    ec2 = boto3.client("ec2", region_name=REGION)
    group = ec2.create_security_group(GroupName="open-ssh", Description="d")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group, IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0"
    )


def _scan_args(store: Path, *extra: str) -> list[str]:
    return [
        "scan",
        "--profile", "audit",
        "--regions", REGION,
        "--service", "ec2",
        "--service", "cloudtrail",
        "--store", str(store),
        *extra,
    ]  # fmt: skip


# --- 기본 ---


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("collect", "evaluate", "scan"):
        assert command in result.output


def test_version_prints_package_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.startswith("kompass ")


# --- scan ---


def test_scan_writes_findings_and_summary(aws: None, store: Path) -> None:
    result = runner.invoke(app, _scan_args(store))
    assert result.exit_code == 0, result.output
    assert "점검 계정: 123456789012" in result.output
    assert "호출자: arn:aws:sts::123456789012:" in result.output
    assert "수집 ec2: 수집 실패 0건" in result.output
    assert "SG-001" in result.output
    assert "건너뛴 룰" in result.output  # s3·iam을 수집하지 않았으므로
    [findings] = (store / "findings" / "123456789012").glob("*.findings.json")
    report = json.loads(findings.read_text(encoding="utf-8"))
    assert report["account_id"] == "123456789012"
    assert {f["rule_id"] for f in report["findings"]} >= {"CT-001", "SG-001", "VPC-001"}


def test_fail_findings_exit_zero_by_default(aws: None, store: Path) -> None:
    _open_ssh_group()
    assert runner.invoke(app, _scan_args(store)).exit_code == 0


def test_fail_on_fail_exits_one(aws: None, store: Path) -> None:
    _open_ssh_group()
    result = runner.invoke(app, _scan_args(store, "--fail-on", "fail"))
    assert result.exit_code == EXIT_FAIL_ON


def test_regions_accept_commas(aws: None, store: Path) -> None:
    result = runner.invoke(
        app,
        ["collect", "--profile", "audit", "--regions", f"{REGION},us-east-1",
         "--service", "ec2", "--store", str(store)],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "점검 리전: 2개" in result.output


def test_custom_output_path(aws: None, store: Path, tmp_path: Path) -> None:
    output = tmp_path / "out" / "result.findings.json"
    result = runner.invoke(app, _scan_args(store, "--output", str(output)))
    assert result.exit_code == 0, result.output
    assert output.is_file()


# --- collect + evaluate ---


def test_evaluate_latest_scan(aws: None, store: Path) -> None:
    collected = runner.invoke(
        app, ["collect", "--profile", "audit", "--regions", REGION, "--service", "ec2",
              "--store", str(store)],
    )  # fmt: skip
    assert collected.exit_code == 0, collected.output
    result = runner.invoke(app, ["evaluate", "--store", str(store)])
    assert result.exit_code == 0, result.output
    assert "점검: " in result.output
    assert "판정 기준: 기본값" in result.output


def test_evaluate_uses_config_file(aws: None, store: Path, tmp_path: Path) -> None:
    config = tmp_path / "kompass.yaml"
    config.write_text("ec2:\n  admin_ports: [2222]\n", encoding="utf-8")
    result = runner.invoke(app, _scan_args(store))
    assert result.exit_code == 0
    assert "판정 기준: kompass.yaml" in result.output  # 현재 디렉터리의 kompass.yaml
    [findings] = (store / "findings" / "123456789012").glob("*.findings.json")
    report = json.loads(findings.read_text(encoding="utf-8"))
    assert report["settings"]["ec2"]["admin_ports"] == [2222]


# --- 오류 ---


def test_unknown_profile_is_session_error(aws: None, store: Path) -> None:
    result = runner.invoke(app, ["collect", "--profile", "nope", "--store", str(store)])
    assert result.exit_code == EXIT_SESSION
    assert "nope" in result.output


def test_account_mismatch_is_session_error(aws: None, store: Path) -> None:
    result = runner.invoke(
        app,
        ["collect", "--profile", "audit", "--account-id", "999999999999", "--store", str(store)],
    )
    assert result.exit_code == EXIT_SESSION


def test_bad_config_stops_before_aws(store: Path, tmp_path: Path) -> None:
    # aws 픽스처 없이도 실패해야 한다: 설정 오류는 AWS 호출 전에 드러난다
    config = tmp_path / "bad.yaml"
    config.write_text("ec2:\n  admin_port: [22]\n", encoding="utf-8")
    result = runner.invoke(app, _scan_args(store, "--config", str(config)))
    assert result.exit_code == EXIT_USAGE
    assert "admin_port" in result.output


def test_unknown_service_is_usage_error(aws: None, store: Path) -> None:
    result = runner.invoke(
        app, ["collect", "--profile", "audit", "--service", "rds", "--store", str(store)]
    )
    assert result.exit_code == EXIT_USAGE


def test_evaluate_without_scans(store: Path) -> None:
    result = runner.invoke(app, ["evaluate", "--store", str(store)])
    assert result.exit_code == EXIT_SNAPSHOT


def test_evaluate_incomplete_scan(store: Path) -> None:
    incomplete = store / "snapshots" / "123456789012" / "20261014T000000Z-abcd"
    incomplete.mkdir(parents=True)
    result = runner.invoke(app, ["evaluate", "--scan", str(incomplete), "--store", str(store)])
    assert result.exit_code == EXIT_SNAPSHOT


# --- report ---


def test_scan_with_reports(aws: None, store: Path) -> None:
    result = runner.invoke(app, _scan_args(store, "--report", "md", "--report", "xlsx"))
    assert result.exit_code == 0, result.output
    reports = store / "123456789012"
    assert len(list(reports.glob("*.md"))) == 1
    assert len(list(reports.glob("*.xlsx"))) == 1
    md = next(reports.glob("*.md")).read_text(encoding="utf-8")
    assert "## KISA 항목별 결과" in md


def test_report_from_latest_findings(aws: None, store: Path) -> None:
    assert runner.invoke(app, _scan_args(store)).exit_code == 0
    result = runner.invoke(app, ["report", "--store", str(store), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert "판정 결과: " in result.output
    [report] = (store / "123456789012").glob("*.report.json")
    data = json.loads(report.read_text(encoding="utf-8"))
    assert len(data["kisa_items"]) == 19


def test_report_defaults_to_md_and_xlsx(aws: None, store: Path) -> None:
    assert runner.invoke(app, _scan_args(store)).exit_code == 0
    assert runner.invoke(app, ["report", "--store", str(store)]).exit_code == 0
    suffixes = sorted(p.suffix for p in (store / "123456789012").iterdir())
    assert suffixes == [".md", ".xlsx"]


def test_report_without_findings(store: Path) -> None:
    result = runner.invoke(app, ["report", "--store", str(store)])
    assert result.exit_code == EXIT_SNAPSHOT


def test_report_refuses_tampered_snapshot(aws: None, store: Path) -> None:
    # 증적(스냅샷)이 판정 후 바뀌었으면 보고서를 만들지 않는다
    assert runner.invoke(app, _scan_args(store)).exit_code == 0
    [snapshot] = (store / "snapshots" / "123456789012").glob("*/ec2.json")
    snapshot.write_text(snapshot.read_text(encoding="utf-8") + " ", encoding="utf-8")
    result = runner.invoke(app, ["report", "--store", str(store)])
    assert result.exit_code == EXIT_SNAPSHOT


def test_unknown_report_format_is_usage_error(aws: None, store: Path) -> None:
    result = runner.invoke(app, ["report", "--store", str(store), "--format", "pdf"])
    assert result.exit_code == EXIT_USAGE


# --- explain ---


@pytest.fixture
def source_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    mappings = load_mappings()
    index = SourceIndex(
        built_at=datetime(2026, 10, 14, tzinfo=UTC),
        documents={},
        kisa={
            code: SourceEntry(title=item.title, page=1, text=f"KISA {code} 원문 구절이다.")
            for code, item in mappings.kisa_items.items()
        },
        isms_p={
            code: SourceEntry(title=name, page=1, text=f"ISMS-P {code} 원문 구절이다.")
            for code, name in mappings.isms_p_controls.items()
        },
    )
    path = tmp_path / "index.json"
    path.write_text(index.model_dump_json(), encoding="utf-8")
    monkeypatch.setenv(INDEX_ENV, str(path))
    return path


@pytest.fixture
def fake_llm(monkeypatch: pytest.MonkeyPatch) -> FakeProvider:
    provider = FakeProvider(cite_first_source)
    monkeypatch.setattr("kompass.cli.make_provider", lambda settings: provider)
    return provider


def _scanned(store: Path) -> None:
    _open_ssh_group()
    assert runner.invoke(app, _scan_args(store)).exit_code == 0


def test_explain_dry_run_sends_no_explanation_request(
    aws: None, store: Path, source_index: Path, fake_llm: FakeProvider
) -> None:
    _scanned(store)
    result = runner.invoke(app, ["explain", "--store", str(store), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "해설 대상: 룰" in result.output and "입력 토큰" in result.output
    assert fake_llm.calls == [] and fake_llm.count_calls > 0
    assert not (store / "explanations").exists()


def test_explain_writes_file_and_reports(
    aws: None, store: Path, source_index: Path, fake_llm: FakeProvider
) -> None:
    _scanned(store)
    result = runner.invoke(app, ["explain", "--store", str(store), "--yes", "--report", "md"])
    assert result.exit_code == 0, result.output
    assert "해설 SG-001" in result.output and "검증됨" in result.output
    [path] = (store / "explanations").rglob("*.explanations.json")
    explained = ExplanationReport.model_validate_json(path.read_text(encoding="utf-8"))
    assert {e.rule_id for e in explained.explanations} >= {"SG-001"}
    assert all(e.verified for e in explained.explanations)
    [md] = store.rglob("*.md")
    assert "## AI 해설 (참고)" in md.read_text(encoding="utf-8")


def test_explain_asks_before_spending(
    aws: None, store: Path, source_index: Path, fake_llm: FakeProvider
) -> None:
    _scanned(store)
    result = runner.invoke(app, ["explain", "--store", str(store)], input="n\n")
    assert result.exit_code == 0
    assert "취소했습니다" in result.output and fake_llm.calls == []


def test_report_attaches_existing_explanations(
    aws: None, store: Path, source_index: Path, fake_llm: FakeProvider
) -> None:
    _scanned(store)
    assert runner.invoke(app, ["explain", "--store", str(store), "--yes"]).exit_code == 0
    result = runner.invoke(app, ["report", "--store", str(store), "--format", "md"])
    assert result.exit_code == 0
    [md] = store.rglob("*.md")
    assert "## AI 해설 (참고)" in md.read_text(encoding="utf-8")


def test_report_warns_about_stale_explanations(
    aws: None, store: Path, source_index: Path, fake_llm: FakeProvider
) -> None:
    _scanned(store)
    assert runner.invoke(app, ["explain", "--store", str(store), "--yes"]).exit_code == 0
    [scan_dir] = (store / "snapshots").glob("*/*")
    evaluate = ["evaluate", "--store", str(store), "--scan", str(scan_dir)]
    assert runner.invoke(app, evaluate).exit_code == 0  # 다시 판정
    result = runner.invoke(app, ["report", "--store", str(store), "--format", "md"])
    assert result.exit_code == 0
    assert "kompass explain을 다시 실행해 주십시오" in result.output
    [md] = store.rglob("*.md")
    assert "## AI 해설" not in md.read_text(encoding="utf-8")


def test_explain_all_failed_exit_code(
    aws: None, store: Path, source_index: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scanned(store)
    provider = FakeProvider(lambda payload, attempt: LLMError("인증 실패"))
    monkeypatch.setattr("kompass.cli.make_provider", lambda settings: provider)
    result = runner.invoke(app, ["explain", "--store", str(store), "--yes"])
    assert result.exit_code == EXIT_LLM
    assert "인증 실패" in result.output


def test_explain_without_index_is_usage_error(
    aws: None, store: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeProvider
) -> None:
    _scanned(store)
    monkeypatch.setenv(INDEX_ENV, str(tmp_path / "missing.json"))
    result = runner.invoke(app, ["explain", "--store", str(store), "--yes"])
    assert result.exit_code == EXIT_USAGE
    assert "build_source_index" in result.output


def test_explain_without_api_key_is_usage_error(
    aws: None, store: Path, source_index: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scanned(store)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    result = runner.invoke(app, ["explain", "--store", str(store), "--yes"])
    assert result.exit_code == EXIT_USAGE
    assert "ANTHROPIC_API_KEY" in result.output


def test_explain_includes_assessment_by_default(
    aws: None, store: Path, source_index: Path, fake_llm: FakeProvider
) -> None:
    _scanned(store)
    result = runner.invoke(app, ["explain", "--store", str(store), "--yes", "--report", "md"])
    assert result.exit_code == 0, result.output
    assert "종합 평가: 검증됨" in result.output and len(fake_llm.assessment_calls) == 1
    [md] = store.rglob("*.md")
    assert "### 종합 위험 평가 — 참조 검증됨" in md.read_text(encoding="utf-8")


def test_explain_without_assessment(
    aws: None, store: Path, source_index: Path, fake_llm: FakeProvider
) -> None:
    _scanned(store)
    result = runner.invoke(app, ["explain", "--store", str(store), "--yes", "--no-assessment"])
    assert result.exit_code == 0, result.output
    assert fake_llm.assessment_calls == [] and "종합 평가" not in result.output


def test_assessment_only_reuses_saved_explanations(
    aws: None, store: Path, source_index: Path, fake_llm: FakeProvider
) -> None:
    _scanned(store)
    args = ["explain", "--store", str(store), "--yes"]
    assert runner.invoke(app, [*args, "--no-assessment"]).exit_code == 0
    explained_calls = len(fake_llm.calls)
    result = runner.invoke(app, [*args, "--assessment-only", "--report", "md"])
    assert result.exit_code == 0, result.output
    assert len(fake_llm.calls) == explained_calls  # 룰별 해설은 다시 요청하지 않는다
    assert len(fake_llm.assessment_calls) == 1 and "종합 평가: 검증됨" in result.output
    [path] = (store / "explanations").rglob("*.explanations.json")
    saved = ExplanationReport.model_validate_json(path.read_text(encoding="utf-8"))
    assert saved.assessment is not None and saved.explanations
    [md] = store.rglob("*.md")
    assert "### 종합 위험 평가" in md.read_text(encoding="utf-8")


def test_assessment_only_needs_saved_explanations(
    aws: None, store: Path, source_index: Path, fake_llm: FakeProvider
) -> None:
    _scanned(store)
    result = runner.invoke(app, ["explain", "--store", str(store), "--yes", "--assessment-only"])
    assert result.exit_code == EXIT_USAGE
    assert "저장된 해설이 없습니다" in result.output and fake_llm.assessment_calls == []


def test_assessment_only_conflicts_with_no_assessment(store: Path) -> None:
    result = runner.invoke(
        app, ["explain", "--store", str(store), "--assessment-only", "--no-assessment"]
    )
    assert result.exit_code == EXIT_USAGE and "함께 쓸 수 없습니다" in result.output
