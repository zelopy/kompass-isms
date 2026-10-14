"""실행 흐름(collect → evaluate → 결과 파일)과 설정 파일 로드 테스트. moto만 쓴다."""

from collections.abc import Iterator
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from kompass.aws.guard import read_only_session
from kompass.aws.session import ScanContext
from kompass.collectors.iam import IamCollector
from kompass.config import ConfigError, Settings, load_settings
from kompass.models import EvaluationReport, Finding, Severity, Status
from kompass.pipeline import (
    COLLECTORS,
    collect,
    default_findings_path,
    evaluate_scan,
    exceeds,
    write_report,
)
from kompass.snapshots import SnapshotStore

ACCOUNT = "123456789012"
HOME = "ap-northeast-2"


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


def _scan() -> ScanContext:
    return ScanContext(
        session=read_only_session(),
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region=HOME,
        regions=(HOME,),
        enabled_regions=(HOME,),
    )


@pytest.fixture
def store(tmp_path: Path) -> SnapshotStore:
    return SnapshotStore(tmp_path / ".kompass")


# --- collect → evaluate ---


def test_collect_and_evaluate_selected_services(aws: None, store: SnapshotStore) -> None:
    boto3.client("ec2", region_name=HOME)  # 기본 VPC·SG는 moto가 만든다
    seen: list[str] = []
    result = collect(_scan(), store, ["ec2"], on_service=lambda s, _: seen.append(s))
    assert seen == ["ec2"]
    assert result.errors_by_service == {"ec2": 0}

    manifest, report = evaluate_scan(result.scan_path, Settings())
    assert manifest.scan_id == report.scan_id
    assert report.account_id == ACCOUNT
    assert {f.rule_id for f in report.findings} >= {"SG-001", "VPC-001"}
    assert "CT-001" in report.skipped_rules  # 수집하지 않은 서비스는 PASS가 아니라 건너뜀
    assert report.settings["ec2"]["admin_ports"] == [22, 3389]
    assert "llm" not in report.settings  # LLM 설정은 판정 기준값이 아니다


def test_collect_all_services_by_default(
    aws: None, store: SnapshotStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 자격증명 보고서 생성 대기를 테스트에서 실제로 기다리지 않는다
    monkeypatch.setitem(COLLECTORS, "iam", lambda: IamCollector(sleep=lambda _: None))
    result = collect(_scan(), store)
    _, report = evaluate_scan(result.scan_path, Settings())
    assert set(result.errors_by_service) == {"cloudtrail", "ec2", "iam", "s3"}
    assert report.skipped_rules == ()


def test_unknown_service_rejected(aws: None, store: SnapshotStore) -> None:
    with pytest.raises(ValueError, match="rds"):
        collect(_scan(), store, ["rds"])


def test_report_round_trips(aws: None, store: SnapshotStore) -> None:
    result = collect(_scan(), store, ["ec2"])
    _, report = evaluate_scan(result.scan_path, Settings())
    path = write_report(report, default_findings_path(store, report))
    assert path == store.root / "findings" / ACCOUNT / f"{report.scan_id}.findings.json"
    assert EvaluationReport.model_validate_json(path.read_text(encoding="utf-8")) == report
    assert not list(path.parent.glob("*.tmp"))


# --- --fail-on ---


def _report(*statuses: Status) -> EvaluationReport:
    findings = tuple(
        Finding(
            rule_id="SG-001",
            resource=f"sg-{i}",
            region=HOME,
            status=status,
            severity=Severity.HIGH,
            message="m",
            evidence={},
            collected_at="2026-10-14T00:00:00Z",  # type: ignore[arg-type]
        )
        for i, status in enumerate(statuses)
    )
    return EvaluationReport(
        scan_id="s",
        account_id=ACCOUNT,
        kompass_version="0.1.0",
        evaluated_at="2026-10-14T00:00:00Z",  # type: ignore[arg-type]
        settings={},
        skipped_rules=(),
        findings=findings,
    )


@pytest.mark.parametrize(
    ("statuses", "fail_on", "expected"),
    [
        ((Status.FAIL,), None, False),
        ((Status.FAIL,), "fail", True),
        ((Status.ERROR,), "fail", False),
        ((Status.ERROR,), "error", True),
        ((Status.REVIEW,), "error", False),
        ((Status.REVIEW,), "review", True),
        ((Status.PASS, Status.NOT_APPLICABLE), "review", False),
    ],
)
def test_exceeds(statuses: tuple[Status, ...], fail_on: str | None, expected: bool) -> None:
    assert exceeds(_report(*statuses), fail_on) is expected


# --- 설정 파일 ---


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "kompass.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_settings_default_when_no_file() -> None:
    assert load_settings(None) == Settings()


def test_load_settings_from_yaml(tmp_path: Path) -> None:
    path = _write(tmp_path, "ec2:\n  admin_ports: [22, 2222]\ns3:\n  require_kms: true\n")
    settings = load_settings(path)
    assert settings.ec2.admin_ports == (22, 2222)
    assert settings.s3.require_kms is True
    assert settings.iam == Settings().iam


def test_load_settings_empty_file(tmp_path: Path) -> None:
    assert load_settings(_write(tmp_path, "")) == Settings()


@pytest.mark.parametrize(
    "text",
    [
        "ec2:\n  admin_port: [22]\n",  # 오타 (정의되지 않은 키)
        "- just\n- a list\n",  # 최상위가 키-값이 아님
        "ec2: [unclosed\n",  # YAML 문법 오류
        "iam:\n  unused_credential_days: soon\n",  # 잘못된 값
    ],
)
def test_load_settings_rejects_bad_files(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(_write(tmp_path, text))


def test_load_settings_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "absent.yaml")
