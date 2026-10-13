"""CLI 테스트. moto와 임시 AWS 설정 파일만 쓴다 (tests/conftest.py)."""

import json
from collections.abc import Iterator
from pathlib import Path

import boto3
import pytest
from moto import mock_aws
from typer.testing import CliRunner

from kompass.cli import EXIT_FAIL_ON, EXIT_SESSION, EXIT_SNAPSHOT, EXIT_USAGE, app
from tests.conftest import AwsFiles

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
