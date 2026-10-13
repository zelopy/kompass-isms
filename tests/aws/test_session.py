"""점검 세션 생성 테스트. moto와 임시 AWS 설정 파일만 쓴다 (tests/conftest.py)."""

from collections.abc import Iterator
from typing import Any

import pytest
from moto import mock_aws

from kompass.aws.guard import ReadOnlyViolation
from kompass.aws.session import (
    SessionError,
    enabled_regions,
    open_scan,
    select_regions,
)
from tests.conftest import AwsFiles

MOTO_ACCOUNT = "123456789012"


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


def _write_profiles(files: AwsFiles, config: str, credentials: str = "") -> None:
    files.config.write_text(config, encoding="utf-8")
    files.credentials.write_text(credentials, encoding="utf-8")


@pytest.fixture
def audit_profile(isolated_aws_env: AwsFiles) -> str:
    _write_profiles(
        isolated_aws_env,
        config="[profile audit]\nregion = ap-northeast-2\n",
        credentials="[audit]\naws_access_key_id = testing\naws_secret_access_key = testing\n",
    )
    return "audit"


# --- enabled_regions: DescribeRegions 응답 해석 (moto는 opt-in 상태를 구분하지 않는다) ---


def test_enabled_regions_excludes_not_opted_in() -> None:
    response = {
        "Regions": [
            {"RegionName": "ap-northeast-2", "OptInStatus": "opt-in-not-required"},
            {"RegionName": "ap-east-1", "OptInStatus": "opted-in"},
            {"RegionName": "me-south-1", "OptInStatus": "not-opted-in"},
        ]
    }
    known, enabled = enabled_regions(response)
    assert known == {"ap-northeast-2", "ap-east-1", "me-south-1"}
    assert enabled == {"ap-northeast-2", "ap-east-1"}


# --- select_regions ---

KNOWN = {"ap-northeast-2", "us-east-1", "me-south-1"}
ENABLED = {"ap-northeast-2", "us-east-1"}


def test_select_all_enabled_when_not_requested() -> None:
    assert select_regions(KNOWN, ENABLED, None) == ("ap-northeast-2", "us-east-1")


def test_select_requested_keeps_order_and_dedupes() -> None:
    requested = ["us-east-1", "ap-northeast-2", "us-east-1"]
    assert select_regions(KNOWN, ENABLED, requested) == ("us-east-1", "ap-northeast-2")


def test_select_rejects_unknown_region() -> None:
    with pytest.raises(SessionError, match="ap-northeast-02"):
        select_regions(KNOWN, ENABLED, ["ap-northeast-02"])


def test_select_rejects_not_enabled_region() -> None:
    with pytest.raises(SessionError, match="me-south-1"):
        select_regions(KNOWN, ENABLED, ["me-south-1"])


def test_select_rejects_empty_request() -> None:
    with pytest.raises(SessionError):
        select_regions(KNOWN, ENABLED, [])


# --- open_scan ---


def test_open_scan_with_access_key_profile(aws: None, audit_profile: str) -> None:
    scan = open_scan(profile=audit_profile)
    assert scan.account_id == MOTO_ACCOUNT
    assert scan.partition == "aws"
    assert scan.home_region == "ap-northeast-2"
    assert scan.caller_arn.startswith(f"arn:aws:sts::{MOTO_ACCOUNT}:")
    assert "ap-northeast-2" in scan.regions
    assert list(scan.regions) == sorted(scan.regions)


def test_open_scan_limits_regions(aws: None, audit_profile: str) -> None:
    scan = open_scan(profile=audit_profile, regions=["ap-northeast-2"])
    assert scan.regions == ("ap-northeast-2",)


def test_explicit_region_overrides_profile(aws: None, audit_profile: str) -> None:
    assert open_scan(profile=audit_profile, region="us-east-1").home_region == "us-east-1"


def test_session_is_guarded(aws: None, audit_profile: str) -> None:
    scan = open_scan(profile=audit_profile)
    with pytest.raises(ReadOnlyViolation):
        scan.session.client("iam").create_user(UserName="must-not-exist")


def test_open_scan_with_role_profile(aws: None, isolated_aws_env: AwsFiles) -> None:
    _write_profiles(
        isolated_aws_env,
        config=(
            "[profile base]\nregion = ap-northeast-2\n"
            "[profile audit-role]\n"
            f"role_arn = arn:aws:iam::{MOTO_ACCOUNT}:role/kompass-audit\n"
            "source_profile = base\nregion = ap-northeast-2\n"
        ),
        credentials="[base]\naws_access_key_id = testing\naws_secret_access_key = testing\n",
    )
    scan = open_scan(profile="audit-role")
    assert ":assumed-role/kompass-audit/" in scan.caller_arn


def test_missing_region_aborts(aws: None, isolated_aws_env: AwsFiles) -> None:
    _write_profiles(
        isolated_aws_env,
        config="[profile noregion]\n",
        credentials="[noregion]\naws_access_key_id = testing\naws_secret_access_key = testing\n",
    )
    with pytest.raises(SessionError, match="리전"):
        open_scan(profile="noregion")


def test_unknown_profile_aborts(aws: None) -> None:
    with pytest.raises(SessionError, match="does-not-exist"):
        open_scan(profile="does-not-exist")


def test_missing_credentials_aborts(
    aws: None, isolated_aws_env: AwsFiles, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")
    _write_profiles(isolated_aws_env, config="[profile nokeys]\nregion = ap-northeast-2\n")
    with pytest.raises(SessionError, match="자격증명"):
        open_scan(profile="nokeys")


def test_unknown_requested_region_aborts(aws: None, audit_profile: str) -> None:
    with pytest.raises(SessionError, match="ap-northeast-02"):
        open_scan(profile=audit_profile, regions=["ap-northeast-02"])


def test_scan_context_is_immutable(aws: None, audit_profile: str) -> None:
    scan: Any = open_scan(profile=audit_profile)
    with pytest.raises(AttributeError):
        scan.account_id = "999999999999"
