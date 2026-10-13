"""점검 세션 생성 테스트. moto와 임시 AWS 설정 파일만 쓴다 (tests/conftest.py)."""

from collections.abc import Iterator
from typing import Any

import pytest
from botocore.exceptions import EndpointConnectionError
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


def test_enabled_regions_includes_missing_status() -> None:
    # 상태를 모르는 리전을 조용히 빼면 점검 누락이 드러나지 않는다.
    # 넣어 두면 실제로 비활성일 때 collector 단계에서 ERROR로 드러난다.
    _, enabled = enabled_regions({"Regions": [{"RegionName": "xx-new-1"}]})
    assert enabled == {"xx-new-1"}


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


def test_select_rejects_plain_string() -> None:
    # 문자열도 Sequence[str]이라 mypy가 잡지 못한다. 글자 단위로 쪼개지는 것을 막는다
    with pytest.raises(TypeError):
        select_regions(KNOWN, ENABLED, "ap-northeast-2")


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


def test_open_scan_with_env_credentials_only(aws: None) -> None:
    # 프로필 없이 환경 변수 자격증명만 있는 경우 (conftest의 가짜 키)
    scan = open_scan(region="ap-northeast-2")
    assert scan.account_id == MOTO_ACCOUNT


def test_clients_use_scanner_config(aws: None, audit_profile: str) -> None:
    config = open_scan(profile=audit_profile).session.client("ec2").meta.config
    assert config.retries["mode"] == "standard"
    assert config.connect_timeout == 10
    assert "kompass/" in config.user_agent_extra


def test_expected_account_matches(aws: None, audit_profile: str) -> None:
    scan = open_scan(profile=audit_profile, expected_account_id=MOTO_ACCOUNT)
    assert scan.account_id == MOTO_ACCOUNT


def test_expected_account_mismatch_aborts(aws: None, audit_profile: str) -> None:
    with pytest.raises(SessionError, match="999999999999"):
        open_scan(profile=audit_profile, expected_account_id="999999999999")


class _UnreachableClient:
    def get_caller_identity(self) -> dict[str, Any]:
        raise EndpointConnectionError(endpoint_url="https://sts.ap-northeast-02.amazonaws.com")


class _UnreachableSession:
    region_name = "ap-northeast-02"

    def client(self, *args: Any, **kwargs: Any) -> _UnreachableClient:
        return _UnreachableClient()


def test_unreachable_home_region_message_points_to_region(monkeypatch: pytest.MonkeyPatch) -> None:
    # 리전 오타가 "자격증명 확인 실패"로 보이면 사용자가 키를 의심하게 된다
    monkeypatch.setattr("kompass.aws.session.read_only_session", lambda **_: _UnreachableSession())
    with pytest.raises(SessionError, match="ap-northeast-02") as exc_info:
        open_scan(region="ap-northeast-02")
    assert "자격증명" not in str(exc_info.value)
