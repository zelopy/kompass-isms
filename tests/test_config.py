"""판정 기준값 설정 테스트."""

import pytest
from pydantic import ValidationError

from kompass.config import Settings


def test_defaults() -> None:
    assert Settings().cloudtrail.require_read_events is True


def test_override_from_mapping() -> None:
    settings = Settings.model_validate({"cloudtrail": {"require_read_events": False}})
    assert settings.cloudtrail.require_read_events is False


def test_unknown_key_rejected() -> None:
    # kompass.yaml 오타가 조용히 무시되어 기본값으로 판정되면 안 된다
    with pytest.raises(ValidationError):
        Settings.model_validate({"cloudtrail": {"require_read_event": False}})


def test_settings_are_immutable() -> None:
    settings = Settings()
    with pytest.raises(ValidationError):
        settings.cloudtrail.require_read_events = False  # type: ignore[misc]


def test_iam_defaults() -> None:
    iam = Settings().iam
    assert iam.unused_credential_days == 90
    assert iam.access_key_rotation_days == 90
    assert iam.root_recent_use_days == 90
    assert iam.password_policy.min_length_two_types == 10
    assert iam.password_policy.min_length_three_types == 8


def test_llm_defaults() -> None:
    llm = Settings().llm
    assert llm.model == "claude-opus-5-5"
    assert llm.effort == "high"
    assert llm.max_tokens == 16000


def test_llm_invalid_effort_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({"llm": {"effort": "extreme"}})


def test_judgment_criteria_exclude_llm() -> None:
    criteria = Settings.model_validate({"llm": {"effort": "low"}}).judgment_criteria()
    assert "llm" not in criteria
    assert criteria["ec2"]["admin_ports"] == [22, 3389]
