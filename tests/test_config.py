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
