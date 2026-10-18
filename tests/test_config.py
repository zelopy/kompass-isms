"""판정 기준값 설정 테스트."""

import json
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from kompass.config import Settings

MANUAL = Path(__file__).parents[1] / "docs" / "MANUAL.md"


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


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        flat: dict[str, Any] = {}
        for key, child in value.items():
            flat |= _flatten(child, f"{prefix}{key}.")
        return flat
    return {prefix.rstrip("."): value}


def _manual_value(value: Any) -> str:
    """MANUAL.md 부록 B의 기본값 표기. 긴 작업 목록은 개수만 적는다."""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, list):
        return f"[{len(value)}개 작업]" if len(value) > 6 else json.dumps(value)
    return str(value)


def test_manual_lists_every_setting_with_its_default() -> None:
    # 매뉴얼 부록 B가 설정 키·기본값의 사용자용 정본이다. 키·기본값을 바꾸면 함께 고친다
    appendix = MANUAL.read_text(encoding="utf-8").split("### B. `kompass.yaml` 전체 키", 1)[1]
    appendix = appendix.split("\n### ", 1)[0]
    documented = dict(re.findall(r"^\| `([a-z0-9_.]+)` \| `([^`]+)` \|", appendix, re.M))
    defaults = _flatten(Settings().model_dump(mode="json"))
    assert documented == {key: _manual_value(value) for key, value in defaults.items()}
