"""LLM 공급자: Claude 구현체의 요청 형태, 응답 처리, 비용 계산 (ADR-029).

실제 API는 부르지 않는다. SDK 클라이언트 자리에 같은 메서드를 가진 가짜 객체를 넣는다.
"""

from types import SimpleNamespace
from typing import Any, cast

import anthropic
import pytest
from pydantic import BaseModel

from kompass.config import LlmSettings
from kompass.interpreter.llm import (
    FALLBACK_BETA,
    ClaudeProvider,
    LLMError,
    LLMRefusal,
    Usage,
    estimate_cost,
)
from kompass.models import RuleExplanationDraft


class _Answer(BaseModel):
    text: str


def _usage(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "input_tokens": 1000,
        "output_tokens": 500,
        "cache_read_input_tokens": None,
        "cache_creation_input_tokens": None,
        "iterations": None,
    }
    return SimpleNamespace(**{**base, **overrides})


def _response(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "stop_reason": "end_turn",
        "stop_details": None,
        "parsed_output": _Answer(text="ok"),
        "model": "claude-opus-5-5",
        "usage": _usage(),
    }
    return SimpleNamespace(**{**base, **overrides})


class _FakeClient:
    def __init__(self, response: Any = None, error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.count_calls: list[dict[str, Any]] = []
        self._response = response if response is not None else _response()
        self._error = error
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self._parse))
        self.messages = SimpleNamespace(count_tokens=self._count)

    def _parse(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self._error:
            raise self._error
        return self._response

    def _count(self, **kwargs: Any) -> Any:
        self.count_calls.append(kwargs)
        return SimpleNamespace(input_tokens=1234)


def _provider(client: _FakeClient, **settings: Any) -> ClaudeProvider:
    return ClaudeProvider(LlmSettings(**settings), client=cast(anthropic.Anthropic, client))


# --- 요청 ---


def test_request_uses_settings_fallback_and_structured_output() -> None:
    client = _FakeClient()
    _provider(client, effort="medium", max_tokens=8000).complete("시스템", "질문", _Answer)
    [call] = client.calls
    assert call["model"] == "claude-opus-5-5"
    assert call["max_tokens"] == 8000
    assert call["output_config"] == {"effort": "medium"}
    assert call["output_format"] is _Answer
    # 거부되면 서버가 권장 모델로 다시 시도한다 (사용자 결정)
    assert call["betas"] == [FALLBACK_BETA] and call["fallbacks"] == "default"
    assert call["messages"] == [{"role": "user", "content": "질문"}]


def test_system_prompt_is_cacheable() -> None:
    client = _FakeClient()
    _provider(client).complete("시스템", "질문", _Answer)
    [block] = client.calls[0]["system"]
    assert block == {"type": "text", "text": "시스템", "cache_control": {"type": "ephemeral"}}


def test_request_never_sends_sampling_parameters() -> None:
    # Opus 5.5는 temperature 등을 받지 않는다 (400)
    client = _FakeClient()
    _provider(client).complete("s", "p", _Answer)
    assert not {"temperature", "top_p", "top_k", "thinking"} & set(client.calls[0])


# --- 응답 ---


def test_parsed_output_and_usage() -> None:
    client = _FakeClient(_response(usage=_usage(cache_read_input_tokens=200)))
    result = _provider(client).complete("s", "p", _Answer)
    assert result.parsed == _Answer(text="ok")
    assert result.model == "claude-opus-5-5"
    assert result.usage == Usage(
        input_tokens=1000,
        output_tokens=500,
        cache_read_input_tokens=200,
        cache_write_input_tokens=0,
    )
    assert result.fallback_used is False


def test_fallback_is_reported() -> None:
    iterations = [SimpleNamespace(type="message"), SimpleNamespace(type="fallback_message")]
    client = _FakeClient(_response(model="claude-opus-4-8", usage=_usage(iterations=iterations)))
    result = _provider(client).complete("s", "p", _Answer)
    assert result.fallback_used is True
    assert result.model == "claude-opus-4-8"


def test_refusal_raises_with_category() -> None:
    details = SimpleNamespace(category="cyber", explanation="...")
    client = _FakeClient(_response(stop_reason="refusal", stop_details=details, parsed_output=None))
    with pytest.raises(LLMRefusal, match="cyber"):
        _provider(client).complete("s", "p", _Answer)


def test_truncated_output_is_an_error() -> None:
    client = _FakeClient(_response(stop_reason="max_tokens", parsed_output=None))
    with pytest.raises(LLMError, match="max_tokens"):
        _provider(client).complete("s", "p", _Answer)


def test_missing_parsed_output_is_an_error() -> None:
    client = _FakeClient(_response(parsed_output=None))
    with pytest.raises(LLMError):
        _provider(client).complete("s", "p", _Answer)


def test_sdk_errors_are_wrapped() -> None:
    client = _FakeClient(error=anthropic.AnthropicError("network down"))
    with pytest.raises(LLMError, match="network down"):
        _provider(client).complete("s", "p", _Answer)


def test_missing_api_key_is_explained(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    with pytest.raises(LLMError, match="ANTHROPIC_API_KEY"):
        ClaudeProvider(LlmSettings())


# --- 토큰·비용 ---


def test_count_input_tokens() -> None:
    client = _FakeClient()
    assert _provider(client).count_input_tokens("s", "p", _Answer) == 1234
    [call] = client.count_calls
    assert call["model"] == "claude-opus-5-5" and call["output_format"] is _Answer


def test_estimate_cost_opus() -> None:
    usage = Usage(
        input_tokens=1_000_000,
        output_tokens=100_000,
        cache_read_input_tokens=1_000_000,
        cache_write_input_tokens=1_000_000,
    )
    # 입력 $4 + 출력 $2 + 캐시 읽기 $0.4 + 캐시 쓰기 $5
    assert estimate_cost("claude-opus-5-5", usage) == pytest.approx(11.4)


def test_estimate_cost_unknown_model() -> None:
    assert estimate_cost("some-local-model", Usage(1, 1, 0, 0)) is None


def test_usage_adds_up() -> None:
    assert Usage(1, 2, 3, 4) + Usage(10, 20, 30, 40) == Usage(11, 22, 33, 44)


# --- 응답 스키마 ---


def _property_names(schema: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(schema, dict):
        names |= set(schema.get("properties", {}))
        for value in schema.values():
            names |= _property_names(value)
    elif isinstance(schema, list):
        for value in schema:
            names |= _property_names(value)
    return names


def test_explanation_schema_has_no_status_field() -> None:
    # 원칙 1: LLM 출력으로 판정 상태를 바꿀 수 있는 통로를 만들지 않는다
    names = _property_names(RuleExplanationDraft.model_json_schema())
    assert "status" not in names and "severity" not in names
    assert {"citations", "remediation", "priority"} <= names


@pytest.mark.parametrize("model", ["claude-opus-5", "claude-opus-4-8"])
def test_estimate_cost_fallback_models(model: str) -> None:
    # 대체 모델이 답해도 비용 합계가 사라지지 않는다
    assert estimate_cost(model, Usage(1_000_000, 0, 0, 0)) == pytest.approx(5.0)
