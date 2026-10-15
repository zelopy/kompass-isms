"""에이전트 공급자: SDK 도구 러너 요청 형태, 도구 연결, 상한, 오류 (ADR-035). 실제 API 없음."""

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any, cast

import anthropic
import pytest
from pydantic import BaseModel

from kompass.agent.llm import AgentTool, ClaudeAgentProvider
from kompass.config import LlmSettings
from kompass.interpreter.llm import FALLBACK_BETA, LLMError


class _Answer(BaseModel):
    summary: str


def _message(stop: str, parsed: Any = None, tokens: int = 100) -> SimpleNamespace:
    usage = SimpleNamespace(
        input_tokens=tokens,
        output_tokens=tokens // 2,
        cache_read_input_tokens=None,
        cache_creation_input_tokens=None,
    )
    return SimpleNamespace(
        stop_reason=stop, parsed_output=parsed, model="claude-opus-5-5", usage=usage
    )


class _FakeClient:
    """`beta.messages.tool_runner`를 흉내 낸다. 첫 응답 전에 첫 도구를 한 번 부른다."""

    def __init__(self, messages: list[SimpleNamespace], error: Exception | None = None) -> None:
        self.kwargs: dict[str, Any] = {}
        self.tool_outputs: list[Any] = []
        self._messages = messages
        self._error = error
        self.beta = SimpleNamespace(messages=SimpleNamespace(tool_runner=self._runner))

    def _runner(self, **kwargs: Any) -> Iterator[SimpleNamespace]:
        self.kwargs = kwargs
        if self._error:
            raise self._error
        self.tool_outputs.append(kwargs["tools"][0].call({"bucket": "MASKED_NAME_1"}))
        yield from self._messages


def _provider(client: _FakeClient, **settings: Any) -> ClaudeAgentProvider:
    return ClaudeAgentProvider(LlmSettings(**settings), client=cast(anthropic.Anthropic, client))


def _tools(seen: list[dict[str, Any]]) -> list[AgentTool]:
    def call(arguments: dict[str, Any]) -> str:
        seen.append(arguments)
        return '{"call_id": "T1"}'

    schema = {
        "type": "object",
        "properties": {"bucket": {"type": "string"}},
        "required": ["bucket"],
    }
    return [AgentTool("s3_bucket_access", "버킷 조회", schema, call)]


def _run(client: _FakeClient, seen: list[dict[str, Any]], **limits: int) -> Any:
    limits = {"max_iterations": 8, "max_total_tokens": 100_000, **limits}
    return _provider(client, effort="medium").run("시스템", "과제", _tools(seen), _Answer, **limits)


def test_runner_request_and_tool_wiring() -> None:
    seen: list[dict[str, Any]] = []
    client = _FakeClient([_message("tool_use"), _message("end_turn", _Answer(summary="끝"))])
    result = _run(client, seen)
    kwargs = client.kwargs
    assert kwargs["model"] == "claude-opus-5-5" and kwargs["max_iterations"] == 8
    assert kwargs["output_format"] is _Answer and kwargs["output_config"] == {"effort": "medium"}
    assert kwargs["betas"] == [FALLBACK_BETA] and kwargs["fallbacks"] == "default"
    assert kwargs["system"] == "시스템" and kwargs["messages"] == [
        {"role": "user", "content": "과제"}
    ]
    assert kwargs["tools"][0].name == "s3_bucket_access"
    assert seen == [{"bucket": "MASKED_NAME_1"}] and client.tool_outputs == ['{"call_id": "T1"}']
    assert result.parsed == _Answer(summary="끝") and result.stop == "end_turn"
    assert result.iterations == 2 and result.usage.input_tokens == 200


def test_iteration_limit_has_no_result() -> None:
    result = _run(_FakeClient([_message("tool_use"), _message("tool_use")]), [])
    assert result.stop == "max_iterations" and result.parsed is None


def test_token_budget_stops_the_loop() -> None:
    client = _FakeClient(
        [_message("tool_use", tokens=600), _message("end_turn", _Answer(summary="x"))]
    )
    result = _run(client, [], max_total_tokens=500)
    assert result.stop == "token_budget" and result.parsed is None and result.iterations == 1


def test_refusal_has_no_result() -> None:
    result = _run(_FakeClient([_message("refusal")]), [])
    assert result.stop == "refusal" and result.parsed is None


def test_sdk_errors_are_wrapped() -> None:
    with pytest.raises(LLMError, match="down"):
        _run(_FakeClient([], error=anthropic.AnthropicError("down")), [])
