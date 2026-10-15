"""에이전트 공급자: 도구를 쓰는 LLM 루프 (ADR-035).

조사 코드는 `AgentProvider`만 본다. Claude 구현체는 Anthropic SDK의 도구 러너(베타)를 쓰고,
테스트는 가짜 공급자를 넣는다. 도구 함수(`AgentTool.call`)는 이미 마스킹된 문자열만 돌려주며
예외를 내지 않는다 (러너는 도구 예외 메시지를 그대로 모델에 보내기 때문이다).
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import anthropic
from anthropic.lib.tools import BetaFunctionTool
from pydantic import BaseModel

from kompass.config import LlmSettings
from kompass.interpreter.llm import FALLBACK_BETA, LLMError, Usage


@dataclass(frozen=True)
class AgentTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    call: Callable[[dict[str, Any]], str]  # 마스킹된 입력 → 마스킹된 결과 (예외 없음)


@dataclass(frozen=True)
class AgentRun[T: BaseModel]:
    parsed: T | None  # 최종 구조화 응답. 예산 초과·거부 등으로 끝나면 None
    model: str
    usage: Usage
    iterations: int  # LLM 응답 수
    stop: str  # end_turn, max_iterations, token_budget, refusal, max_tokens, …


class AgentProvider(Protocol):
    @property
    def model(self) -> str: ...

    def run[T: BaseModel](
        self,
        system: str,
        task: str,
        tools: Sequence[AgentTool],
        schema: type[T],
        *,
        max_iterations: int,
        max_total_tokens: int,
    ) -> AgentRun[T]: ...


class ClaudeAgentProvider:
    """SDK 도구 러너로 도구 호출 루프를 돈다. 마지막 응답은 `schema` 구조화 출력으로 받는다."""

    def __init__(self, settings: LlmSettings, client: anthropic.Anthropic | None = None) -> None:
        self._settings = settings
        if client is None:
            client = anthropic.Anthropic(timeout=settings.timeout_s)
            if client.api_key is None and client.auth_token is None:
                raise LLMError(
                    "Claude API 키가 없습니다. 환경 변수 ANTHROPIC_API_KEY를 설정해 주십시오"
                )
        self._client = client

    @property
    def model(self) -> str:
        return self._settings.model

    def run[T: BaseModel](
        self,
        system: str,
        task: str,
        tools: Sequence[AgentTool],
        schema: type[T],
        *,
        max_iterations: int,
        max_total_tokens: int,
    ) -> AgentRun[T]:
        runner = self._client.beta.messages.tool_runner(
            model=self._settings.model,
            max_tokens=self._settings.max_tokens,
            system=system,
            messages=[{"role": "user", "content": task}],
            tools=[_function_tool(tool) for tool in tools],
            max_iterations=max_iterations,
            output_format=schema,
            output_config={"effort": self._settings.effort},
            betas=[FALLBACK_BETA],
            fallbacks="default",
        )
        total = Usage(0, 0, 0, 0)
        iterations = 0
        last: Any = None
        stop = ""
        try:
            for message in runner:
                iterations += 1
                last = message
                total = total + _usage(message.usage)
                if total.input_tokens + total.output_tokens > max_total_tokens:
                    stop = "token_budget"
                    break
        except anthropic.AnthropicError as exc:
            raise LLMError(f"Claude API 호출 실패: {exc}") from exc
        if last is None:
            raise LLMError("응답이 없음")
        reason = last.stop_reason or ""
        if not stop:
            stop = "max_iterations" if reason == "tool_use" else reason
        parsed = getattr(last, "parsed_output", None) if stop == "end_turn" else None
        return AgentRun(
            parsed=parsed, model=last.model, usage=total, iterations=iterations, stop=stop
        )


def _function_tool(tool: AgentTool) -> BetaFunctionTool[Any]:
    def run(**arguments: Any) -> str:
        return tool.call(arguments)

    return BetaFunctionTool(
        run, name=tool.name, description=tool.description, input_schema=tool.input_schema
    )


def _usage(raw: Any) -> Usage:
    return Usage(
        input_tokens=raw.input_tokens or 0,
        output_tokens=raw.output_tokens or 0,
        cache_read_input_tokens=raw.cache_read_input_tokens or 0,
        cache_write_input_tokens=raw.cache_creation_input_tokens or 0,
    )
