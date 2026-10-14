"""LLM 공급자 인터페이스와 Claude 구현체 (ADR-007, ADR-029).

해설 코드는 `LLMProvider`만 보고, 테스트는 가짜 공급자를 넣는다. 로컬 LLM 구현체는 같은
인터페이스로 붙인다. 여기로 들어오는 텍스트는 이미 마스킹된 것이어야 한다 (원칙 5).

Claude 요청 방식:
- 구조화된 출력(`output_format`)으로 pydantic 스키마에 맞는 응답만 받는다.
- 안전 분류기가 거부하면 서버가 권장 모델로 다시 시도한다 (`fallbacks="default"`, 사용자 결정).
  어떤 모델이 답했는지(`model`)와 대체 여부(`fallback_used`)를 남긴다.
- 시스템 프롬프트에 캐시 지정을 해 둔다. 최소 길이에 못 미치면 캐시되지 않을 뿐 비용은 같다.
- API 키는 환경 변수(`ANTHROPIC_API_KEY`)로만 받는다. 설정 파일에 두지 않는다.
"""

from dataclasses import dataclass
from typing import Any, Protocol

import anthropic
from pydantic import BaseModel

from kompass.config import LlmSettings

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class LLMError(Exception):
    """LLM 호출 실패 (네트워크, 인증, 잘린 응답, 스키마 불일치 등)."""


class LLMRefusal(LLMError):
    """모델(대체 모델 포함)이 요청을 거부했다."""


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int
    cache_read_input_tokens: int
    cache_write_input_tokens: int

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cache_read_input_tokens + other.cache_read_input_tokens,
            self.cache_write_input_tokens + other.cache_write_input_tokens,
        )


@dataclass(frozen=True)
class LLMResponse[T: BaseModel]:
    parsed: T
    model: str  # 실제로 답한 모델 (대체되었으면 대체 모델)
    usage: Usage
    fallback_used: bool


class LLMProvider(Protocol):
    @property
    def model(self) -> str: ...

    def complete[T: BaseModel](
        self, system: str, prompt: str, schema: type[T]
    ) -> LLMResponse[T]: ...

    def count_input_tokens(self, system: str, prompt: str, schema: type[BaseModel]) -> int: ...


# --- 비용 ---


@dataclass(frozen=True)
class Price:
    input_per_mtok: float  # 100만 토큰당 달러
    output_per_mtok: float


PRICES: dict[str, Price] = {
    "claude-opus-5-5": Price(4.0, 20.0),
}
_CACHE_READ_RATE = 0.1  # 캐시 읽기는 입력 단가의 0.1배
_CACHE_WRITE_RATE = 1.25  # 캐시 쓰기(5분)는 입력 단가의 1.25배


def estimate_cost(model: str, usage: Usage) -> float | None:
    """사용량의 대략적인 비용(달러). 단가를 모르는 모델이면 None."""
    price = PRICES.get(model)
    if price is None:
        return None
    input_equivalent = (
        usage.input_tokens
        + usage.cache_read_input_tokens * _CACHE_READ_RATE
        + usage.cache_write_input_tokens * _CACHE_WRITE_RATE
    )
    return (
        input_equivalent * price.input_per_mtok + usage.output_tokens * price.output_per_mtok
    ) / 1_000_000


# --- Claude ---


class ClaudeProvider:
    def __init__(self, settings: LlmSettings, client: anthropic.Anthropic | None = None) -> None:
        self._settings = settings
        if client is None:
            client = anthropic.Anthropic()
            if client.api_key is None and client.auth_token is None:
                raise LLMError(
                    "Claude API 키가 없음. 환경 변수 ANTHROPIC_API_KEY 설정 필요 "
                    "(설정 파일에 키를 두지 않음)"
                )
        self._client = client

    @property
    def model(self) -> str:
        return self._settings.model

    def complete[T: BaseModel](self, system: str, prompt: str, schema: type[T]) -> LLMResponse[T]:
        try:
            response = self._client.beta.messages.parse(
                model=self._settings.model,
                max_tokens=self._settings.max_tokens,
                betas=[FALLBACK_BETA],
                fallbacks="default",
                output_config={"effort": self._settings.effort},
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": prompt}],
                output_format=schema,
            )
        except anthropic.AnthropicError as exc:
            raise LLMError(f"Claude API 호출 실패: {exc}") from exc

        if response.stop_reason == "refusal":
            details = response.stop_details
            category = getattr(details, "category", None) or "unknown"
            raise LLMRefusal(f"모델이 요청을 거부함 (분류: {category})")
        if response.stop_reason == "max_tokens":
            raise LLMError("응답이 max_tokens에서 잘림. llm.max_tokens를 늘려야 함")
        parsed = response.parsed_output
        if parsed is None:
            raise LLMError(f"응답을 스키마로 해석하지 못함 (stop_reason={response.stop_reason})")
        return LLMResponse(
            parsed=parsed,
            model=response.model,
            usage=_usage(response.usage),
            fallback_used=any(
                getattr(item, "type", None) == "fallback_message"
                for item in response.usage.iterations or []
            ),
        )

    def count_input_tokens(self, system: str, prompt: str, schema: type[BaseModel]) -> int:
        try:
            result = self._client.messages.count_tokens(
                model=self._settings.model,
                system=system,
                messages=[{"role": "user", "content": prompt}],
                output_format=schema,
            )
        except anthropic.AnthropicError as exc:
            raise LLMError(f"토큰 수 계산 실패: {exc}") from exc
        return result.input_tokens


def _usage(raw: Any) -> Usage:
    return Usage(
        input_tokens=raw.input_tokens or 0,
        output_tokens=raw.output_tokens or 0,
        cache_read_input_tokens=raw.cache_read_input_tokens or 0,
        cache_write_input_tokens=raw.cache_creation_input_tokens or 0,
    )
