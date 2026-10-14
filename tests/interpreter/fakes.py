"""테스트용 가짜 LLM 공급자. 실제 API를 부르지 않는다."""

import json
import re
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from kompass.interpreter.llm import LLMResponse, Usage
from kompass.models import Citation, Remediation, ResourceNote, RuleExplanationDraft

Responder = Callable[[dict[str, Any], int], RuleExplanationDraft | Exception]


class FakeProvider:
    """프롬프트의 JSON을 읽어 `responder(payload, 같은 룰 몇 번째 요청)`의 결과를 돌려준다."""

    def __init__(self, responder: Responder) -> None:
        self.responder = responder
        self.calls: list[tuple[str, str]] = []
        self.count_calls = 0

    @property
    def model(self) -> str:
        return "fake-model"

    def complete[T: BaseModel](self, system: str, prompt: str, schema: type[T]) -> LLMResponse[T]:
        self.calls.append((system, prompt))
        rule = payload_of(prompt)["rule"]
        attempt = sum(1 for _, p in self.calls if payload_of(p)["rule"] == rule)
        result = self.responder(payload_of(prompt), attempt)
        if isinstance(result, Exception):
            raise result
        assert isinstance(result, schema)
        return LLMResponse(
            parsed=result, model="fake-model", usage=Usage(100, 50, 0, 0), fallback_used=False
        )

    def count_input_tokens(self, system: str, prompt: str, schema: type[BaseModel]) -> int:
        self.count_calls += 1
        return 1000


def payload_of(prompt: str) -> dict[str, Any]:
    match = re.search(r"```json\n(.*?)\n```", prompt, re.DOTALL)
    assert match, prompt
    data: dict[str, Any] = json.loads(match.group(1))
    return data


def cite_first_source(payload: dict[str, Any], attempt: int) -> RuleExplanationDraft:
    """첫 번째 원문 전체를 인용하는 응답 (원문이 짧은 가짜 색인용)."""
    source = payload["sources"][0]
    first = payload["findings"][0]
    return RuleExplanationDraft(
        summary=f"{payload['rule']['id']} 해설",
        risk="위험",
        priority="high",
        priority_reason="외부 노출",
        citations=[Citation(scheme=source["scheme"], code=source["code"], quote=source["text"])],
        remediation=Remediation(steps=["조치"], aws_cli=[], terraform=None),
        resource_notes=[ResourceNote(finding_key=first["key"], note="메모")],
    )
