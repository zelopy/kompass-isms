"""테스트용 가짜 LLM 공급자. 실제 API를 부르지 않는다."""

import json
import re
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from kompass.interpreter.llm import LLMResponse, Usage
from kompass.models import (
    ActionStep,
    Citation,
    Remediation,
    ResourceNote,
    RiskAssessmentDraft,
    RiskScenario,
    RuleExplanationDraft,
)

Responder = Callable[[dict[str, Any], int], RuleExplanationDraft | Exception]
Assessor = Callable[[dict[str, Any], int], RiskAssessmentDraft | Exception]


def good_assessment(payload: dict[str, Any], attempt: int) -> RiskAssessmentDraft:
    """보낸 finding과 룰만 참조하는 올바른 종합 평가."""
    return RiskAssessmentDraft(
        summary="외부 노출 경로가 여러 곳에 있음",
        scenarios=[
            RiskScenario(
                title="외부 접근 경로",
                description="공개 설정이 겹쳐 침해 위험이 커짐",
                finding_keys=[f["key"] for f in payload["findings"][:2]],
                impact="high",
            )
        ],
        action_order=[
            ActionStep(rule_id=r["id"], reason="노출 차단 우선") for r in payload["rules"]
        ],
    )


class FakeProvider:
    """프롬프트의 JSON을 읽어 `responder(payload, 같은 룰 몇 번째 요청)`의 결과를 돌려준다."""

    def __init__(self, responder: Responder, assessor: Assessor = good_assessment) -> None:
        self.responder = responder
        self.assessor = assessor
        self.calls: list[tuple[str, str]] = []  # 룰별 해설 요청
        self.assessment_calls: list[tuple[str, str]] = []  # 종합 평가 요청
        self.count_calls = 0

    @property
    def model(self) -> str:
        return "fake-model"

    def complete[T: BaseModel](self, system: str, prompt: str, schema: type[T]) -> LLMResponse[T]:
        result: BaseModel | Exception
        if schema is RiskAssessmentDraft:
            self.assessment_calls.append((system, prompt))
            result = self.assessor(payload_of(prompt), len(self.assessment_calls))
        else:
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
