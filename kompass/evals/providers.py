"""평가용 공급자: 시도 기록 래퍼, 오라클(정답), 널(오답) (ADR-033).

- `RecordingProvider`: 실제 공급자를 감싸 시도마다 프롬프트·응답·사용량·지연 시간을 남긴다.
- `OracleProvider`: 정답대로 해설한다. 채점기가 약 100%를 줘야 한다 (유료 실행 전 점검).
- `NullProvider`: 인용 없음·잘못된 명령·문체 위반 해설. 채점기가 약 0%를 줘야 한다.
오라클·널은 실제 해설 흐름(마스킹, 검증, 복원)을 그대로 거치도록 마스킹된 프롬프트만 보고 답한다.
"""

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from kompass.evals.grader import kisa_sections
from kompass.interpreter.llm import LLMProvider, LLMResponse, Usage
from kompass.models import (
    Citation,
    Golden,
    Remediation,
    ResourceNote,
    RuleExplanationDraft,
)

_NEEDS_ACTION = {"FAIL", "ERROR", "REVIEW"}


@dataclass
class Attempt:
    prompt: str
    parsed: BaseModel
    model: str
    usage: Usage
    latency_s: float


@dataclass
class RecordingProvider:
    inner: LLMProvider
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def model(self) -> str:
        return self.inner.model

    def complete[T: BaseModel](self, system: str, prompt: str, schema: type[T]) -> LLMResponse[T]:
        started = time.monotonic()
        response = self.inner.complete(system, prompt, schema)
        self.attempts.append(
            Attempt(
                prompt, response.parsed, response.model, response.usage, time.monotonic() - started
            )
        )
        return response

    def count_input_tokens(self, system: str, prompt: str, schema: type[BaseModel]) -> int:
        return self.inner.count_input_tokens(system, prompt, schema)


def payload_of(prompt: str) -> dict[str, Any]:
    match = re.search(r"```json\n(.*?)\n```", prompt, re.DOTALL)
    if match is None:
        raise ValueError("프롬프트에 JSON 본문이 없다")
    data: dict[str, Any] = json.loads(match.group(1))
    return data


class _Scripted:
    """프롬프트 JSON으로 답을 만드는 공급자의 공통 부분."""

    @property
    def model(self) -> str:
        return "scripted"

    def draft(self, payload: dict[str, Any]) -> RuleExplanationDraft:
        raise NotImplementedError

    def complete[T: BaseModel](self, system: str, prompt: str, schema: type[T]) -> LLMResponse[T]:
        draft = self.draft(payload_of(prompt))
        if not isinstance(draft, schema):
            raise TypeError(schema)
        return LLMResponse(
            parsed=draft, model=self.model, usage=Usage(0, 0, 0, 0), fallback_used=False
        )

    def count_input_tokens(self, system: str, prompt: str, schema: type[BaseModel]) -> int:
        return 0


class OracleProvider(_Scripted):
    def __init__(self, golden: Golden) -> None:
        self.golden = golden

    @property
    def model(self) -> str:
        return "oracle"

    def draft(self, payload: dict[str, Any]) -> RuleExplanationDraft:
        rule_id = payload["rule"]["id"]
        targets = [f for f in payload["findings"] if f["status"] in _NEEDS_ACTION]
        statuses = {f["status"] for f in targets}
        resource = next((f["resource"] for f in targets if f["resource"] != "account"), "account")
        commands = []
        if statuses & {"FAIL", "REVIEW"}:
            short = resource.rsplit("/", 1)[-1]
            commands.append(self.golden.rules[rule_id].example.replace("{resource}", short))
        if "ERROR" in statuses:
            commands.append(self.golden.error_example)
        return RuleExplanationDraft(
            summary="설정 미흡 확인됨",
            risk="외부 접근 위험이 있음",
            priority="high",
            priority_reason="빠른 조치 필요",
            citations=[_core_citation(payload["sources"])],
            remediation=Remediation(
                steps=["현재 설정 확인", "설정 변경 적용"], aws_cli=commands, terraform=None
            ),
            resource_notes=[ResourceNote(finding_key=targets[0]["key"], note="조치 대상임")],
        )


class NullProvider(_Scripted):
    @property
    def model(self) -> str:
        return "null"

    def draft(self, payload: dict[str, Any]) -> RuleExplanationDraft:
        return RuleExplanationDraft(
            summary="문제가 있습니다.",
            risk="위험하다.",
            priority="low",
            priority_reason="잘 모르겠다.",
            citations=[],
            remediation=Remediation(
                steps=["알아서 고친다."], aws_cli=["aws ec2 fix-everything --now"], terraform=None
            ),
            resource_notes=[],
        )


def _core_citation(sources: list[dict[str, Any]]) -> Citation:
    """KISA 원문이 있으면 판단 기준의 '취약' 줄, 없으면 ISMS-P 본문 앞부분을 인용한다."""
    for source in sources:
        if source["scheme"] == "kisa":
            criteria = kisa_sections(source["text"]).get("판단 기준", "")
            line = next((ln.strip() for ln in criteria.splitlines() if "취약" in ln), None)
            if line:
                return Citation(scheme="kisa", code=source["code"], quote=line)
    source = next(s for s in sources if s["scheme"] == "isms_p")
    return Citation(scheme="isms_p", code=source["code"], quote=source["text"][:40])


class ReplayProvider:
    """기록된 응답을 순서대로 돌려준다. API를 부르지 않고 채점 기준만 바꿔 다시 채점할 때 쓴다.

    traces의 assistant 턴(마스킹된 응답)을 실제 해설 흐름에 다시 넣으므로 마스킹·검증·복원은
    처음 실행과 똑같이 일어난다.
    """

    def __init__(self, trace: list[dict[str, Any]]) -> None:
        self._turns = [t for t in trace if t["role"] == "assistant"]
        self._model = self._turns[0].get("model", "replay") if self._turns else "replay"

    @property
    def model(self) -> str:
        return self._model

    def complete[T: BaseModel](self, system: str, prompt: str, schema: type[T]) -> LLMResponse[T]:
        if not self._turns:
            raise RuntimeError("기록된 응답보다 많은 요청이 왔다 (해설 흐름이 바뀌었다)")
        turn = self._turns.pop(0)
        return LLMResponse(
            parsed=schema.model_validate_json(turn["content"]),
            model=turn.get("model", self._model),
            usage=Usage(0, 0, 0, 0),
            fallback_used=False,
        )

    def count_input_tokens(self, system: str, prompt: str, schema: type[BaseModel]) -> int:
        return 0
