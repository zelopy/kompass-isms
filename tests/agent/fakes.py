"""테스트용 가짜 에이전트: 과제 JSON을 읽고 실제 도구 함수를 불러 결과를 낸다 (API 없음)."""

import json
import re
from collections.abc import Callable, Sequence
from typing import Any

from pydantic import BaseModel

from kompass.agent.llm import AgentRun, AgentTool
from kompass.interpreter.llm import Usage

# (과제 JSON, 도구 이름 → 도구) → 최종 응답 / 예외 / None(결과 없이 끝남)
Script = Callable[[dict[str, Any], dict[str, AgentTool]], BaseModel | Exception | None]


def task_payload(task: str) -> dict[str, Any]:
    match = re.search(r"```json\n(.*?)\n```", task, re.DOTALL)
    assert match, task
    data: dict[str, Any] = json.loads(match.group(1))
    return data


class ScriptedAgent:
    def __init__(self, script: Script) -> None:
        self.script = script
        self.tasks: list[tuple[str, str]] = []  # (시스템 프롬프트, 과제)

    @property
    def model(self) -> str:
        return "fake-agent"

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
        self.tasks.append((system, task))
        result = self.script(task_payload(task), {t.name: t for t in tools})
        if isinstance(result, Exception):
            raise result
        usage = Usage(1000, 200, 0, 0)
        if result is None:
            return AgentRun(None, "fake-agent", usage, max_iterations, "max_iterations")
        assert isinstance(result, schema)
        return AgentRun(result, "fake-agent", usage, 3, "end_turn")
