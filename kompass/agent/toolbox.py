"""조사 도구 상자: 마스킹 다리, 도구 호출 예산, 호출 기록 (ADR-035).

LLM은 자리표시자만 보고, AWS는 원래 값만 받는다.
1. LLM이 보낸 입력의 자리표시자를 원래 값으로 바꾼다. 마스커가 만들지 않은 자리표시자
   (지어낸 식별자)가 있으면 호출하지 않는다.
2. 읽기 전용 도구를 실행한다 (`call_tool`, 가드가 걸린 점검 세션).
3. 결과에 새로 나온 이름을 치환표에 더하고 결과를 가린다. 전송 직전 검사에 걸리면 결과 대신
   차단 사실만 돌려준다 (fail closed).
4. 호출마다 ID(`T1`, `T2`, …)를 붙여 기록한다. 조사 결과의 사실은 이 ID로 근거를 가리킨다.

예외는 밖으로 내지 않는다 (도구 러너가 예외 메시지를 그대로 모델에 보내기 때문). 읽기 전용
가드 위반만은 `violation`에 남겨, 조사를 마친 쪽이 다시 올리게 한다.
"""

import json
import time
from collections.abc import Sequence
from functools import partial
from typing import Any

from kompass.agent.llm import AgentTool
from kompass.agent.tools import TOOLS, ToolContext, ToolInputError, call_tool
from kompass.aws.guard import ReadOnlyViolation
from kompass.interpreter.masking import Masker, MaskingError
from kompass.models import AgentToolCall

DEFAULT_MAX_CALLS = 15


class InvestigationToolbox:
    def __init__(
        self,
        context: ToolContext,
        masker: Masker,
        resources: Sequence[str] = (),
        max_calls: int = DEFAULT_MAX_CALLS,
    ) -> None:
        self.context = context
        self.masker = masker
        self.resources = list(resources)  # 결과에 그대로 남으면 안 되는 원본 리소스 값
        self.max_calls = max_calls
        self.calls: list[AgentToolCall] = []
        self.violation: ReadOnlyViolation | None = None

    def agent_tools(self) -> list[AgentTool]:
        return [
            AgentTool(tool.name, tool.description, tool.input_schema, partial(self.call, tool.name))
            for tool in TOOLS
        ]

    def call(self, name: str, arguments: dict[str, Any]) -> str:
        call_id = f"T{len(self.calls) + 1}"
        started = time.monotonic()
        raw: dict[str, Any] = {}
        names: tuple[str, ...] = ()
        error: str | None = None
        if len(self.calls) >= self.max_calls:
            output: dict[str, Any] = {
                "error": "Budget",
                "message": "도구 호출 예산을 모두 씀. 지금까지 확인한 사실로 결과를 작성해야 함",
            }
        elif invented := self.masker.unknown_tokens(json.dumps(arguments)):
            output = {
                "error": "UnknownPlaceholder",
                "message": f"주어지지 않은 자리표시자: {', '.join(sorted(invented))}",
            }
        else:
            raw = self.masker.unmask(arguments)
            output, names = self._run(name, raw)
        error = output.get("error") if isinstance(output.get("error"), str) else None
        masked = self.masker.mask(output)
        text = json.dumps({"call_id": call_id, **masked}, ensure_ascii=False, sort_keys=True)
        try:
            masked_names = set(self.masker.names)
            self.masker.require_clean(
                text, [*self.resources, *(n for n in names if n in masked_names)]
            )
        except MaskingError:
            error = "MaskingBlocked"
            text = json.dumps(
                {
                    "call_id": call_id,
                    "error": error,
                    "message": "결과에 가리지 못한 식별자가 있어 전달하지 않음",
                },
                ensure_ascii=False,
            )
        self.calls.append(
            AgentToolCall(
                call_id=call_id,
                tool=name,
                input_masked=arguments,
                input_raw=raw,
                output_masked=text,
                error=error,
                duration_s=round(time.monotonic() - started, 3),
            )
        )
        return text

    def _run(self, name: str, raw: dict[str, Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
        try:
            result = call_tool(self.context, name, raw)
        except ToolInputError as exc:
            return {"error": "InvalidInput", "message": str(exc)}, ()
        except ReadOnlyViolation as exc:
            self.violation = exc  # 도구의 버그. 조사를 마친 쪽이 다시 올린다
            return {"error": "Internal", "message": "도구 내부 오류"}, ()
        except Exception as exc:  # 예외 메시지에 원본 값이 있을 수 있어 종류만 알린다
            return {"error": type(exc).__name__, "message": "도구 실행 실패"}, ()
        self.masker.add_names(result.names)
        return result.data, result.names
