"""MCP 서버: 판정 결과와 읽기 전용 조사 도구를 MCP 클라이언트에 노출한다 (ADR-038).

MCP 클라이언트(Claude Code, Claude Desktop 등) 뒤에는 LLM이 있으므로 에이전트 조사와 같은
마스킹 다리(`InvestigationToolbox`)를 쓴다 (원칙 5). 세션 하나가 마스커 하나를 공유하므로
같은 리소스는 세션 내내 같은 자리표시자로 보인다.

- 도구: `kompass_findings`(판정 결과 조회, 마스킹) + 조사 도구 12개 (`agent/tools.py`)
- AWS 호출은 판정 결과와 같은 계정의 읽기 전용 점검 세션으로만 한다 (원칙 2).
- 판정은 바꾸지 않는다. 판정 결과를 바꾸는 도구는 없다 (원칙 1).
- 호출마다 원래 입력값과 마스킹한 결과를 로그 파일(JSON Lines)에 남긴다. 실제 계정 데이터이므로
  저장 위치(`reports/`) 아래에 둔다 (원칙 4).
- 읽기 전용 가드 위반은 도구의 버그이므로 그 뒤의 호출을 모두 거부한다.
"""

import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from kompass.agent.toolbox import InvestigationToolbox
from kompass.agent.tools import TOOLS, ToolContext
from kompass.interpreter.explainer import report_names
from kompass.interpreter.masking import Masker, MaskingError
from kompass.models import AgentToolCall, AuditReport, Finding, Status
from kompass.rules.base import ACCOUNT_RESOURCE
from kompass.rules.registry import RULES

SERVER_NAME = "kompass"
DEFAULT_MCP_MAX_CALLS = 50  # 세션 하나의 AWS 조사 도구 호출 상한
FINDINGS_TOOL = "kompass_findings"
MAX_FINDINGS_PAGE = 50
_TITLES = {rule.id: rule.title for rule in RULES}

INSTRUCTIONS = (
    "kompass 점검 결과를 조회하고 AWS 계정을 읽기 전용으로 추가 조사하는 도구다. "
    "계정 ID·ARN·IP·리소스 이름은 MASKED_* 자리표시자로 가려져 있으며, 도구 입력에는 "
    "자리표시자를 그대로 쓰면 서버가 원래 값으로 바꿔 조회한다. 자리표시자를 지어내면 거부된다. "
    "판정(status)은 결정론적 룰이 내린 것이며 이 도구로 바꿀 수 없다. "
    "먼저 kompass_findings로 판정 결과를 확인한 뒤 필요한 조사 도구를 호출한다."
)

_FINDINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "enum": [s.value for s in Status],
            "description": "이 판정 상태의 finding만 조회 (없으면 전체)",
        },
        "rule_id": {"type": "string", "description": "이 룰의 finding만 조회 (예: SG-001)"},
        "offset": {"type": "integer", "minimum": 0, "default": 0},
        "limit": {"type": "integer", "minimum": 1, "maximum": MAX_FINDINGS_PAGE, "default": 20},
    },
    "additionalProperties": False,
}
_FINDINGS_DESCRIPTION = (
    "이 점검의 판정 결과(finding)를 조회한다. 상태·룰로 거를 수 있고 증적을 포함한다. "
    "식별정보는 자리표시자로 가려져 있다. 판정 시각과 점검 범위(계정·리전)도 함께 돌려준다."
)


class McpSession:
    """MCP 연결 하나의 상태: 마스커, 조사 도구 상자, 호출 로그."""

    def __init__(
        self,
        report: AuditReport,
        context: ToolContext,
        log_path: Path,
        *,
        max_calls: int = DEFAULT_MCP_MAX_CALLS,
    ) -> None:
        self.report = report
        self.masker = Masker(report_names(report))
        self.resources = tuple(
            {f.resource for f in report.findings if f.resource != ACCOUNT_RESOURCE}
        )
        self.toolbox = InvestigationToolbox(context, self.masker, self.resources, max_calls)
        self.log_path = log_path
        self.findings_calls = 0
        self._lock = anyio.Lock()

    def tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name=FINDINGS_TOOL,
                description=_FINDINGS_DESCRIPTION,
                input_schema=_FINDINGS_SCHEMA,
                annotations=types.ToolAnnotations(read_only_hint=True, open_world_hint=False),
            ),
            *(
                types.Tool(
                    name=tool.name,
                    description=tool.description,
                    input_schema=tool.input_schema,
                    annotations=types.ToolAnnotations(read_only_hint=True, open_world_hint=True),
                )
                for tool in TOOLS
            ),
        ]

    async def call_async(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        # boto3 호출은 동기라 스레드에서 돌리고, 마스커·로그는 호출 하나씩만 건드리게 한다
        async with self._lock:
            return await anyio.to_thread.run_sync(self.call, name, arguments)

    def call(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """도구를 실행하고 (LLM에 보낼 마스킹된 결과, 오류 여부)를 돌려준다. 예외를 내지 않는다."""
        if self.toolbox.violation is not None:
            return _error("Stopped", "읽기 전용 가드 위반으로 세션이 중단됨"), True
        if name == FINDINGS_TOOL:
            record = self._findings(arguments)
        elif name in {tool.name for tool in TOOLS}:
            self.toolbox.call(name, arguments)
            record = self.toolbox.calls[-1]
            if self.toolbox.violation is not None:
                print(f"읽기 전용 가드 위반: {self.toolbox.violation}", file=sys.stderr)
        else:
            return _error("UnknownTool", f"알 수 없는 도구: {name}"), True
        self._log(record)
        return record.output_masked, record.error is not None

    def _findings(self, arguments: dict[str, Any]) -> AgentToolCall:
        self.findings_calls += 1
        call_id = f"F{self.findings_calls}"
        started = time.monotonic()
        error: str | None = None
        try:
            payload = self._findings_payload(arguments)
            masked = self.masker.mask(payload)
            text = json.dumps({"call_id": call_id, **masked}, ensure_ascii=False, sort_keys=True)
            self.masker.require_clean(text, self.resources)
        except (ValueError, TypeError) as exc:
            error = "InvalidInput"
            text = _error(error, str(exc), call_id)
        except MaskingError:
            error = "MaskingBlocked"
            text = _error(error, "결과에 가리지 못한 식별자가 있어 전달하지 않음", call_id)
        return AgentToolCall(
            call_id=call_id,
            tool=FINDINGS_TOOL,
            input_masked=arguments,
            input_raw=arguments,  # 판정 결과 조회 입력에는 식별자가 없다
            output_masked=text,
            error=error,
            duration_s=round(time.monotonic() - started, 3),
        )

    def _findings_payload(self, arguments: dict[str, Any]) -> dict[str, Any]:
        unknown = set(arguments) - set(_FINDINGS_SCHEMA["properties"])
        if unknown:
            raise ValueError(f"알 수 없는 입력: {', '.join(sorted(unknown))}")
        status = arguments.get("status")
        if status is not None:
            status = Status(status)
        rule_id = arguments.get("rule_id")
        offset = _int(arguments.get("offset", 0), "offset", 0)
        limit = min(_int(arguments.get("limit", 20), "limit", 1), MAX_FINDINGS_PAGE)
        selected = [
            f
            for f in self.report.findings
            if (status is None or f.status == status) and (rule_id is None or f.rule_id == rule_id)
        ]
        scan = self.report.scan
        return {
            "account_id": scan.account_id,
            "regions": list(scan.regions),
            "evaluated_at": self.report.evaluation.evaluated_at.isoformat(),
            "total": len(selected),
            "offset": offset,
            "findings": [_finding(f) for f in selected[offset : offset + limit]],
        }

    def _log(self, record: AgentToolCall) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as log:
            log.write(record.model_dump_json() + "\n")


def _int(value: Any, name: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name}은 {minimum} 이상의 정수여야 함")
    return value


def _finding(finding: Finding) -> dict[str, Any]:
    return {
        "key": finding.key,
        "rule_id": finding.rule_id,
        "rule_title": _TITLES.get(finding.rule_id, finding.rule_id),
        "resource": finding.resource,
        "region": finding.region,
        "status": finding.status.value,
        "severity": finding.severity.value,
        "message": finding.message,
        "kisa": list(finding.mappings.kisa) if finding.mappings else [],
        "evidence": finding.evidence,
    }


def _error(code: str, message: str, call_id: str | None = None) -> str:
    body = {"error": code, "message": message}
    if call_id is not None:
        body = {"call_id": call_id, **body}
    return json.dumps(body, ensure_ascii=False)


def build_server(session: McpSession) -> Server[Any]:
    async def list_tools(
        ctx: Any, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=session.tools())

    async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        text, is_error = await session.call_async(params.name, params.arguments or {})
        return types.CallToolResult(content=[types.TextContent(text=text)], is_error=is_error)

    return Server(
        SERVER_NAME,
        instructions=INSTRUCTIONS,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


def default_log_path(root: Path, report: AuditReport, now: datetime | None = None) -> Path:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    scan = report.scan
    return root / "mcp" / scan.account_id / f"{scan.scan_id}.{stamp}.mcp.jsonl"


def serve_stdio(server: Server[Any]) -> None:
    async def main() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    anyio.run(main)
