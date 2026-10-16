"""MCP 서버: 프로세스 안의 MCP 클라이언트로 도구 목록·마스킹·로그·가드 위반을 확인한다 (moto)."""

import json
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import Client

from kompass.agent import tools
from kompass.agent.mcp_server import FINDINGS_TOOL, McpSession, build_server
from kompass.agent.tools import Tool, ToolContext, ToolResult
from kompass.models import AgentToolCall, AuditReport, Status
from tests.agent.conftest import ACCOUNT, REGION, admin
from tests.reporters.sample import finding, sample_report


def _open_group() -> str:
    ec2 = admin("ec2")
    group: str = ec2.create_security_group(GroupName="open-ssh", Description="d")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group, IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0"
    )
    return group


def _report(group: str) -> AuditReport:
    return sample_report(
        finding("SG-001", Status.FAIL, group, REGION, f"관리 포트가 전체 개방: {group}"),
        finding("SG-001", Status.PASS, "sg-0000000000000aaaa", REGION),
        finding("IAM-008", Status.REVIEW, message="루트 비밀번호 사용 이력 확인 불가"),
    )


@pytest.fixture
def session(context: ToolContext, tmp_path: Path) -> tuple[McpSession, str]:
    group = _open_group()
    return McpSession(_report(group), context, tmp_path / "mcp.jsonl", max_calls=3), group


def _calls(script: Any, session: McpSession) -> Any:
    """MCP 클라이언트로 서버에 연결해 script(client)를 실행한다."""

    async def main() -> Any:
        async with Client(build_server(session)) as client:
            return await script(client)

    return anyio.run(main)


def _text(result: Any) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(result.content[0].text)
    return body


def test_lists_findings_tool_and_read_only_tools(session: tuple[McpSession, str]) -> None:
    async def script(client: Client) -> Any:
        return await client.list_tools()

    listed = _calls(script, session[0])
    names = [t.name for t in listed.tools]
    assert names == [FINDINGS_TOOL, *(t.name for t in tools.TOOLS)]
    assert all(t.annotations and t.annotations.read_only_hint for t in listed.tools)


def test_findings_are_masked_and_filtered(session: tuple[McpSession, str]) -> None:
    mcp_session, group = session

    async def script(client: Client) -> Any:
        return await client.call_tool(FINDINGS_TOOL, {"status": "FAIL"})

    result = _calls(script, mcp_session)
    text = result.content[0].text
    assert not result.is_error
    assert group not in text and ACCOUNT not in text
    body = _text(result)
    assert body["call_id"] == "F1" and body["total"] == 1
    [item] = body["findings"]
    assert item["rule_id"] == "SG-001" and item["status"] == "FAIL"
    assert item["resource"].startswith("MASKED_") and item["kisa"] == ["CA-09"]


def test_findings_rejects_bad_input(session: tuple[McpSession, str]) -> None:
    async def script(client: Client) -> Any:
        return await client.call_tool(FINDINGS_TOOL, {"limit": 0})

    result = _calls(script, session[0])
    assert result.is_error and _text(result)["error"] == "InvalidInput"


def test_aws_tool_uses_placeholders_and_logs_raw_input(
    session: tuple[McpSession, str],
) -> None:
    mcp_session, group = session

    async def script(client: Client) -> Any:
        listed = _text(await client.call_tool(FINDINGS_TOOL, {"status": "FAIL"}))
        placeholder = listed["findings"][0]["resource"]
        return await client.call_tool(
            "ec2_security_group", {"group_id": placeholder, "region": REGION}
        )

    result = _calls(script, mcp_session)
    assert not result.is_error
    body = _text(result)
    assert body["call_id"] == "T1" and group not in result.content[0].text
    assert body["group_id"].startswith("MASKED_") and body["ingress"][0]["from_port"] == 22

    records = [
        AgentToolCall.model_validate_json(line)
        for line in mcp_session.log_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [r.call_id for r in records] == ["F1", "T1"]
    assert records[1].input_raw == {"group_id": group, "region": REGION}
    assert group not in records[1].output_masked


def test_invented_placeholder_and_unknown_tool_are_errors(
    session: tuple[McpSession, str],
) -> None:
    async def script(client: Client) -> Any:
        invented = await client.call_tool("ec2_security_group", {"group_id": "MASKED_SG_99"})
        unknown = await client.call_tool("s3_delete_bucket", {"bucket": "x"})
        return invented, unknown

    invented, unknown = _calls(script, session[0])
    assert invented.is_error and _text(invented)["error"] == "UnknownPlaceholder"
    assert unknown.is_error and _text(unknown)["error"] == "UnknownTool"


def test_call_budget_applies_to_session(session: tuple[McpSession, str]) -> None:
    async def script(client: Client) -> Any:
        return [await client.call_tool("s3_account_public_access_block", {}) for _ in range(4)]

    results = _calls(script, session[0])
    assert _text(results[-1])["error"] == "Budget"  # max_calls=3


def test_guard_violation_stops_session(
    session: tuple[McpSession, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def bad(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
        ctx.client("s3").create_bucket(Bucket="x")
        return ToolResult({})

    name = "s3_account_public_access_block"
    monkeypatch.setitem(tools.TOOLS_BY_NAME, name, Tool(name, "d", {"type": "object"}, bad))

    async def script(client: Client) -> Any:
        first = await client.call_tool(name, {})
        after = await client.call_tool(FINDINGS_TOOL, {})
        return first, after

    first, after = _calls(script, session[0])
    assert first.is_error and _text(first)["error"] == "Internal"
    assert after.is_error and _text(after)["error"] == "Stopped"


def test_stdio_transport_round_trip(tmp_path: Path) -> None:
    import sys

    from mcp import StdioServerParameters

    root = Path(__file__).parents[2]
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "tests.agent.mcp_stdio_server", str(tmp_path / "log.jsonl")],
        cwd=root,
    )

    async def main() -> Any:
        async with Client(params) as client:
            listed = await client.list_tools()
            result = await client.call_tool(FINDINGS_TOOL, {"status": "FAIL"})
            return listed, result

    listed, result = anyio.run(main)
    assert len(listed.tools) == 1 + len(tools.TOOLS)
    body = _text(result)
    assert body["total"] == 2 and ACCOUNT not in result.content[0].text
    assert (tmp_path / "log.jsonl").is_file()
