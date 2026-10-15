"""조사 도구 상자: 마스킹 다리, 예산, 호출 기록, 가드 위반 (ADR-035)."""

import json
from typing import Any

import pytest

from kompass.agent import tools
from kompass.agent.toolbox import InvestigationToolbox
from kompass.agent.tools import TOOLS, Tool, ToolContext, ToolResult
from kompass.interpreter.masking import Masker
from tests.agent.conftest import REGION, admin

POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadForPartners",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::acme-public/*",
        }
    ],
}


def _bucket() -> None:
    s3 = admin("s3")
    s3.create_bucket(Bucket="acme-public", CreateBucketConfiguration={"LocationConstraint": REGION})
    s3.put_bucket_policy(Bucket="acme-public", Policy=json.dumps(POLICY))


def test_round_trip_masks_both_ways(context: ToolContext) -> None:
    # LLM은 자리표시자만 보고, AWS는 원래 값만 받는다
    _bucket()
    masker = Masker(["acme-public"])
    token = masker.mask_text("acme-public")
    box = InvestigationToolbox(context, masker, resources=["acme-public"])
    text = box.call("s3_bucket_access", {"bucket": token})
    assert "acme-public" not in text and "PublicReadForPartners" not in text  # 새 이름도 가린다
    body = json.loads(text)
    assert body["call_id"] == "T1" and body["bucket"] == token
    [call] = box.calls
    assert call.input_raw == {"bucket": "acme-public"} and call.input_masked == {"bucket": token}
    assert call.error is None and call.output_masked == text


def test_invented_placeholder_is_not_called(context: ToolContext) -> None:
    box = InvestigationToolbox(context, Masker([]))
    body = json.loads(box.call("s3_bucket_access", {"bucket": "MASKED_NAME_9"}))
    assert body["error"] == "UnknownPlaceholder" and box.calls[0].input_raw == {}


def test_call_budget(context: ToolContext) -> None:
    box = InvestigationToolbox(context, Masker([]), max_calls=1)
    box.call("s3_account_public_access_block", {})
    body = json.loads(box.call("s3_account_public_access_block", {}))
    assert body["call_id"] == "T2" and body["error"] == "Budget"


def test_invalid_input_is_reported(context: ToolContext) -> None:
    box = InvestigationToolbox(context, Masker([]))
    body = json.loads(box.call("ec2_security_group", {"group_id": "sg-1", "region": "us-west-2"}))
    assert body["error"] == "InvalidInput" and box.calls[0].error == "InvalidInput"


def test_read_only_violation_is_recorded(
    context: ToolContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bad(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
        ctx.client("s3").create_bucket(Bucket="x")
        return ToolResult({})

    monkeypatch.setitem(tools.TOOLS_BY_NAME, "bad", Tool("bad", "d", {"type": "object"}, bad))
    box = InvestigationToolbox(context, Masker([]))
    body = json.loads(box.call("bad", {}))
    assert body["error"] == "Internal" and box.violation is not None


def test_unexpected_exception_message_is_not_forwarded(
    context: ToolContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
        raise RuntimeError("secret-bucket-name 처리 중 실패")

    monkeypatch.setitem(tools.TOOLS_BY_NAME, "boom", Tool("boom", "d", {"type": "object"}, boom))
    text = InvestigationToolbox(context, Masker([])).call("boom", {})
    assert "secret-bucket-name" not in text and json.loads(text)["error"] == "RuntimeError"


def test_unmaskable_result_is_blocked(
    context: ToolContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 원본 리소스 값이 남으면 결과 대신 차단 사실만 보낸다 (fail closed)
    def leaky(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
        return ToolResult({"note": "xy"})  # 3자 미만이라 가려지지 않는다

    monkeypatch.setitem(tools.TOOLS_BY_NAME, "leaky", Tool("leaky", "d", {"type": "object"}, leaky))
    box = InvestigationToolbox(context, Masker([]), resources=["xy"])
    body = json.loads(box.call("leaky", {}))
    assert body["error"] == "MaskingBlocked" and "xy" not in json.dumps(body)


def test_agent_tools_cover_catalog(context: ToolContext) -> None:
    box = InvestigationToolbox(context, Masker([]))
    agent_tools = box.agent_tools()
    assert [t.name for t in agent_tools] == [t.name for t in TOOLS]
    assert json.loads(agent_tools[1].call({}))["call_id"] == "T1"
