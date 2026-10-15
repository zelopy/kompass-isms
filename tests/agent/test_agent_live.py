"""실제 Claude API로 도구 러너 + 구조화 출력 확인 (`pytest -m llm`, 비용 발생). AWS 미사용."""

import json
import os
from typing import Any

import pytest
from pydantic import BaseModel

from kompass.agent.llm import AgentTool, ClaudeAgentProvider
from kompass.config import LlmSettings

pytestmark = pytest.mark.llm


class _Finding(BaseModel):
    bucket_is_public: bool
    evidence_call_ids: list[str]


@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="ANTHROPIC_API_KEY 없음")
def test_tool_runner_with_structured_output() -> None:
    calls: list[dict[str, Any]] = []

    def bucket_access(arguments: dict[str, Any]) -> str:
        calls.append(arguments)
        return json.dumps(
            {
                "call_id": "T1",
                "bucket": arguments["bucket"],
                "policy_is_public": True,
                "public_access_block": None,
            }
        )

    schema = {
        "type": "object",
        "properties": {"bucket": {"type": "string"}},
        "required": ["bucket"],
    }
    tools = [
        AgentTool("s3_bucket_access", "버킷의 정책 퍼블릭 여부를 조회한다.", schema, bucket_access)
    ]
    result = ClaudeAgentProvider(LlmSettings(effort="low", max_tokens=4000)).run(
        "너는 AWS 점검 보조자다. 도구로 확인한 사실만 답한다.",
        "버킷 MASKED_NAME_1이 퍼블릭인지 도구로 확인하고, 근거가 된 call_id를 적는다.",
        tools,
        _Finding,
        max_iterations=4,
        max_total_tokens=50_000,
    )
    print(f"\nstop={result.stop} iterations={result.iterations} usage={result.usage} calls={calls}")
    assert calls and calls[0]["bucket"] == "MASKED_NAME_1"
    assert result.stop == "end_turn" and result.parsed is not None
    assert result.parsed.bucket_is_public is True and "T1" in result.parsed.evidence_call_ids
