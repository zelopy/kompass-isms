"""실제 Claude API 확인 (`pytest -m llm`, 비용 발생). 기본 실행에서 제외한다.

보내는 내용은 가공한 가짜 finding뿐이다. 실제 계정 데이터는 보내지 않는다.
"""

import os

import pytest

from kompass.config import LlmSettings
from kompass.interpreter.llm import ClaudeProvider, estimate_cost
from kompass.models import RuleExplanationDraft

pytestmark = pytest.mark.llm

SYSTEM = "너는 AWS 보안 점검 결과를 설명하는 보조자다. 한국어로 짧게 답한다."
PROMPT = """룰 SG-001 (관리 포트 전체 개방)이 아래 finding에서 FAIL이다.
판정은 바꾸지 말고 설명만 한다.
finding_key: SG-001:ap-northeast-2:MASKED_SG_1
evidence: {"open_rules": [{"port": 22, "cidr": "0.0.0.0/0"}]}
인용 가능한 원문 (KISA CA-08): "각 서비스별 IP, 포트 할당을 적용하여 불필요한 연결을 최소화해야 함"
citations에는 위 구절만 그대로 인용한다."""


@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"), reason="ANTHROPIC_API_KEY 없음")
def test_explanation_schema_round_trip() -> None:
    provider = ClaudeProvider(LlmSettings(effort="low", max_tokens=8000))
    result = provider.complete(SYSTEM, PROMPT, RuleExplanationDraft)
    draft = result.parsed
    assert isinstance(draft, RuleExplanationDraft)
    assert draft.summary and draft.remediation.steps
    assert any(c.code == "CA-08" for c in draft.citations)
    cost = estimate_cost(result.model, result.usage)
    print(f"\nmodel={result.model} fallback={result.fallback_used}")
    print(f"usage={result.usage} cost=${cost}")
