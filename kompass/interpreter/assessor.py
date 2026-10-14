"""종합 위험 평가: 여러 룰의 결과를 엮은 위험 시나리오와 조치 순서 (ADR-034).

룰별 해설이 끝난 뒤 보고서 전체에 대해 LLM을 한 번 더 부른다. 입력은 해설 대상 finding 전체
(마스킹)와 룰별 해설의 우선순위·요약이다. 원문 인용은 룰별 해설에 있으므로 다시 보내지 않는다.

검증 (원칙 1·5):
- 시나리오가 참조한 finding 키가 실제로 보낸 finding에 있어야 한다
- 조치 순서에 해설 대상 룰이 모두 정확히 한 번씩 있어야 한다
- 지어낸 자리표시자가 없어야 한다
문제가 있으면 한 번 다시 묻고, 그래도 있으면 "검증되지 않음"으로 남긴다. 판정은 바꾸지 않는다.
"""

import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

from kompass.interpreter.llm import LLMProvider, Usage
from kompass.interpreter.masking import Masker
from kompass.models import (
    NEEDS_ACTION,
    AuditReport,
    RiskAssessment,
    RiskAssessmentDraft,
    RuleExplanation,
    TokenUsage,
)
from kompass.rules.base import ACCOUNT_RESOURCE
from kompass.rules.registry import RULES

SYSTEM_PROMPT = (
    files("kompass.interpreter").joinpath("assess_system.txt").read_text(encoding="utf-8").strip()
)
MAX_FINDINGS = 60  # 이보다 많으면 앞의 것만 보내고 룰별 건수만 알린다
MAX_ATTEMPTS = 2
_TITLES = {rule.id: rule.title for rule in RULES}


@dataclass(frozen=True)
class PreparedAssessment:
    masker: Masker
    prompt: str
    finding_keys: frozenset[str]  # 마스킹된 키
    rule_ids: tuple[str, ...]


def prepare_assessment(
    report: AuditReport, explanations: Sequence[RuleExplanation], names: tuple[str, ...]
) -> PreparedAssessment:
    """프롬프트를 만든다. 원본 식별정보가 남으면 MaskingError (보내지 않는다)."""
    findings = [f for f in report.findings if f.status in NEEDS_ACTION]
    shown = findings[:MAX_FINDINGS]
    masker = Masker(names)
    masked: list[dict[str, Any]] = masker.mask(
        [
            {
                "key": f.key,
                "rule_id": f.rule_id,
                "status": f.status.value,
                "severity": f.severity.value,
                "resource": f.resource,
                "region": f.region,
                "message": f.message,
                "evidence": f.evidence,
            }
            for f in shown
        ]
    )
    by_rule = {e.rule_id: e for e in explanations}
    counts = Counter(f.rule_id for f in findings)
    rule_ids = tuple(sorted(counts))
    rules = []
    for rule_id in rule_ids:
        explained = by_rule.get(rule_id)
        rules.append(
            {
                "id": rule_id,
                "title": _TITLES.get(rule_id, rule_id),
                "finding_count": counts[rule_id],
                "priority": explained.explanation.priority if explained else None,
                # 룰별 해설은 복원된 상태로 저장되어 있으므로 같은 마스커로 다시 가린다
                "summary": masker.mask_text(explained.explanation.summary) if explained else None,
            }
        )
    payload = {"rules": rules, "findings": masked, "omitted_findings": len(findings) - len(shown)}
    body = json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True)
    masker.require_clean(body, [f.resource for f in shown if f.resource != ACCOUNT_RESOURCE])
    return PreparedAssessment(
        masker=masker,
        prompt=f"다음 점검 결과 전체를 종합 평가한다.\n\n```json\n{body}\n```",
        finding_keys=frozenset(item["key"] for item in masked),
        rule_ids=rule_ids,
    )


def check_assessment(draft: RiskAssessmentDraft, prepared: PreparedAssessment) -> list[str]:
    problems: list[str] = []
    if not draft.scenarios:
        problems.append("시나리오가 없음. 위험 시나리오를 하나 이상 적어야 함")
    for scenario in draft.scenarios:
        if not scenario.finding_keys:
            problems.append(f"finding_key가 없는 시나리오: {scenario.title}")
        unknown = [k for k in scenario.finding_keys if k not in prepared.finding_keys]
        if unknown:
            problems.append(f"findings에 없는 finding_key: {', '.join(unknown)}")
    ordered = [step.rule_id for step in draft.action_order]
    expected = set(prepared.rule_ids)
    missing = sorted(expected - set(ordered))
    extra = sorted(set(ordered) - expected)
    repeated = sorted(r for r, n in Counter(ordered).items() if n > 1)
    if missing:
        problems.append(f"조치 순서에 빠진 룰: {', '.join(missing)}")
    if extra:
        problems.append(f"rules에 없는 룰: {', '.join(extra)}")
    if repeated:
        problems.append(f"조치 순서에 두 번 이상 나온 룰: {', '.join(repeated)}")
    invented = prepared.masker.unknown_tokens(draft.model_dump_json())
    if invented:
        problems.append(f"주어지지 않은 자리표시자: {', '.join(sorted(invented))}")
    return problems


def assess_report(
    report: AuditReport,
    explanations: Sequence[RuleExplanation],
    provider: LLMProvider,
    names: tuple[str, ...],
) -> tuple[RiskAssessment, list[tuple[str, Usage]]]:
    """종합 평가를 만든다. LLMError·MaskingError는 호출한 쪽이 실패로 기록한다."""
    prepared = prepare_assessment(report, explanations, names)
    prompt = prepared.prompt
    usages: list[tuple[str, Usage]] = []
    fallback_used = False
    for attempt in range(1, MAX_ATTEMPTS + 1):
        response = provider.complete(SYSTEM_PROMPT, prompt, RiskAssessmentDraft)
        usages.append((response.model, response.usage))
        fallback_used = fallback_used or response.fallback_used
        problems = check_assessment(response.parsed, prepared)
        if not problems or attempt == MAX_ATTEMPTS:
            break
        lines = "\n".join(f"- {p}" for p in problems)
        prompt = (
            f"{prepared.prompt}\n\n이전 응답에서 다음 문제가 있었다. 고쳐서 처음부터 다시 답한다.\n"
            f"{lines}"
        )
    masker = prepared.masker
    total = sum((u for _, u in usages), Usage(0, 0, 0, 0))
    assessment = RiskAssessment(
        assessment=RiskAssessmentDraft.model_validate(
            masker.unmask(response.parsed.model_dump(mode="json"))
        ),
        verified=not problems,
        problems=tuple(masker.unmask_text(p) for p in problems),
        model=response.model,
        fallback_used=fallback_used,
        attempts=attempt,
        usage=TokenUsage(
            input_tokens=total.input_tokens,
            output_tokens=total.output_tokens,
            cache_read_input_tokens=total.cache_read_input_tokens,
            cache_write_input_tokens=total.cache_write_input_tokens,
        ),
    )
    return assessment, usages
