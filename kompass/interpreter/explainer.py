"""룰별 해설: 조치가 필요한 finding을 룰 단위로 묶어 LLM에 설명을 요청한다 (ADR-029, ADR-030).

흐름 (룰 하나마다):
1. FAIL·ERROR·REVIEW finding을 모은다. PASS·N/A는 해설하지 않는다.
2. finding을 마스킹한다 (원칙 5). 원문(공개 문서)은 마스킹하지 않는다.
3. 그 finding들에 매핑된 KISA·ISMS-P 항목의 원문을 붙여 요청한다.
4. 응답을 검증한다: 인용 코드가 매핑에 있는가, 구절이 그 항목 원문에 있는가, 모르는 finding이나
   지어낸 자리표시자가 없는가. 문제가 있으면 문제를 알려 주고 한 번 다시 요청한다.
   그래도 문제가 있으면 마지막 응답을 "검증되지 않음"으로 남긴다.
5. 마스킹을 복원해 저장한다.

해설은 finding의 판정을 바꾸지 않는다 (원칙 1). 결과는 별도 파일에 담기고 finding과는
`Finding.key`로만 연결된다.
"""

import json
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any

from kompass.interpreter.llm import LLMError, LLMProvider, Usage, estimate_cost
from kompass.interpreter.masking import Masker
from kompass.interpreter.sources import SourceLookup, SourceScheme
from kompass.models import (
    AuditReport,
    ExplanationFailure,
    ExplanationReport,
    Finding,
    RuleExplanation,
    RuleExplanationDraft,
    Status,
    TokenUsage,
)
from kompass.rules.registry import RULES

NEEDS_ACTION = frozenset({Status.FAIL, Status.ERROR, Status.REVIEW})
MAX_FINDINGS_PER_REQUEST = 30  # 이보다 많으면 앞의 것만 보내고 나머지 건수를 알린다
MAX_ATTEMPTS = 2

SYSTEM_PROMPT = (
    files("kompass.interpreter").joinpath("explain_system.txt").read_text(encoding="utf-8").strip()
)

_RULES = {rule.id: rule for rule in RULES}


@dataclass(frozen=True)
class RuleGroup:
    rule_id: str
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class _Prepared:
    masker: Masker
    prompt: str
    allowed: frozenset[tuple[SourceScheme, str]]
    masked_keys: frozenset[str]


@dataclass(frozen=True)
class ExplanationEstimate:
    rules: int
    findings: int
    input_tokens: int
    assumed_output_tokens: int
    cost_usd: float | None


def select_groups(report: AuditReport) -> list[RuleGroup]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in report.findings:
        if finding.status in NEEDS_ACTION:
            grouped[finding.rule_id].append(finding)
    return [RuleGroup(rule_id, tuple(grouped[rule_id])) for rule_id in sorted(grouped)]


def explain_report(
    report: AuditReport,
    provider: LLMProvider,
    lookup: SourceLookup,
    *,
    effort: str,
    on_progress: Callable[[str], None] | None = None,
) -> ExplanationReport:
    explanations: list[RuleExplanation] = []
    failures: list[ExplanationFailure] = []
    total = Usage(0, 0, 0, 0)
    cost: float | None = 0.0
    for group in select_groups(report):
        if on_progress:
            on_progress(group.rule_id)
        keys = tuple(f.key for f in group.findings)
        try:
            explanation, usages = _explain_group(group, provider, lookup)
        except LLMError as exc:
            failures.append(
                ExplanationFailure(rule_id=group.rule_id, finding_keys=keys, error=str(exc))
            )
            continue
        explanations.append(explanation)
        for model, usage in usages:
            total = total + usage
            call_cost = estimate_cost(model, usage)
            cost = None if cost is None or call_cost is None else cost + call_cost
    return ExplanationReport(
        scan_id=report.scan.scan_id,
        account_id=report.scan.account_id,
        findings_evaluated_at=report.evaluation.evaluated_at,
        generated_at=datetime.now(UTC),
        model=provider.model,
        effort=effort,
        source_documents=lookup.documents,
        explanations=tuple(explanations),
        failures=tuple(failures),
        usage=_token_usage(total),
        estimated_cost_usd=cost,
    )


def estimate_explanation(
    report: AuditReport,
    provider: LLMProvider,
    lookup: SourceLookup,
    output_tokens_per_rule: int = 4000,
) -> ExplanationEstimate:
    """해설 요청을 보내지 않고 입력 토큰을 세어 비용을 어림한다 (재시도는 셈하지 않는다).

    토큰 계산에도 마스킹한 프롬프트만 보낸다.
    """
    groups = select_groups(report)
    input_tokens = sum(
        provider.count_input_tokens(SYSTEM_PROMPT, _prepare(g, lookup).prompt, RuleExplanationDraft)
        for g in groups
    )
    output_tokens = output_tokens_per_rule * len(groups)
    return ExplanationEstimate(
        rules=len(groups),
        findings=sum(len(g.findings) for g in groups),
        input_tokens=input_tokens,
        assumed_output_tokens=output_tokens,
        cost_usd=estimate_cost(provider.model, Usage(input_tokens, output_tokens, 0, 0)),
    )


# --- 내부 ---


def _explain_group(
    group: RuleGroup, provider: LLMProvider, lookup: SourceLookup
) -> tuple[RuleExplanation, list[tuple[str, Usage]]]:
    prepared = _prepare(group, lookup)
    prompt = prepared.prompt
    usages: list[tuple[str, Usage]] = []
    fallback_used = False
    for attempt in range(1, MAX_ATTEMPTS + 1):
        response = provider.complete(SYSTEM_PROMPT, prompt, RuleExplanationDraft)
        usages.append((response.model, response.usage))
        fallback_used = fallback_used or response.fallback_used
        problems = _check(response.parsed, prepared, lookup)
        if not problems or attempt == MAX_ATTEMPTS:
            break
        prompt = prepared.prompt + _feedback(problems)
    masker = prepared.masker
    explanation = RuleExplanation(
        rule_id=group.rule_id,
        finding_keys=tuple(f.key for f in group.findings),
        explanation=RuleExplanationDraft.model_validate(
            masker.unmask(response.parsed.model_dump(mode="json"))
        ),
        verified=not problems,
        problems=tuple(masker.unmask_text(p) for p in problems),
        model=response.model,
        fallback_used=fallback_used,
        attempts=attempt,
        usage=_token_usage(sum((u for _, u in usages), Usage(0, 0, 0, 0))),
    )
    return explanation, usages


def _prepare(group: RuleGroup, lookup: SourceLookup) -> _Prepared:
    shown = group.findings[:MAX_FINDINGS_PER_REQUEST]
    raw = [
        {
            "key": f.key,
            "resource": f.resource,
            "region": f.region,
            "status": f.status.value,
            "message": f.message,
            "evidence": f.evidence,
        }
        for f in shown
    ]
    masker = Masker.for_values(raw)
    masked: list[dict[str, Any]] = masker.mask(raw)

    allowed: set[tuple[SourceScheme, str]] = set()
    for finding in group.findings:
        if finding.mappings:
            allowed |= {("kisa", code) for code in finding.mappings.kisa}
            allowed |= {("isms_p", code) for code in finding.mappings.isms_p}
    sources = []
    for scheme, code in sorted(allowed):
        entry = lookup.entry(scheme, code)
        if entry is not None:
            sources.append(
                {"scheme": scheme, "code": code, "title": entry.title, "text": entry.text}
            )

    rule = _RULES.get(group.rule_id)
    payload = {
        "rule": {
            "id": group.rule_id,
            "title": rule.title if rule else group.rule_id,
            "severity": group.findings[0].severity.value,
        },
        "findings": masked,
        "omitted_findings": len(group.findings) - len(shown),
        "sources": sources,
    }
    body = json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True)
    prompt = f"다음 룰의 finding을 해설한다.\n\n```json\n{body}\n```"
    return _Prepared(
        masker=masker,
        prompt=prompt,
        allowed=frozenset(allowed),
        masked_keys=frozenset(item["key"] for item in masked),
    )


def _check(draft: RuleExplanationDraft, prepared: _Prepared, lookup: SourceLookup) -> list[str]:
    problems: list[str] = []
    if not draft.citations:
        problems.append("인용이 없음. sources의 원문에서 근거 구절을 하나 이상 인용해야 함")
    for citation in draft.citations:
        if (citation.scheme, citation.code) not in prepared.allowed:
            problems.append(f"매핑에 없는 항목 인용: {citation.scheme} {citation.code}")
        elif not lookup.contains_quote(citation.scheme, citation.code, citation.quote):
            problems.append(
                f'원문에 없는 구절: {citation.scheme} {citation.code} "{citation.quote}"'
            )
    for note in draft.resource_notes:
        if note.finding_key not in prepared.masked_keys:
            problems.append(f"findings에 없는 finding_key: {note.finding_key}")
    invented = prepared.masker.unknown_tokens(draft.model_dump_json())
    if invented:
        problems.append(f"주어지지 않은 자리표시자: {', '.join(sorted(invented))}")
    return problems


def _feedback(problems: list[str]) -> str:
    lines = "\n".join(f"- {p}" for p in problems)
    return f"\n\n이전 응답에서 다음 문제가 있었다. 고쳐서 처음부터 다시 답한다.\n{lines}"


def _token_usage(usage: Usage) -> TokenUsage:
    return TokenUsage(
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        cache_read_input_tokens=usage.cache_read_input_tokens,
        cache_write_input_tokens=usage.cache_write_input_tokens,
    )
