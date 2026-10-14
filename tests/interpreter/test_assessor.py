"""종합 위험 평가: 입력 구성·마스킹, 참조 검증·재시도, 해설 흐름 연결 (ADR-034)."""

from typing import Any

from kompass.interpreter.assessor import prepare_assessment
from kompass.interpreter.explainer import explain_report, report_names
from kompass.interpreter.llm import LLMError
from kompass.models import ActionStep, RiskAssessmentDraft, RiskScenario
from tests.interpreter.fakes import FakeProvider, good_assessment
from tests.interpreter.test_explainer import LOOKUP, REPORT, SG, USER_ARN, _good
from tests.reporters.sample import ACCOUNT


def _run(assessor: Any) -> Any:
    provider = FakeProvider(_good, assessor)
    return explain_report(REPORT, provider, LOOKUP, effort="high"), provider


def test_prompt_has_rules_findings_and_summaries_masked() -> None:
    result, provider = _run(good_assessment)
    [(_, prompt)] = provider.assessment_calls
    for raw in (ACCOUNT, SG, "alice-admin", "prod-bastion", USER_ARN):
        assert raw not in prompt
    assert '"id": "SG-001"' in prompt and '"id": "IAM-003"' in prompt
    assert '"priority": "high"' in prompt  # 룰별 해설의 우선순위를 넘긴다
    assert "PASS" not in prompt  # 해설 대상이 아닌 finding은 보내지 않는다
    assert result.assessment is not None and result.assessment.verified


def test_assessment_is_unmasked() -> None:
    result, _ = _run(good_assessment)
    keys = result.assessment.assessment.scenarios[0].finding_keys
    assert f"SG-001:ap-northeast-2:{SG}" in keys or f"IAM-003:-:{USER_ARN}" in keys
    assert [s.rule_id for s in result.assessment.assessment.action_order] == ["IAM-003", "SG-001"]


def test_missing_rule_and_unknown_key_are_retried_then_marked() -> None:
    def bad(payload: dict[str, Any], attempt: int) -> RiskAssessmentDraft:
        scenario = RiskScenario(title="t", description="d", finding_keys=["X:-:y"], impact="low")
        step = ActionStep(rule_id="SG-001", reason="r")
        return RiskAssessmentDraft(summary="요약", scenarios=[scenario], action_order=[step, step])

    result, provider = _run(bad)
    assessment = result.assessment
    assert assessment is not None and not assessment.verified and assessment.attempts == 2
    problems = " / ".join(assessment.problems)
    assert "X:-:y" in problems and "빠진 룰: IAM-003" in problems and "두 번 이상" in problems
    assert "빠진 룰" in provider.assessment_calls[1][1]  # 재시도에 문제를 알려 준다


def test_fixed_on_retry() -> None:
    def flaky(payload: dict[str, Any], attempt: int) -> RiskAssessmentDraft:
        draft = good_assessment(payload, attempt)
        if attempt == 1:
            return RiskAssessmentDraft(summary="s", scenarios=[], action_order=draft.action_order)
        return draft

    result, _ = _run(flaky)
    assert result.assessment is not None
    assert result.assessment.verified and result.assessment.attempts == 2


def test_assessment_failure_is_recorded_not_raised() -> None:
    result, _ = _run(lambda payload, attempt: LLMError("거부됨"))
    assert result.assessment is None and result.assessment_failure == "거부됨"
    assert len(result.explanations) == 2  # 룰별 해설은 그대로 남는다


def test_no_assessment_when_disabled_or_nothing_explained() -> None:
    provider = FakeProvider(_good)
    result = explain_report(REPORT, provider, LOOKUP, effort="high", assess=False)
    assert result.assessment is None and provider.assessment_calls == []
    failing = FakeProvider(lambda payload, attempt: LLMError("x"))
    result = explain_report(REPORT, failing, LOOKUP, effort="high")
    assert result.assessment is None and failing.assessment_calls == []


def test_prepare_counts_rules_without_explanations() -> None:
    prepared = prepare_assessment(REPORT, [], report_names(REPORT))
    assert prepared.rule_ids == ("IAM-003", "SG-001")
    assert '"summary": null' in prepared.prompt


def test_reassess_keeps_explanations_and_adds_usage() -> None:
    from kompass.interpreter.explainer import reassess_report

    first, _ = _run(lambda payload, attempt: LLMError("일시 오류"))
    assert first.assessment is None
    result = reassess_report(REPORT, first, FakeProvider(_good))
    assert result.explanations == first.explanations
    assert result.assessment is not None and result.assessment_failure is None
    assert result.usage.input_tokens == first.usage.input_tokens + 100
