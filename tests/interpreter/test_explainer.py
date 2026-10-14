"""룰별 해설 흐름: 묶기, 마스킹, 원문 첨부, 인용 검증·재시도, 복원 (ADR-029, ADR-030)."""

from datetime import UTC, datetime
from typing import Any

import pytest

from kompass.interpreter.explainer import estimate_explanation, explain_report, select_groups
from kompass.interpreter.llm import LLMError
from kompass.interpreter.sources import SourceLookup
from kompass.models import (
    Citation,
    Remediation,
    ResourceNote,
    RuleExplanationDraft,
    SourceDocument,
    SourceEntry,
    SourceIndex,
    Status,
)
from tests.interpreter.fakes import FakeProvider, payload_of
from tests.reporters.sample import ACCOUNT, finding, sample_report

SG = "sg-0a1b2c3d4e5f67890"
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/alice-admin"
CA09_QUOTE = "불필요한 포트는 허용하지 않도록 접근 제어 설정을 적용해야 함"
CA03_QUOTE = "각 계정별 2차 인증을 사용해 계정 탈취를 방지해야 함"

REPORT = sample_report(
    finding(
        "SG-001",
        Status.FAIL,
        SG,
        "ap-northeast-2",
        f"관리 포트가 전체 개방: {SG}",
        {"group_name": "prod-bastion", "open_rules": [{"port": 22, "cidrs": ["0.0.0.0/0"]}]},
    ),
    finding("SG-001", Status.PASS, "sg-0fedcba9876543210", "ap-northeast-2"),
    finding("IAM-003", Status.FAIL, USER_ARN, None, "MFA 없는 콘솔 사용자: alice-admin",
            {"user": "alice-admin"}),
    finding("CT-001", Status.PASS),
)  # fmt: skip


def _entry(title: str, text: str) -> SourceEntry:
    return SourceEntry(title=title, page=1, text=text)


INDEX = SourceIndex(
    built_at=datetime(2026, 10, 14, tzinfo=UTC),
    documents={"kisa": SourceDocument(file="kisa.pdf", sha256="a" * 64)},
    kisa={
        "CA-09": _entry("접근 제어 설정 관리", f"§ {CA09_QUOTE}"),
        "CA-03": _entry("MFA 설정", f"§ {CA03_QUOTE}"),
    },
    isms_p={
        code: _entry(code, f"통제항목 {code}의 본문이다.")
        for code in ("2.6.1", "2.6.6", "2.10.1", "2.10.2", "2.5.3")
    },
)
LOOKUP = SourceLookup(INDEX)


def _draft(
    payload: dict[str, Any], citations: list[Citation], cli: str = ""
) -> RuleExplanationDraft:
    first = payload["findings"][0]
    return RuleExplanationDraft(
        summary=f"{first['resource']} 문제",
        risk="위험",
        priority="high",
        priority_reason="외부 노출",
        citations=citations,
        remediation=Remediation(steps=["조치"], aws_cli=[cli] if cli else [], terraform=None),
        resource_notes=[ResourceNote(finding_key=first["key"], note="메모")],
    )


def _good(payload: dict[str, Any], attempt: int) -> RuleExplanationDraft:
    if payload["rule"]["id"] == "SG-001":
        cite = Citation(scheme="kisa", code="CA-09", quote=CA09_QUOTE)
        sg = payload["findings"][0]["resource"]
        return _draft(payload, [cite], f"aws ec2 revoke-security-group-ingress --group-id {sg}")
    return _draft(payload, [Citation(scheme="kisa", code="CA-03", quote=CA03_QUOTE)])


# --- 묶기 ---


def test_groups_only_findings_needing_action_by_rule() -> None:
    groups = select_groups(REPORT)
    assert [g.rule_id for g in groups] == ["IAM-003", "SG-001"]
    assert [f.status for g in groups for f in g.findings] == [Status.FAIL, Status.FAIL]


# --- 마스킹 (원칙 5) ---


def test_prompt_contains_no_raw_identifiers() -> None:
    provider = FakeProvider(_good)
    explain_report(REPORT, provider, LOOKUP, effort="high")
    sent = "\n".join(system + prompt for system, prompt in provider.calls)
    for raw in (ACCOUNT, SG, "alice-admin", "prod-bastion", USER_ARN):
        assert raw not in sent
    assert "0.0.0.0/0" in sent  # 판정의 의미는 남긴다


def test_prompt_includes_mapped_source_text() -> None:
    provider = FakeProvider(_good)
    explain_report(REPORT, provider, LOOKUP, effort="high")
    sg_payload = next(payload_of(p) for _, p in provider.calls if "SG-001" in p)
    codes = {(s["scheme"], s["code"]) for s in sg_payload["sources"]}
    assert ("kisa", "CA-09") in codes and ("isms_p", "2.6.1") in codes
    assert ("kisa", "CA-03") not in codes  # 다른 룰의 원문은 보내지 않는다
    assert any(CA09_QUOTE in s["text"] for s in sg_payload["sources"])


# --- 검증·복원 ---


def test_verified_explanation_is_unmasked() -> None:
    result = explain_report(REPORT, FakeProvider(_good), LOOKUP, effort="high")
    sg = next(e for e in result.explanations if e.rule_id == "SG-001")
    assert sg.verified and sg.problems == () and sg.attempts == 1
    assert sg.finding_keys == (f"SG-001:ap-northeast-2:{SG}",)
    assert sg.explanation.remediation.aws_cli == [
        f"aws ec2 revoke-security-group-ingress --group-id {SG}"
    ]
    assert sg.explanation.resource_notes[0].finding_key == f"SG-001:ap-northeast-2:{SG}"
    iam = next(e for e in result.explanations if e.rule_id == "IAM-003")
    assert iam.explanation.summary == f"{USER_ARN} 문제"


def test_bad_quote_is_retried_once_with_feedback() -> None:
    def responder(payload: dict[str, Any], attempt: int) -> RuleExplanationDraft:
        if payload["rule"]["id"] == "SG-001" and attempt == 1:
            return _draft(
                payload, [Citation(scheme="kisa", code="CA-09", quote="원문에 없는 지어낸 문장")]
            )
        return _good(payload, attempt)

    provider = FakeProvider(responder)
    result = explain_report(REPORT, provider, LOOKUP, effort="high")
    sg = next(e for e in result.explanations if e.rule_id == "SG-001")
    assert sg.verified and sg.attempts == 2
    retry_prompt = [p for _, p in provider.calls if "SG-001" in p][1]
    assert "원문에 없는 구절" in retry_prompt


def test_still_invalid_after_retry_is_marked_unverified() -> None:
    def responder(payload: dict[str, Any], attempt: int) -> RuleExplanationDraft:
        return _draft(payload, [Citation(scheme="kisa", code="CA-05", quote=CA09_QUOTE)])

    result = explain_report(REPORT, FakeProvider(responder), LOOKUP, effort="high")
    sg = next(e for e in result.explanations if e.rule_id == "SG-001")
    assert not sg.verified and sg.attempts == 2
    assert any("매핑에 없는 항목" in p and "CA-05" in p for p in sg.problems)


def test_missing_citation_is_a_problem() -> None:
    result = explain_report(
        REPORT, FakeProvider(lambda payload, _: _draft(payload, [])), LOOKUP, effort="high"
    )
    assert all(not e.verified for e in result.explanations)
    assert all(any("인용이 없음" in p for p in e.problems) for e in result.explanations)


def test_invented_placeholder_is_a_problem() -> None:
    def responder(payload: dict[str, Any], attempt: int) -> RuleExplanationDraft:
        data = _good(payload, attempt).model_dump()
        data["remediation"]["steps"] = ["MASKED_SG_77 규칙을 지운다"]
        return RuleExplanationDraft.model_validate(data)

    result = explain_report(REPORT, FakeProvider(responder), LOOKUP, effort="high")
    sg = next(e for e in result.explanations if e.rule_id == "SG-001")
    assert not sg.verified
    assert any("MASKED_SG_77" in p for p in sg.problems)


def test_unknown_finding_key_is_a_problem() -> None:
    def responder(payload: dict[str, Any], attempt: int) -> RuleExplanationDraft:
        data = _good(payload, attempt).model_dump()
        data["resource_notes"] = [{"finding_key": "X:-:y", "note": "n"}]
        return RuleExplanationDraft.model_validate(data)

    result = explain_report(REPORT, FakeProvider(responder), LOOKUP, effort="high")
    assert all(any("X:-:y" in p for p in e.problems) for e in result.explanations)


# --- 실패·집계 ---


def test_llm_error_for_one_rule_does_not_stop_others() -> None:
    def responder(payload: dict[str, Any], attempt: int) -> RuleExplanationDraft | Exception:
        if payload["rule"]["id"] == "IAM-003":
            return LLMError("거부")
        return _good(payload, attempt)

    result = explain_report(REPORT, FakeProvider(responder), LOOKUP, effort="high")
    assert [e.rule_id for e in result.explanations] == ["SG-001"]
    [failure] = result.failures
    assert failure.rule_id == "IAM-003" and "거부" in failure.error
    assert failure.finding_keys == (f"IAM-003:-:{USER_ARN}",)


def test_report_metadata_and_usage() -> None:
    result = explain_report(REPORT, FakeProvider(_good), LOOKUP, effort="high")
    assert result.scan_id == REPORT.scan.scan_id and result.account_id == ACCOUNT
    assert result.findings_evaluated_at == REPORT.evaluation.evaluated_at
    assert result.model == "fake-model" and result.effort == "high"
    assert result.source_documents == INDEX.documents
    assert result.usage.input_tokens == 200 and result.usage.output_tokens == 100
    assert result.estimated_cost_usd is None  # 단가를 모르는 모델


def test_findings_are_not_modified() -> None:
    before = REPORT.model_dump()
    explain_report(REPORT, FakeProvider(_good), LOOKUP, effort="high")
    assert REPORT.model_dump() == before


def test_progress_callback() -> None:
    seen: list[str] = []
    explain_report(REPORT, FakeProvider(_good), LOOKUP, effort="high", on_progress=seen.append)
    assert seen == ["IAM-003", "SG-001"]


# --- 예상 비용 ---


def test_estimate_counts_input_and_assumes_output() -> None:
    provider = FakeProvider(_good)
    estimate = estimate_explanation(REPORT, provider, LOOKUP, output_tokens_per_rule=3000)
    assert estimate.rules == 2 and estimate.findings == 2
    assert estimate.input_tokens == 2000
    assert estimate.assumed_output_tokens == 6000
    assert provider.calls == []  # 해설 요청은 보내지 않는다


def test_no_findings_needing_action() -> None:
    report = sample_report(finding("CT-001", Status.PASS))
    result = explain_report(report, FakeProvider(_good), LOOKUP, effort="high")
    assert result.explanations == () and result.failures == ()


@pytest.mark.parametrize("status", [Status.ERROR, Status.REVIEW])
def test_error_and_review_are_explained(status: Status) -> None:
    report = sample_report(finding("IAM-003", status, USER_ARN))
    assert [g.rule_id for g in select_groups(report)] == ["IAM-003"]


def test_system_prompt_states_core_rules() -> None:
    from kompass.interpreter.explainer import SYSTEM_PROMPT

    assert "status" in SYSTEM_PROMPT and "MASKED_" in SYSTEM_PROMPT and "sources" in SYSTEM_PROMPT
