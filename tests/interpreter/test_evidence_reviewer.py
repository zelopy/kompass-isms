"""제출된 증적 문서 검토: 마스킹, 요청·원문 첨부, 발췌 대조 검증·재시도, 복원 (ADR-049)."""

from datetime import UTC, datetime
from typing import Any

import pytest

from kompass.interpreter.evidence_reviewer import (
    estimate_review,
    render_preview,
    review_submission,
    select_requests,
)
from kompass.interpreter.llm import LLMError
from kompass.interpreter.sources import SourceLookup
from kompass.mappings.data import load_mappings
from kompass.models import (
    EvidenceFact,
    EvidenceFile,
    EvidenceFileKind,
    EvidenceReviewDraft,
    EvidenceSubmission,
    SourceDocument,
    SourceEntry,
    SourceIndex,
    Status,
)
from tests.interpreter.fakes import ReviewProvider, payload_of, quote_first_line
from tests.reporters.sample import ACCOUNT, finding, sample_report

CATALOG = load_mappings().evidence
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/alice-admin"
REPORT = sample_report(
    finding("IAM-007", Status.REVIEW, USER_ARN, None, "관리자 권한 사용자: alice-admin",
            {"user": "alice-admin"}),
)  # fmt: skip
INDEX = SourceIndex(
    built_at=datetime(2026, 10, 14, tzinfo=UTC),
    documents={"kisa": SourceDocument(file="kisa.pdf", sha256="a" * 64)},
    kisa={"CA-02": SourceEntry(title="사용자 정책 관리", page=855, text="판단 기준 원문")},
    isms_p={},
)
LOOKUP = SourceLookup(INDEX)
PERMS = (
    "[시트: 권한]\n사용자\t직무\t권한\n"
    "alice-admin\t홍길동(인프라)\tAdministratorAccess\n"
    "연락처: hong@corp.example, 010-1234-5678\n"
)
REVIEW_LOG = "[쪽 1]\n2026-09-30 권한 검토 수행. 검토자 이산. 조치: 불필요 권한 2건 회수"
TERMS = ("홍길동", "이산")


def _file(request_id: str, path: str, text: str | None, problem: str | None = None) -> EvidenceFile:
    kind = EvidenceFileKind.PDF if path.endswith(".pdf") else EvidenceFileKind.XLSX
    return EvidenceFile(
        request_id=request_id, path=path, sha256="b" * 64, size=len(text or ""),
        kind=kind, text=text, problem=problem,
    )  # fmt: skip


SUBMISSION = EvidenceSubmission(
    files=(
        _file("CA-02-1", "CA-02-1/홍길동_권한.xlsx", PERMS),
        _file("CA-02-2", "CA-02-2/검토 기록.pdf", REVIEW_LOG),
        _file("CA-02-2", "CA-02-2/스캔.pdf", None, "PDF에 텍스트가 없음 (스캔 문서로 보임)"),
        _file("CA-09-1", "CA-09-1/scan.pdf", None, "PDF에 텍스트가 없음 (스캔 문서로 보임)"),
    ),
    ignored=("notes",),
)


def _review(responder: Any = quote_first_line, **kwargs: Any) -> Any:
    provider = ReviewProvider(responder)
    result = review_submission(
        REPORT, SUBMISSION, CATALOG, provider, LOOKUP, terms=TERMS, effort="high", **kwargs
    )
    return result, provider


def test_only_requests_with_readable_files_are_sent() -> None:
    assert select_requests(SUBMISSION) == ["CA-02-1", "CA-02-2"]
    result, provider = _review()
    assert [payload_of(p)["request"]["id"] for _, p in provider.calls] == ["CA-02-1", "CA-02-2"]
    assert [(u.request_id, u.path) for u in result.unreadable] == [
        ("CA-02-2", "CA-02-2/스캔.pdf"),
        ("CA-09-1", "CA-09-1/scan.pdf"),
    ]
    assert result.ignored == ("notes",)


def test_prompt_masks_names_terms_and_personal_data() -> None:
    _, provider = _review()
    prompt = provider.calls[0][1]
    for raw in ("alice-admin", "홍길동", "hong@corp.example", "010-1234-5678", ACCOUNT):
        assert raw not in prompt, raw
    payload = payload_of(prompt)
    document = payload["documents"][0]
    assert document["id"] == "D1" and document["path"] == "CA-02-1/MASKED_TERM_1_권한.xlsx"
    assert "MASKED_NAME_1\tMASKED_TERM_1(인프라)" in document["text"]
    assert "MASKED_EMAIL_1, MASKED_PHONE_1" in document["text"]
    assert payload["targets"][0]["resource"] == "arn:aws:iam::MASKED_ACCOUNT_1:user/MASKED_NAME_1"


def test_prompt_carries_request_source_text_and_unreadable_files() -> None:
    _, provider = _review()
    payload = payload_of(provider.calls[1][1])
    request = CATALOG["CA-02"].requests[1]
    assert payload["request"] == {
        "id": "CA-02-2",
        "request": request.request,
        "purpose": request.purpose,
        "basis": request.basis,
    }
    assert payload["kisa_item"] == {"code": "CA-02", "title": "사용자 정책 관리",
                                    "source": "판단 기준 원문"}  # fmt: skip
    assert payload["unreadable_documents"] == [
        {"path": "CA-02-2/스캔.pdf", "problem": "PDF에 텍스트가 없음 (스캔 문서로 보임)"}
    ]
    assert "MASKED_TERM_" in payload["documents"][0]["text"]  # 검토자 이산


def test_verified_review_is_unmasked_and_has_no_status() -> None:
    result, _ = _review()
    [first, second] = result.reviews
    assert first.verified and first.problems == () and first.attempts == 1
    assert first.review.facts[0].excerpt == "alice-admin\t홍길동(인프라)\tAdministratorAccess"
    assert first.documents[0].path == "CA-02-1/홍길동_권한.xlsx"
    assert first.documents[0].document_id == "D1" and not first.documents[0].truncated
    assert (
        second.review.facts[0].excerpt
        == "2026-09-30 권한 검토 수행. 검토자 이산. 조치: 불필요 권한 2건 회수"
    )
    assert "status" not in EvidenceReviewDraft.model_fields
    assert result.usage.input_tokens == 200 and result.estimated_cost_usd is None  # 가짜 모델
    assert result.scan_id == REPORT.scan.scan_id
    assert result.findings_evaluated_at == REPORT.evaluation.evaluated_at


def test_excerpt_not_in_document_is_retried_with_feedback() -> None:
    def responder(payload: dict[str, Any], attempt: int) -> EvidenceReviewDraft:
        draft = quote_first_line(payload, attempt)
        if attempt == 1:
            fact = EvidenceFact(
                statement="사실", document_id="D1", excerpt="문서에 없는 구절입니다"
            )
            return EvidenceReviewDraft(**{**draft.model_dump(), "facts": [fact]})
        return draft

    result, provider = _review(responder)
    assert result.reviews[0].verified and result.reviews[0].attempts == 2
    retry = provider.calls[1][1]
    assert "문서에 없는 발췌: D1" in retry


def test_problems_remain_after_last_attempt() -> None:
    def responder(payload: dict[str, Any], attempt: int) -> EvidenceReviewDraft:
        return EvidenceReviewDraft(
            summary="MASKED_TERM_9 관련",
            facts=[
                EvidenceFact(statement="a", document_id="D7", excerpt="아무 구절이나 길게"),
                EvidenceFact(statement="b", document_id="D1", excerpt="짧음"),
            ],
            gaps=[],
            follow_up_requests=[],
        )

    result, _ = _review(responder)
    review = result.reviews[0]
    assert not review.verified and review.attempts == 2
    assert any("documents에 없는 document_id: D7" in p for p in review.problems)
    assert any("발췌가 너무 짧음" in p for p in review.problems)
    assert any("주어지지 않은 자리표시자: MASKED_TERM_9" in p for p in review.problems)


def test_empty_review_is_a_problem() -> None:
    def responder(payload: dict[str, Any], attempt: int) -> EvidenceReviewDraft:
        return EvidenceReviewDraft(summary="없음", facts=[], gaps=[], follow_up_requests=[])

    result, _ = _review(responder)
    assert any("사실도 부족한 점도 없음" in p for p in result.reviews[0].problems)


def test_llm_failure_is_recorded_and_other_requests_continue() -> None:
    def responder(payload: dict[str, Any], attempt: int) -> EvidenceReviewDraft | Exception:
        if payload["request"]["id"] == "CA-02-1":
            return LLMError("Claude API 호출 실패")
        return quote_first_line(payload, attempt)

    result, _ = _review(responder)
    assert [(f.request_id, f.error) for f in result.failures] == [
        ("CA-02-1", "Claude API 호출 실패")
    ]
    assert [r.request_id for r in result.reviews] == ["CA-02-2"]


def test_long_documents_are_truncated() -> None:
    result, provider = _review(max_chars=40)
    document = payload_of(provider.calls[0][1])["documents"][0]
    assert document["truncated"] is True and len(document["text"]) <= 40
    assert result.reviews[0].documents[0].truncated


def test_estimate_counts_tokens_without_sending() -> None:
    provider = ReviewProvider(quote_first_line)
    estimate = estimate_review(REPORT, SUBMISSION, CATALOG, provider, LOOKUP, terms=TERMS)
    assert provider.calls == [] and provider.count_calls == 2
    assert estimate.requests == 2 and estimate.documents == 2 and estimate.input_tokens == 2000
    # 요청별로 바꾼 값의 수를 더한다 (두 요청 모두 확인 대상 ARN을 담는다)
    assert estimate.masked == {"ACCOUNT": 2, "EMAIL": 1, "NAME": 2, "PHONE": 1, "TERM": 2}


def test_unknown_request_folder_is_rejected() -> None:
    submission = EvidenceSubmission(files=(_file("CA-99-1", "CA-99-1/a.pdf", "x"),), ignored=())
    with pytest.raises(ValueError, match="카탈로그에 없는 요청"):
        review_submission(
            REPORT, submission, CATALOG, ReviewProvider(quote_first_line), LOOKUP,
            terms=(), effort="high",
        )  # fmt: skip


def test_preview_shows_exactly_what_would_be_sent() -> None:
    preview = render_preview(REPORT, SUBMISSION, CATALOG, LOOKUP, terms=TERMS)
    provider = ReviewProvider(quote_first_line)
    review_submission(REPORT, SUBMISSION, CATALOG, provider, LOOKUP, terms=TERMS, effort="high")
    for _, prompt in provider.calls:
        assert prompt in preview
    assert (
        "## CA-02-1" in preview
        and "가린 값: ACCOUNT 1, EMAIL 1, NAME 1, PHONE 1, TERM 1" in preview
    )
    for raw in ("홍길동", "hong@corp.example", "010-1234-5678"):
        assert raw not in preview.split("## CA-02-1", 1)[1]
    assert "CA-09-1" not in preview  # 읽을 수 있는 파일이 없는 요청은 보내지 않는다
