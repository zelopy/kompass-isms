"""제출된 증적 문서 검토: 요청마다 문서를 LLM에 보내 사실·부족한 점·추가 요청을 받는다 (ADR-049).

흐름 (텍스트를 뽑은 파일이 있는 요청 하나마다):
1. 요청 문구·확인 목적·근거 구절과 KISA 항목 원문(공개 문서, 마스킹하지 않음)을 모은다.
2. 보고서의 확인 대상 리소스와 문서 텍스트·파일 경로를 마스킹한다 (원칙 5). 보고서 전체의 이름,
   사용자 사전 용어, 메일 주소·전화번호·주민등록번호를 바꾼다. 문서는 길이 상한에서 자른다.
3. 응답을 검증한다: 사실마다 주어진 문서 ID를 가리키고 발췌가 그 문서(마스킹된 텍스트)에 있는가,
   지어낸 자리표시자가 없는가. 문제가 있으면 한 번 다시 요청하고, 그래도 남으면 "검증되지 않음".
4. 마스킹을 복원해 저장한다.

검토 결과는 판정·항목 결과·요청서 제출 여부를 바꾸지 않는다 (원칙 1). 응답 스키마에 상태
필드가 없다. 텍스트를 뽑지 못한 파일은 보내지 않고 사람이 검토할 목록으로 남긴다.
"""

import json
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any

from kompass.interpreter.explainer import report_names
from kompass.interpreter.llm import LLMError, LLMProvider, Usage, estimate_cost
from kompass.interpreter.masking import Masker, MaskingError
from kompass.interpreter.sources import MIN_QUOTE_LENGTH, SourceLookup, normalize_for_match
from kompass.models import (
    AuditReport,
    EvidenceCatalogItem,
    EvidenceDocumentRef,
    EvidenceFile,
    EvidenceRequest,
    EvidenceReview,
    EvidenceReviewDraft,
    EvidenceReviewFailure,
    EvidenceReviewReport,
    EvidenceSubmission,
    EvidenceUnreadable,
    TokenUsage,
)
from kompass.rules.base import ACCOUNT_RESOURCE

MAX_DOCUMENT_CHARS = 50_000  # 문서 하나에서 보내는 최대 글자 수 (마스킹 후)
MAX_DOCUMENTS_PER_REQUEST = 10  # 이보다 많으면 앞의 것만 보내고 나머지는 사람이 검토
MAX_ATTEMPTS = 2

SYSTEM_PROMPT = (
    files("kompass.interpreter")
    .joinpath("evidence_review_system.txt")
    .read_text(encoding="utf-8")
    .strip()
)

# 자른 끝에 걸린 자리표시자 조각. 남겨 두면 다른 번호의 자리표시자로 읽힐 수 있다
_CUT_TOKEN = re.compile(r"MASKED_[A-Z0-9_]*$")


@dataclass(frozen=True)
class PreparedReview:
    request_id: str
    masker: Masker
    prompt: str
    documents: tuple[EvidenceDocumentRef, ...]
    texts: Mapping[str, str]  # 문서 ID → 보낸(마스킹된) 텍스트, 발췌 대조용


@dataclass(frozen=True)
class EvidenceReviewEstimate:
    requests: int
    documents: int
    input_tokens: int
    assumed_output_tokens: int
    cost_usd: float | None
    masked: Mapping[str, int]  # 종류별로 바꾼 값의 수 (요청별 합)
    blocked: tuple[str, ...] = ()  # 마스킹 검증에 실패해 보내지 않을 요청


def select_requests(submission: EvidenceSubmission) -> list[str]:
    """텍스트를 뽑은 파일이 있는 요청 ID."""
    return sorted({f.request_id for f in submission.files if f.text is not None})


def review_submission(
    report: AuditReport,
    submission: EvidenceSubmission,
    catalog: Mapping[str, EvidenceCatalogItem],
    provider: LLMProvider,
    lookup: SourceLookup,
    *,
    terms: Iterable[str],
    effort: str,
    max_chars: int = MAX_DOCUMENT_CHARS,
    on_progress: Callable[[str], None] | None = None,
) -> EvidenceReviewReport:
    requests = _requests(catalog)
    _require_known(submission, requests)
    names = report_names(report)
    terms = tuple(terms)
    reviews: list[EvidenceReview] = []
    failures: list[EvidenceReviewFailure] = []
    total = Usage(0, 0, 0, 0)
    cost: float | None = 0.0
    for request_id in select_requests(submission):
        if on_progress:
            on_progress(request_id)
        try:
            prepared = prepare_review(
                report, submission, requests[request_id], lookup, names, terms, max_chars
            )
            review, usages = _review(prepared, provider)
        except (LLMError, MaskingError) as exc:
            failures.append(EvidenceReviewFailure(request_id=request_id, error=str(exc)))
            continue
        reviews.append(review)
        for model, usage in usages:
            total = total + usage
            call_cost = estimate_cost(model, usage)
            cost = None if cost is None or call_cost is None else cost + call_cost
    return EvidenceReviewReport(
        scan_id=report.scan.scan_id,
        account_id=report.scan.account_id,
        findings_evaluated_at=report.evaluation.evaluated_at,
        generated_at=datetime.now(UTC),
        model=provider.model,
        effort=effort,
        reviews=tuple(reviews),
        failures=tuple(failures),
        unreadable=_unreadable(submission),
        ignored=submission.ignored,
        usage=TokenUsage(
            input_tokens=total.input_tokens,
            output_tokens=total.output_tokens,
            cache_read_input_tokens=total.cache_read_input_tokens,
            cache_write_input_tokens=total.cache_write_input_tokens,
        ),
        estimated_cost_usd=cost,
    )


def estimate_review(
    report: AuditReport,
    submission: EvidenceSubmission,
    catalog: Mapping[str, EvidenceCatalogItem],
    provider: LLMProvider,
    lookup: SourceLookup,
    *,
    terms: Iterable[str],
    max_chars: int = MAX_DOCUMENT_CHARS,
    output_tokens_per_request: int = 3000,
) -> EvidenceReviewEstimate:
    """검토 요청을 보내지 않고 입력 토큰을 세어 비용을 어림한다.

    토큰 계산에도 마스킹한 프롬프트만 보낸다.
    """
    requests = _requests(catalog)
    _require_known(submission, requests)
    names = report_names(report)
    terms = tuple(terms)
    prepared: list[PreparedReview] = []
    blocked: list[str] = []
    for request_id in select_requests(submission):
        try:
            prepared.append(
                prepare_review(
                    report, submission, requests[request_id], lookup, names, terms, max_chars
                )
            )
        except MaskingError:
            blocked.append(request_id)
    input_tokens = sum(
        provider.count_input_tokens(SYSTEM_PROMPT, p.prompt, EvidenceReviewDraft) for p in prepared
    )
    output_tokens = output_tokens_per_request * len(prepared)
    masked: Counter[str] = Counter()
    for p in prepared:
        masked.update(p.masker.token_counts())
    return EvidenceReviewEstimate(
        requests=len(prepared),
        documents=sum(len(p.documents) for p in prepared),
        input_tokens=input_tokens,
        assumed_output_tokens=output_tokens,
        cost_usd=estimate_cost(provider.model, Usage(input_tokens, output_tokens, 0, 0)),
        masked=dict(sorted(masked.items())),
        blocked=tuple(blocked),
    )


def render_preview(
    report: AuditReport,
    submission: EvidenceSubmission,
    catalog: Mapping[str, EvidenceCatalogItem],
    lookup: SourceLookup,
    *,
    terms: Iterable[str],
    max_chars: int = MAX_DOCUMENT_CHARS,
) -> str:
    """보낼 프롬프트 전체(마스킹 후)를 사람이 확인할 수 있게 이어 붙인다 (전송 전 확인, ADR-049).

    가려지지 않은 이름이 보이면 사전에 더해 다시 실행한다. 로컬에만 쓰고 보내지 않는다.
    """
    requests = _requests(catalog)
    _require_known(submission, requests)
    names = report_names(report)
    terms = tuple(terms)
    parts = [
        "# 증적 검토 전송 미리보기",
        "",
        "아래는 LLM에 보낼 내용 그대로임. 가려지지 않은 이름·연락처가 있으면 마스킹 사전에 "
        "더한 뒤 다시 실행해야 함.",
    ]
    for request_id in select_requests(submission):
        parts += ["", f"## {request_id}", ""]
        try:
            prepared = prepare_review(
                report, submission, requests[request_id], lookup, names, terms, max_chars
            )
        except MaskingError as exc:
            parts.append(f"보내지 않음: {exc}")
            continue
        counts = ", ".join(f"{k} {v}" for k, v in prepared.masker.token_counts().items())
        parts += [f"가린 값: {counts or '없음'}", "", prepared.prompt]
    return "\n".join(parts) + "\n"


def prepare_review(
    report: AuditReport,
    submission: EvidenceSubmission,
    request: EvidenceRequest,
    lookup: SourceLookup,
    names: Sequence[str],
    terms: Sequence[str],
    max_chars: int = MAX_DOCUMENT_CHARS,
) -> PreparedReview:
    """요청 하나의 프롬프트. 마스킹 검증에 실패하면 MaskingError (보내지 않는다)."""
    code = request.id.rsplit("-", 1)[0]
    masker = Masker(names, terms=terms, personal=True)
    group = next((g for g in report.evidence_requests if g.code == code), None)
    targets = group.targets if group else ()
    masked_targets = [
        masker.mask(
            {"rule_id": t.rule_id, "resource": t.resource, "status": t.status.value,
             "message": t.message}
        )
        for t in targets
    ]  # fmt: skip

    files_ = submission.for_request(request.id)
    readable = [f for f in files_ if f.text is not None][:MAX_DOCUMENTS_PER_REQUEST]
    documents: list[dict[str, Any]] = []
    refs: list[EvidenceDocumentRef] = []
    texts: dict[str, str] = {}
    for n, file in enumerate(readable, start=1):
        document_id = f"D{n}"
        assert file.text is not None
        text, truncated = _truncate(masker.mask_text(file.text), max_chars)
        documents.append(
            {"id": document_id, "path": masker.mask_text(file.path), "kind": str(file.kind),
             "truncated": truncated, "text": text}
        )  # fmt: skip
        refs.append(
            EvidenceDocumentRef(
                document_id=document_id, path=file.path, sha256=file.sha256, truncated=truncated
            )
        )
        texts[document_id] = text
    unreadable = [
        {"path": masker.mask_text(f.path), "problem": f.problem or "읽지 못함"}
        for f in files_
        if f.text is None
    ]
    unreadable += [
        {"path": masker.mask_text(f.path), "problem": "문서 수 상한을 넘어 보내지 않음"}
        for f in [f for f in files_ if f.text is not None][MAX_DOCUMENTS_PER_REQUEST:]
    ]

    # JSON 문자열로 검사하면 이스케이프(`\t`)의 글자가 자리표시자 앞에 붙어 일부만 가려진 값으로
    # 잘못 잡힌다. 값을 줄 단위로 이어 검사한다
    masked_part = "\n".join(_strings([masked_targets, documents, unreadable]))
    masker.require_clean(
        masked_part, [t.resource for t in targets if t.resource != ACCOUNT_RESOURCE]
    )

    entry = lookup.entry("kisa", code)
    payload = {
        "request": {
            "id": request.id,
            "request": request.request,
            "purpose": request.purpose,
            "basis": request.basis,
        },
        "kisa_item": {
            "code": code,
            "title": entry.title if entry else (group.title if group else code),
            "source": entry.text if entry else None,
        },
        "targets": masked_targets,
        "documents": documents,
        "unreadable_documents": unreadable,
    }
    body = json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True)
    prompt = f"다음 증적 요청에 대해 제출된 문서를 검토한다.\n\n```json\n{body}\n```"
    return PreparedReview(
        request_id=request.id, masker=masker, prompt=prompt, documents=tuple(refs), texts=texts
    )


def check_review(draft: EvidenceReviewDraft, prepared: PreparedReview) -> list[str]:
    problems: list[str] = []
    if not draft.facts and not draft.gaps:
        problems.append(
            "사실도 부족한 점도 없음. 문서로 확인한 사실이나 확인되지 않는 점을 써야 함"
        )
    normalized = {doc_id: normalize_for_match(text) for doc_id, text in prepared.texts.items()}
    for fact in draft.facts:
        haystack = normalized.get(fact.document_id)
        needle = normalize_for_match(fact.excerpt)
        if haystack is None:
            problems.append(f"documents에 없는 document_id: {fact.document_id}")
        elif len(needle) < MIN_QUOTE_LENGTH:
            problems.append(f'발췌가 너무 짧음: {fact.document_id} "{fact.excerpt}"')
        elif needle not in haystack:
            problems.append(f'문서에 없는 발췌: {fact.document_id} "{fact.excerpt}"')
    invented = prepared.masker.unknown_tokens(draft.model_dump_json())
    if invented:
        problems.append(f"주어지지 않은 자리표시자: {', '.join(sorted(invented))}")
    return problems


# --- 내부 ---


def _review(
    prepared: PreparedReview, provider: LLMProvider
) -> tuple[EvidenceReview, list[tuple[str, Usage]]]:
    prompt = prepared.prompt
    usages: list[tuple[str, Usage]] = []
    fallback_used = False
    for attempt in range(1, MAX_ATTEMPTS + 1):
        response = provider.complete(SYSTEM_PROMPT, prompt, EvidenceReviewDraft)
        usages.append((response.model, response.usage))
        fallback_used = fallback_used or response.fallback_used
        problems = check_review(response.parsed, prepared)
        if not problems or attempt == MAX_ATTEMPTS:
            break
        prompt = prepared.prompt + _feedback(problems)
    masker = prepared.masker
    total = sum((u for _, u in usages), Usage(0, 0, 0, 0))
    review = EvidenceReview(
        request_id=prepared.request_id,
        documents=prepared.documents,
        review=EvidenceReviewDraft.model_validate(
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
    return review, usages


def _requests(catalog: Mapping[str, EvidenceCatalogItem]) -> dict[str, EvidenceRequest]:
    return {r.id: r for item in catalog.values() for r in item.requests}


def _require_known(submission: EvidenceSubmission, requests: Mapping[str, EvidenceRequest]) -> None:
    unknown = sorted({f.request_id for f in submission.files} - set(requests))
    if unknown:
        raise ValueError(f"카탈로그에 없는 요청: {', '.join(unknown)}")


def _unreadable(submission: EvidenceSubmission) -> tuple[EvidenceUnreadable, ...]:
    by_request: dict[str, list[EvidenceFile]] = {}
    for file in submission.files:
        by_request.setdefault(file.request_id, []).append(file)
    out: list[EvidenceUnreadable] = []
    for request_id in sorted(by_request):
        files_ = by_request[request_id]
        out += [
            EvidenceUnreadable(request_id=request_id, path=f.path, problem=f.problem or "읽지 못함")
            for f in files_
            if f.text is None
        ]
        out += [
            EvidenceUnreadable(
                request_id=request_id, path=f.path, problem="문서 수 상한을 넘어 보내지 않음"
            )
            for f in [f for f in files_ if f.text is not None][MAX_DOCUMENTS_PER_REQUEST:]
        ]
    return tuple(out)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value


def _truncate(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    return _CUT_TOKEN.sub("", text[:max_chars]), True


def _feedback(problems: list[str]) -> str:
    lines = "\n".join(f"- {p}" for p in problems)
    return f"\n\n이전 응답에서 다음 문제가 있었다. 고쳐서 처음부터 다시 답한다.\n{lines}"
