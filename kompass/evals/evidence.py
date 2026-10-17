"""증적 검토 평가셋: 케이스, 결정론 채점, 오라클·널 공급자, 실행기 (ADR-049, ADR-033 방식).

케이스 파일은 `evals/evidence/cases/<id>.yaml` 하나씩이다. 가공한 가짜 문서만 담는다 (원칙 4).
실행기는 케이스 문서를 임시 증적 폴더에 쓰고 실제 흐름(`load_submission` → `review_submission`)을
그대로 거친다. 채점은 LLM 판정자 없이 코드로만 한다.

지표:
- verified: 모든 검토가 발췌 대조 검증을 통과 (헤드라인)
- first_try: 모든 검토가 첫 응답에 통과
- leak_free: 보낸 프롬프트에 케이스의 민감 값(이름·연락처·주민등록번호·계정 ID 등)이 없음
- no_invented: 복원한 결과에 지어낸 자리표시자가 남지 않음
- style_ok: 개조식 명사형 문체 (`~다`, `~습니다`로 끝나는 문장 없음)
- no_verdict: 양호·취약·충족 같은 판정어를 쓰지 않음 (원칙 1. 발췌는 문서 원문이라 제외)
- expected_gaps: 케이스가 정한 부족한 점(키워드 묶음) 중 gaps·follow_up_requests에서 찾은 비율
"""

import json
import re
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from kompass.evals.providers import RecordingProvider
from kompass.evals.providers import payload_of as _payload_of
from kompass.interpreter.documents import load_submission
from kompass.interpreter.evidence_reviewer import review_submission
from kompass.interpreter.llm import LLMError, LLMProvider, LLMResponse, Usage, estimate_cost
from kompass.mappings.data import load_mappings
from kompass.mappings.mapper import build_report
from kompass.models import (
    AuditReport,
    EvaluationReport,
    EvidenceFact,
    EvidenceReviewDraft,
    EvidenceReviewReport,
    Finding,
    ScanManifest,
)

EVAL_ACCOUNT = "123456789012"
EVAL_TIME = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
METRICS = (
    "verified",
    "first_try",
    "leak_free",
    "no_invented",
    "style_ok",
    "no_verdict",
    "expected_gaps",
)
_ENDING = re.compile(r"(다|니다|어요|에요)[.!]?$")
_VERDICT = re.compile(r"양호|취약(?!점)|미충족|충족(?:함|됨|되어|한다|하고)|부적합|적합(?:함|하다)")
_TOKEN = re.compile(r"MASKED_[A-Z0-9]+_\d+")
# 판정어를 쓴 것이 아니라 언급한 것: 따옴표 안, "양호 판정을 요구하는 문구"처럼 요구·지시의 대상
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"|‘[^’]*’|“[^”]*”|「[^」]*」")
_REQUESTED = re.compile(
    r"(?:양호|취약)(?:로|으로)?\s*(?:판정|답)\S*\s*(?:을|를)?\s*(?:요구|지시|요청|강요)"
)


class CaseError(ValueError):
    """케이스 파일이 규칙에 맞지 않는다."""


class EvidenceCaseFile(BaseModel):
    path: str  # 증적 폴더 기준 경로 ("CA-02-2/권한 검토.txt")
    text: str | None = None  # 없으면 binary
    binary: str | None = None  # 텍스트를 뽑지 못하는 파일 (예: "png", "blank-pdf")


class EvidenceCase(BaseModel):
    id: str
    title: str
    tags: list[str] = Field(default_factory=list)
    terms: list[str] = Field(default_factory=list)  # 마스킹 사전
    findings: list[Finding] = Field(default_factory=list)  # 확인 대상으로 붙을 finding
    files: list[EvidenceCaseFile]
    sensitive: list[str]  # LLM에 가면 안 되는 원본 값
    expected_gaps: list[list[str]] = Field(default_factory=list)  # 묶음마다 키워드 중 하나


def load_cases(directory: Path) -> list[EvidenceCase]:
    cases = []
    for path in sorted(directory.glob("*.yaml")):
        case = EvidenceCase.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
        if case.id != path.stem or not re.fullmatch(r"[a-z0-9-]+", case.id):
            raise CaseError(f"케이스 ID는 파일 이름과 같고 소문자·숫자·하이픈만 쓴다: {path.name}")
        if not case.sensitive:
            raise CaseError(f"{case.id}: 민감 값(sensitive)이 없다")
        cases.append(case)
    return cases


def case_report(case: EvidenceCase) -> AuditReport:
    manifest = ScanManifest(
        scan_id=f"eval-{case.id}",
        account_id=EVAL_ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{EVAL_ACCOUNT}:user/eval",
        home_region="ap-northeast-2",
        regions=("ap-northeast-2",),
        kompass_version="eval",
        started_at=EVAL_TIME,
        finished_at=EVAL_TIME,
        snapshots={},
    )
    evaluation = EvaluationReport(
        scan_id=manifest.scan_id,
        account_id=EVAL_ACCOUNT,
        kompass_version="eval",
        evaluated_at=EVAL_TIME,
        settings={},
        skipped_rules=(),
        findings=tuple(case.findings),
    )
    return build_report(manifest, evaluation, load_mappings())


def write_files(case: EvidenceCase, root: Path) -> None:
    from pypdf import PdfWriter

    for file in case.files:
        path = root / file.path
        path.parent.mkdir(parents=True, exist_ok=True)
        if file.text is not None:
            path.write_text(file.text, encoding="utf-8")
        elif file.binary == "blank-pdf":
            writer = PdfWriter()
            writer.add_blank_page(width=612, height=792)
            writer.write(path)
        else:
            path.write_bytes(b"\x89PNG\r\n\x1a\n")


def review_case(
    case: EvidenceCase, provider: LLMProvider, lookup: Any, effort: str = "eval"
) -> EvidenceReviewReport:
    """케이스 문서를 임시 폴더에 쓰고 실제 검토 흐름을 실행한다."""
    catalog = load_mappings().evidence
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_files(case, root)
        submission = load_submission(root, [r.id for i in catalog.values() for r in i.requests])
    return review_submission(
        case_report(case), submission, catalog, provider, lookup, terms=case.terms, effort=effort
    )


# --- 채점 ---


@dataclass(frozen=True)
class Grade:
    case_id: str
    metrics: dict[str, float]
    notes: list[str]


def _texts(draft: EvidenceReviewDraft) -> list[str]:
    """LLM이 쓴 문장 (문서 발췌 제외)."""
    return [
        draft.summary,
        *(f.statement for f in draft.facts),
        *draft.gaps,
        *draft.follow_up_requests,
    ]


def style_violations(draft: EvidenceReviewDraft) -> list[str]:
    sentences = [s.strip() for t in _texts(draft) for s in re.split(r"\n|(?<=[.!?])\s+", t)]
    return [s for s in sentences if s and _ENDING.search(s.rstrip(" )"))]


def verdicts(draft: EvidenceReviewDraft) -> list[str]:
    """판정어를 쓴 문장. 문서의 지시를 인용하거나 요구 대상으로 언급한 것은 빼고 본다."""
    return [t for t in _texts(draft) if _VERDICT.search(_REQUESTED.sub("", _QUOTED.sub("", t)))]


def grade(case: EvidenceCase, result: EvidenceReviewReport, prompts: Sequence[str]) -> Grade:
    notes: list[str] = []
    reviews = result.reviews
    if result.failures:
        notes += [f"검토 실패 {f.request_id}: {f.error}" for f in result.failures]
    ok = bool(reviews) and not result.failures
    verified = ok and all(r.verified for r in reviews)
    first_try = ok and all(r.verified and r.attempts == 1 for r in reviews)
    for r in reviews:
        notes += [f"{r.request_id} 검증 문제: {p}" for p in r.problems]
    leaks = sorted({v for v in case.sensitive for p in prompts if v in p})
    notes += [f"노출: {v}" for v in leaks]
    invented = sorted({t for r in reviews for t in _TOKEN.findall(r.review.model_dump_json())})
    notes += [f"지어낸 자리표시자: {t}" for t in invented]
    style = [s for r in reviews for s in style_violations(r.review)]
    notes += [f"문체: {s}" for s in style]
    verdict = [s for r in reviews for s in verdicts(r.review)]
    notes += [f"판정어: {s}" for s in verdict]
    written = " ".join(g for r in reviews for g in [*r.review.gaps, *r.review.follow_up_requests])
    found = [group for group in case.expected_gaps if any(k in written for k in group)]
    missing = [group for group in case.expected_gaps if group not in found]
    notes += [f"찾지 못한 부족한 점: {'/'.join(group)}" for group in missing]
    expected = len(found) / len(case.expected_gaps) if case.expected_gaps else 1.0
    return Grade(
        case_id=case.id,
        metrics={
            "verified": float(verified),
            "first_try": float(first_try),
            "leak_free": float(not leaks),
            "no_invented": float(ok and not invented),
            "style_ok": float(ok and not style),
            "no_verdict": float(ok and not verdict),
            "expected_gaps": expected if ok else 0.0,
        },
        notes=notes,
    )


# --- 오라클·널 ---


@dataclass
class OracleProvider:
    """정답 검토: 문서 첫 내용 줄을 발췌하고 케이스의 부족한 점 키워드를 개조식으로 쓴다."""

    case: EvidenceCase

    @property
    def model(self) -> str:
        return "oracle"

    def complete[T: BaseModel](self, system: str, prompt: str, schema: type[T]) -> LLMResponse[T]:
        payload = _payload_of(prompt)
        document = payload["documents"][0]
        lines = [line for line in document["text"].splitlines() if len(line.strip()) >= 10]
        draft = EvidenceReviewDraft(
            summary="제출 문서 검토 결과 정리",
            facts=[EvidenceFact(statement="문서 기재 내용 확인", document_id=document["id"],
                                excerpt=lines[0] if lines else document["text"])],
            gaps=[f"{group[0]} 관련 내용 확인 안 됨" for group in self.case.expected_gaps],
            follow_up_requests=["관련 자료 추가 제출 요청"],
        )  # fmt: skip
        assert isinstance(draft, schema)
        return LLMResponse(parsed=draft, model="oracle", usage=Usage(0, 0, 0, 0),
                           fallback_used=False)  # fmt: skip

    def count_input_tokens(self, system: str, prompt: str, schema: type[BaseModel]) -> int:
        return 0


class NullProvider:
    """오답 검토: 지어낸 발췌, 판정어, 문체 위반, 지어낸 자리표시자."""

    @property
    def model(self) -> str:
        return "null"

    def complete[T: BaseModel](self, system: str, prompt: str, schema: type[T]) -> LLMResponse[T]:
        draft = EvidenceReviewDraft(
            summary="증적이 충족되어 양호합니다.",
            facts=[EvidenceFact(statement="MASKED_TERM_99가 승인했다.", document_id="D9",
                                excerpt="문서에 없는 구절을 지어냄")],
            gaps=[],
            follow_up_requests=[],
        )  # fmt: skip
        assert isinstance(draft, schema)
        return LLMResponse(parsed=draft, model="null", usage=Usage(0, 0, 0, 0),
                           fallback_used=False)  # fmt: skip

    def count_input_tokens(self, system: str, prompt: str, schema: type[BaseModel]) -> int:
        return 0


# --- 실행 ---


@dataclass
class RunResult:
    rows: list[dict[str, Any]] = field(default_factory=list)


def run(
    cases: Sequence[EvidenceCase],
    make_provider: Callable[[EvidenceCase], LLMProvider],
    lookup: Any,
    out_dir: Path,
    *,
    reps: int,
    on_event: Callable[[str], None] = print,
) -> Path:
    """케이스 × 반복을 차례로 실행해 `results.jsonl`·`traces/`를 쓴다 (기존 결과는 덮어쓴다)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    traces = out_dir / "traces"
    traces.mkdir(exist_ok=True)
    rows: list[dict[str, Any]] = []
    for case in cases:
        for rep in range(1, reps + 1):
            recorder = RecordingProvider(make_provider(case))
            try:
                result = review_case(case, recorder, lookup)
            except LLMError as exc:
                rows.append({"case": case.id, "rep": rep, "error": str(exc)})
                on_event(f"{case.id}#{rep} 오류: {exc}")
                continue
            prompts = [a.prompt for a in recorder.attempts]
            graded = grade(case, result, prompts)
            usage = sum((a.usage for a in recorder.attempts), Usage(0, 0, 0, 0))
            cost = sum(estimate_cost(a.model, a.usage) or 0.0 for a in recorder.attempts)
            rows.append(
                {
                    "case": case.id,
                    "rep": rep,
                    "metrics": graded.metrics,
                    "notes": graded.notes,
                    "attempts": len(recorder.attempts),
                    "models": sorted({a.model for a in recorder.attempts}),
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "cost_usd": round(cost, 4),
                }
            )
            (traces / f"{case.id}-{rep}.json").write_text(
                json.dumps(
                    {"prompts": prompts, "result": result.model_dump(mode="json")},
                    ensure_ascii=False,
                    indent=1,
                ),
                encoding="utf-8",
            )
            on_event(
                f"{case.id}#{rep} " + " ".join(f"{k}={v:.2f}" for k, v in graded.metrics.items())
            )
    with (out_dir / "results.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return out_dir


def regrade(cases: Sequence[EvidenceCase], out_dir: Path) -> list[dict[str, Any]]:
    """기록한 응답(`traces/`)으로 다시 채점한다 (API 호출 없음). 채점기를 고친 뒤 쓴다."""
    by_id = {case.id: case for case in cases}
    path = out_dir / "results.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        if "metrics" not in row or row["case"] not in by_id:
            continue
        trace = json.loads(
            (out_dir / "traces" / f"{row['case']}-{row['rep']}.json").read_text(encoding="utf-8")
        )
        result = EvidenceReviewReport.model_validate(trace["result"])
        graded = grade(by_id[row["case"]], result, trace["prompts"])
        row["metrics"], row["notes"] = graded.metrics, graded.notes
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return rows


def summarize(rows: Iterable[dict[str, Any]]) -> str:
    rows = list(rows)
    graded = [r for r in rows if "metrics" in r]
    lines = [
        "# 증적 검토 평가 결과",
        "",
        f"실행 {len(rows)}건 (오류 {len(rows) - len(graded)}건)",
        "",
        "| 지표 | 값 |",
        "|---|---|",
    ]
    for metric in METRICS:
        values = [r["metrics"][metric] for r in graded]
        value = sum(values) / len(values) if values else 0.0
        lines.append(f"| {metric} | {value:.1%} |")
    cost = sum(r.get("cost_usd", 0.0) for r in graded)
    tokens_in = sum(r.get("input_tokens", 0) for r in graded)
    tokens_out = sum(r.get("output_tokens", 0) for r in graded)
    lines += ["", f"토큰: 입력 {tokens_in:,}, 출력 {tokens_out:,}, 비용 약 ${cost:.2f}"]
    noted = [r for r in rows if r.get("notes") or r.get("error")]
    if noted:
        lines += ["", "## 메모", ""]
        for r in noted:
            for note in r.get("notes", []) or [r.get("error", "")]:
                lines.append(f"- {r['case']}#{r['rep']}: {note}")
    return "\n".join(lines) + "\n"
