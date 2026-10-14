"""해설 평가 실행기 (ADR-033). 실제 해설 흐름(`explain_report`)을 케이스마다 돌리고 채점한다.

결과 형식은 claude-api 평가 가이드를 따른다 (`<out>/<variant>/`):
- `results.jsonl`: (케이스, 반복)마다 한 줄. 끝나는 대로 쓰고, 다시 실행하면 이미 있는 것은 건너뛴다
- `traces/<id>_rep<k>.json`: LLM과 주고받은 내용 (마스킹된 프롬프트와 응답 그대로)
- `errors.jsonl`: 채점할 수 없는 실패 (거부, API 오류, 마스킹 차단, 시간 초과). 0점이 아니다
반복 실패한 시도는 결과에 넣지 않으므로 다시 실행하면 그 (케이스, 반복)만 다시 돈다.
"""

import hashlib
import json
import math
import statistics
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kompass.evals.cases import case_report
from kompass.evals.grader import METRICS, CaseOutcome, grade
from kompass.evals.providers import RecordingProvider, ReplayProvider
from kompass.interpreter.explainer import SYSTEM_PROMPT, explain_report
from kompass.interpreter.llm import LLMProvider, Usage, estimate_cost
from kompass.interpreter.sources import SourceLookup
from kompass.models import EvalCase, Golden

METRIC_LABELS = {
    "verified": "검증 통과",
    "first_try": "첫 응답 통과",
    "cite_precision": "인용 정밀도",
    "core_basis": "핵심 근거",
    "cli_valid": "CLI 유효",
    "action_cover": "조치 작업",
    "target_match": "대상 일치",
    "leak_free": "노출 없음",
    "no_invented": "지어냄 없음",
    "style_ok": "문체 준수",
}


@dataclass(frozen=True)
class RunConfig:
    out_dir: Path  # .claude/hillclimb/explain
    variant: str = "baseline"
    reps: int = 2
    concurrency: int = 4
    timeout_s: float = 600.0
    effort: str = "high"


def harness_digest(paths: Sequence[Path]) -> str:
    """채점 기준(실행기·채점기·정답·케이스)이 바뀌었는지 알기 위한 해시."""
    digest = hashlib.sha256()
    for path in sorted(paths):
        files = sorted(path.rglob("*")) if path.is_dir() else [path]
        for file in files:
            if file.is_file() and "__pycache__" not in file.parts:
                digest.update(file.as_posix().encode())
                digest.update(file.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()


def write_state(out_dir: Path, harness: str) -> None:
    """보고서 빌더가 읽는 지표 선언. 헤드라인은 첫 지표(검증 통과)."""
    state = {
        "flow": "explain",
        "harness_sha": harness,
        "metrics": [
            {"id": m, "label": METRIC_LABELS[m], "kind": "binary" if m in _BINARY else "score"}
            for m in METRICS
        ],
        "perf_fields": ["latency_s", "cost_usd", "attempts"],
        "prices": {"claude-opus-5-5": {"in": 4.0, "out": 20.0}},
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "_state.json").write_text(json.dumps(state, ensure_ascii=False, indent=2), "utf-8")


_BINARY = {"verified", "first_try", "core_basis", "leak_free", "no_invented", "style_ok"}


def done_keys(variant_dir: Path) -> set[tuple[str, int]]:
    path = variant_dir / "results.jsonl"
    if not path.is_file():
        return set()
    rows = [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]
    return {(row["prompt_id"], row["rep"]) for row in rows}


def run(
    cases: Sequence[EvalCase],
    make_provider: Callable[[], LLMProvider],
    lookup: SourceLookup,
    golden: Golden,
    config: RunConfig,
    harness: str,
    on_event: Callable[[str], None] = lambda message: None,
) -> Path:
    variant_dir = config.out_dir / config.variant
    (variant_dir / "traces").mkdir(parents=True, exist_ok=True)
    finished = done_keys(variant_dir)
    todo = [(c, r) for c in cases for r in range(config.reps) if (c.id, r) not in finished]
    on_event(f"실행 {len(todo)}건 (이미 끝난 {len(finished)}건 건너뜀)")
    lock = threading.Lock()

    def one(case: EvalCase, rep: int) -> None:
        recorder = RecordingProvider(make_provider())
        started = time.monotonic()
        try:
            result = explain_report(case_report(case), recorder, lookup, effort=config.effort)
        except Exception as exc:  # 실행기 결함·예상 못한 오류도 결과를 막지 않고 기록한다
            _append(
                variant_dir / "errors.jsonl",
                _error_row(case, rep, "harness", str(exc), recorder),
                lock,
            )
            return
        latency = time.monotonic() - started
        _write_trace(variant_dir, case, rep, recorder)
        if result.failures:
            error = result.failures[0].error
            _append(
                variant_dir / "errors.jsonl",
                _error_row(case, rep, _failure_class(error), error, recorder),
                lock,
            )
            on_event(f"  실패 {case.id} #{rep}: {error}")
            return
        [explanation] = result.explanations
        outcome = CaseOutcome(
            case=case,
            explanation=explanation,
            first_draft=recorder.attempts[0].parsed,  # type: ignore[arg-type]
            prompts=[a.prompt for a in recorder.attempts],
        )
        graded = grade(outcome, golden, lookup)
        _append(
            variant_dir / "results.jsonl",
            _result_row(case, rep, recorder, graded.scores, graded.details, latency, harness),
            lock,
        )
        on_event(f"  완료 {case.id} #{rep}: 검증 {graded.scores['verified']:.0f}")

    with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
        futures = {pool.submit(one, case, rep): (case, rep) for case, rep in todo}
        deadline = time.monotonic() + config.timeout_s * max(
            1, math.ceil(len(todo) / config.concurrency)
        )
        _, pending = wait(futures, timeout=max(0.0, deadline - time.monotonic()))
        for future in pending:  # 시간 상한을 넘긴 시도는 결과에서 빼고 기록만 한다
            case, rep = futures[future]
            future.cancel()
            _append(
                variant_dir / "errors.jsonl",
                {
                    "prompt_id": case.id,
                    "rep": rep,
                    "class": "timeout",
                    "error": f"{config.timeout_s:.0f}초 상한 초과",
                },
                lock,
            )
    return variant_dir


# --- 행 만들기 ---


def _usage_of(recorder: RecordingProvider) -> dict[str, int]:
    total = Usage(0, 0, 0, 0)
    for attempt in recorder.attempts:
        total = total + attempt.usage
    return {
        "input_tokens": total.input_tokens,
        "output_tokens": total.output_tokens,
        "cache_read_input_tokens": total.cache_read_input_tokens,
        "cache_creation_input_tokens": total.cache_write_input_tokens,
    }


def _cost_of(recorder: RecordingProvider) -> float | None:
    costs = [estimate_cost(a.model, a.usage) for a in recorder.attempts]
    return None if any(c is None for c in costs) else sum(c for c in costs if c is not None)


def _result_row(
    case: EvalCase,
    rep: int,
    recorder: RecordingProvider,
    scores: dict[str, float | None],
    details: dict[str, Any],
    latency: float,
    harness: str,
) -> dict[str, Any]:
    models = {a.model for a in recorder.attempts}
    return {
        "prompt_id": case.id,
        "rep": rep,
        # 전체 프롬프트는 원문 구간을 담으므로 traces(커밋 안 함)에만 둔다 (ADR-012)
        "prompt": f"{case.rule_id} {case.title}",
        "tags": list(case.tags),
        "split": case.source,
        "status": "ok",
        "stop_reason": "end_turn",
        "grade": scores,
        "model": sorted(models)[0] if len(models) == 1 else ",".join(sorted(models)),
        "usage": _usage_of(recorder),
        "latency_s": round(latency, 2),
        "cost_usd": _cost_of(recorder),
        "attempts": len(recorder.attempts),
        "meta": {"title": case.title, "rule_id": case.rule_id, "harness_sha": harness, **details},
    }


def _error_row(
    case: EvalCase, rep: int, kind: str, error: str, recorder: RecordingProvider
) -> dict[str, Any]:
    return {
        "prompt_id": case.id,
        "rep": rep,
        "class": kind,
        "error": error,
        "attempts": len(recorder.attempts),
        "usage": _usage_of(recorder),  # 실패한 시도도 비용은 들었다
        "cost_usd": _cost_of(recorder),
    }


def _failure_class(error: str) -> str:
    if "마스킹" in error:
        return "masking_blocked"
    if "거부" in error:
        return "refusal"
    if "잘림" in error:
        return "truncated"
    return "api_error"


def _write_trace(variant_dir: Path, case: EvalCase, rep: int, recorder: RecordingProvider) -> None:
    turns: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
    for attempt in recorder.attempts:
        turns.append({"role": "user", "content": attempt.prompt})
        turns.append(
            {
                "role": "assistant",
                "content": attempt.parsed.model_dump_json(indent=1),
                "model": attempt.model,
            }
        )
    path = variant_dir / "traces" / f"{case.id}_rep{rep}.json"
    path.write_text(json.dumps(turns, ensure_ascii=False, indent=1), "utf-8")


def _append(path: Path, row: dict[str, Any], lock: threading.Lock) -> None:
    with lock, path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


# --- 요약 ---


def summarize(variant_dir: Path) -> str:
    """지표별 평균과 95% 신뢰구간(정규 근사), 비용·지연·오류를 Markdown으로."""
    results = _rows(variant_dir / "results.jsonl")
    errors = _rows(variant_dir / "errors.jsonl")
    done = {(r["prompt_id"], r["rep"]) for r in results}
    open_errors = [e for e in errors if (e["prompt_id"], e["rep"]) not in done]
    lines = [
        f"# 해설 평가 결과 — {variant_dir.name}",
        "",
        f"채점된 시도 {len(results)}건 (케이스 {len({r['prompt_id'] for r in results})}개), "
        f"채점 못한 실패 {len(open_errors)}건",
        "",
        "| 지표 | 평균 | 95% 신뢰구간 | n |",
        "|---|---|---|---|",
    ]
    for metric in METRICS:
        values = [r["grade"][metric] for r in results if r["grade"].get(metric) is not None]
        if not values:
            lines.append(f"| {METRIC_LABELS[metric]} | - | - | 0 |")
            continue
        mean = statistics.fmean(values)
        half = 1.96 * statistics.stdev(values) / math.sqrt(len(values)) if len(values) > 1 else 0.0
        lines.append(f"| {METRIC_LABELS[metric]} | {mean:.1%} | ±{half:.1%} | {len(values)} |")
    costs = [r["cost_usd"] for r in results if r.get("cost_usd") is not None]
    costs += [e["cost_usd"] for e in errors if e.get("cost_usd")]
    latencies = [r["latency_s"] for r in results]
    lines += ["", "| 항목 | 값 |", "|---|---|"]
    if costs:
        lines.append(
            f"| 비용 합계 | ${sum(costs):.2f} (시도당 평균 ${statistics.fmean(costs):.3f}) |"
        )
    if latencies:
        lines.append(
            f"| 지연 (중앙값 / 최대) | {statistics.median(latencies):.1f}초 "
            f"/ {max(latencies):.1f}초 |"
        )
    if results:
        retried = sum(1 for r in results if r["attempts"] > 1)
        lines.append(f"| 재시도한 시도 | {retried}건 |")
    if open_errors:
        lines += ["", "채점 못한 실패:", ""]
        lines += [
            f"- {e['prompt_id']} #{e['rep']} ({e['class']}): {e['error']}" for e in open_errors
        ]
    failing = [
        (r["prompt_id"], r["rep"], m)
        for r in results
        for m in METRICS
        if r["grade"].get(m) is not None and r["grade"][m] < 1.0
    ]
    if failing:
        lines += ["", "만점이 아닌 지표:", ""]
        lines += [f"- {case_id} #{rep}: {METRIC_LABELS[m]}" for case_id, rep, m in failing]
    return "\n".join(lines) + "\n"


def _rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]


def regrade(
    variant_dir: Path,
    cases: Sequence[EvalCase],
    lookup: SourceLookup,
    golden: Golden,
    harness: str,
) -> int:
    """기록된 응답(traces)을 재생해 다시 채점한다. 사용량·비용·지연은 처음 기록을 유지한다."""
    by_id = {case.id: case for case in cases}
    rows = _rows(variant_dir / "results.jsonl")
    for row in rows:
        case = by_id[row["prompt_id"]]
        trace_path = variant_dir / "traces" / f"{case.id}_rep{row['rep']}.json"
        trace = json.loads(trace_path.read_text("utf-8"))
        recorder = RecordingProvider(ReplayProvider(trace))
        result = explain_report(case_report(case), recorder, lookup, effort="replay")
        [explanation] = result.explanations
        outcome = CaseOutcome(
            case=case,
            explanation=explanation,
            first_draft=recorder.attempts[0].parsed,  # type: ignore[arg-type]
            prompts=[a.prompt for a in recorder.attempts],
        )
        graded = grade(outcome, golden, lookup)
        row["grade"] = graded.scores
        row["meta"] = {**row["meta"], **graded.details, "harness_sha": harness}
    path = variant_dir / "results.jsonl"
    temp = path.with_name(path.name + ".tmp")
    temp.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), "utf-8")
    temp.replace(path)
    return len(rows)
