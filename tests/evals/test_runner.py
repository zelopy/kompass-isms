"""평가 실행기: 결과 파일 형식, 재개, 실패 기록, 요약 (ADR-033). 실제 API는 쓰지 않는다."""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from kompass.evals.cases import load_cases
from kompass.evals.grader import METRICS, load_golden
from kompass.evals.providers import OracleProvider
from kompass.evals.runner import (
    RunConfig,
    done_keys,
    harness_digest,
    regrade,
    run,
    summarize,
    write_state,
)
from kompass.interpreter.llm import LLMError, LLMResponse
from kompass.interpreter.sources import SourceIndexError, SourceLookup, load_index

EVAL_DIR = Path(__file__).parents[2] / "evals" / "explain"
GOLDEN = load_golden(EVAL_DIR / "golden.yaml")
CASES = load_cases(EVAL_DIR / "cases")[:3]


@pytest.fixture
def lookup() -> SourceLookup:
    try:
        return SourceLookup(load_index())
    except SourceIndexError:
        pytest.skip("원문 색인이 없음")


def _rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text("utf-8").splitlines()]


def test_oracle_run_writes_results_traces_and_summary(tmp_path: Path, lookup: SourceLookup) -> None:
    config = RunConfig(tmp_path, reps=2, concurrency=2)
    variant = run(CASES, lambda: OracleProvider(GOLDEN), lookup, GOLDEN, config, "sha")
    rows = _rows(variant / "results.jsonl")
    assert len(rows) == 6 and {r["status"] for r in rows} == {"ok"}
    row = rows[0]
    assert set(row["grade"]) == set(METRICS)
    assert {"prompt_id", "rep", "prompt", "tags", "usage", "model", "latency_s"} <= set(row)
    assert row["prompt"].startswith(row["meta"]["rule_id"])  # 원문이 든 전체 프롬프트는 traces에만
    trace = json.loads(
        (variant / "traces" / f"{row['prompt_id']}_rep{row['rep']}.json").read_text("utf-8")
    )
    assert [t["role"] for t in trace[:3]] == ["system", "user", "assistant"]
    summary = summarize(variant)
    assert "| 검증 통과 | 100.0% |" in summary and "채점된 시도 6건" in summary


def test_resume_skips_finished_attempts(tmp_path: Path, lookup: SourceLookup) -> None:
    config = RunConfig(tmp_path, reps=1)
    run(CASES, lambda: OracleProvider(GOLDEN), lookup, GOLDEN, config, "sha")
    calls: list[str] = []

    class Counting(OracleProvider):
        def complete[T: BaseModel](
            self, system: str, prompt: str, schema: type[T]
        ) -> LLMResponse[T]:
            calls.append(prompt)
            return super().complete(system, prompt, schema)

    run(CASES, lambda: Counting(GOLDEN), lookup, GOLDEN, config, "sha")
    assert calls == []
    assert done_keys(tmp_path / "baseline") == {(c.id, 0) for c in CASES}


def test_api_errors_go_to_errors_file_not_zero_scores(tmp_path: Path, lookup: SourceLookup) -> None:
    class Failing(OracleProvider):
        def complete[T: BaseModel](
            self, system: str, prompt: str, schema: type[T]
        ) -> LLMResponse[T]:
            raise LLMError("Claude API 호출 실패: 529 overloaded")

    variant = run(
        CASES[:1], lambda: Failing(GOLDEN), lookup, GOLDEN, RunConfig(tmp_path, reps=1), "sha"
    )
    assert not (variant / "results.jsonl").exists()
    [error] = _rows(variant / "errors.jsonl")
    assert error["class"] == "api_error" and "529" in error["error"]
    assert done_keys(variant) == set()  # 다시 실행하면 이 시도만 다시 돈다
    assert "채점 못한 실패 1건" in summarize(variant)


def test_state_declares_metrics_with_headline_first(tmp_path: Path) -> None:
    write_state(tmp_path, "sha")
    state = json.loads((tmp_path / "_state.json").read_text("utf-8"))
    assert [m["id"] for m in state["metrics"]] == list(METRICS)
    assert state["metrics"][0] == {"id": "verified", "label": "검증 통과", "kind": "binary"}
    assert all(len(m["label"]) <= 14 for m in state["metrics"])


def test_harness_digest_changes_with_files(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1", "utf-8")
    before = harness_digest([tmp_path])
    (tmp_path / "a.py").write_text("x = 2", "utf-8")
    assert harness_digest([tmp_path]) != before


def test_regrade_replays_traces_without_calling_the_model(
    tmp_path: Path, lookup: SourceLookup
) -> None:
    variant = run(
        CASES, lambda: OracleProvider(GOLDEN), lookup, GOLDEN, RunConfig(tmp_path, reps=1), "old"
    )
    before = _rows(variant / "results.jsonl")
    assert regrade(variant, CASES, lookup, GOLDEN, "new") == len(CASES)
    after = _rows(variant / "results.jsonl")
    assert [r["grade"] for r in after] == [r["grade"] for r in before]
    assert [r["usage"] for r in after] == [r["usage"] for r in before]  # 원래 사용량 유지
    assert {r["meta"]["harness_sha"] for r in after} == {"new"}
