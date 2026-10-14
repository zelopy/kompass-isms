"""해설 평가셋 실행 (ADR-033). 결과: .claude/hillclimb/explain/<variant>/

    uv run python scripts/run_explain_eval.py --provider oracle     # 무료 점검 (정답 해설)
    uv run python scripts/run_explain_eval.py --dry-run             # 예상 입력 토큰·비용
    uv run python scripts/run_explain_eval.py --cases a,b --reps 1  # 파일럿
    uv run python scripts/run_explain_eval.py                       # 전체 (Claude, 비용 발생)

다시 실행하면 이미 채점한 (케이스, 반복)은 건너뛴다.
결과를 처음부터 다시 만들려면 variant 폴더를 지운다.
"""

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from kompass.config import load_settings
from kompass.evals.cases import case_report, load_cases
from kompass.evals.grader import load_golden
from kompass.evals.providers import NullProvider, OracleProvider
from kompass.evals.runner import RunConfig, harness_digest, run, summarize, write_state
from kompass.interpreter.explainer import estimate_explanation
from kompass.interpreter.llm import ClaudeProvider, LLMError, LLMProvider, Usage, estimate_cost
from kompass.interpreter.sources import SourceIndexError, SourceLookup, load_index
from kompass.snapshots import project_root

ROOT = project_root() or Path.cwd()
EVAL_DIR = ROOT / "evals" / "explain"
OUT_DIR = ROOT / ".claude" / "hillclimb" / "explain"
HARNESS = [
    ROOT / "scripts" / "run_explain_eval.py",
    ROOT / "kompass" / "evals",
    EVAL_DIR,
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--variant", default="baseline", help="결과 폴더 이름 (baseline, v1, v2, ...)"
    )
    parser.add_argument("--reps", type=int, default=2)
    parser.add_argument("--cases", help="쉼표로 구분한 케이스 ID (파일럿). 없으면 전체")
    parser.add_argument("--provider", choices=("claude", "oracle", "null"), default="claude")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout-s", type=float, default=600.0)
    parser.add_argument("--config", type=Path, help="kompass.yaml (llm 설정)")
    parser.add_argument(
        "--dry-run", action="store_true", help="해설을 요청하지 않고 입력 토큰만 센다"
    )
    args = parser.parse_args()

    settings = load_settings(args.config)
    cases = load_cases(EVAL_DIR / "cases")
    if args.cases:
        wanted = {c.strip() for c in args.cases.split(",")}
        unknown = wanted - {c.id for c in cases}
        if unknown:
            print(f"오류: 없는 케이스: {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        cases = [c for c in cases if c.id in wanted]
    golden = load_golden(EVAL_DIR / "golden.yaml")
    try:
        lookup = SourceLookup(load_index())
    except SourceIndexError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 2

    make_provider: Callable[[], LLMProvider]
    if args.provider == "oracle":
        make_provider = lambda: OracleProvider(golden)  # noqa: E731
    elif args.provider == "null":
        make_provider = NullProvider
    else:
        try:
            ClaudeProvider(settings.llm)  # API 키 확인
        except LLMError as exc:
            print(f"오류: {exc}", file=sys.stderr)
            return 2
        make_provider = lambda: ClaudeProvider(settings.llm)  # noqa: E731

    if args.dry_run:
        provider = make_provider()
        tokens = sum(
            estimate_explanation(case_report(c), provider, lookup).input_tokens for c in cases
        )
        total = tokens * args.reps
        cost = estimate_cost(provider.model, Usage(total, 3000 * len(cases) * args.reps, 0, 0))
        print(f"케이스 {len(cases)}개 × {args.reps}회, 입력 토큰 {total:,}")
        print(
            "예상 비용: "
            + (
                f"약 ${cost:.2f} (출력 시도당 3,000 토큰 가정, 재시도 제외)"
                if cost
                else "단가 모름"
            )
        )
        return 0

    harness = harness_digest(HARNESS)
    write_state(OUT_DIR, harness)
    config = RunConfig(OUT_DIR, args.variant, args.reps, args.concurrency, args.timeout_s,
                       settings.llm.effort)  # fmt: skip
    variant_dir = run(cases, make_provider, lookup, golden, config, harness, on_event=print)
    summary = summarize(variant_dir)
    (variant_dir / "metrics.md").write_text(summary, encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
