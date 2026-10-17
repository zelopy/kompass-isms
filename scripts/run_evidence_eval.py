"""증적 검토 평가셋 실행 (ADR-049). 결과: .claude/hillclimb/evidence/<variant>/

    uv run python scripts/run_evidence_eval.py --provider oracle     # 무료 점검 (정답 검토)
    uv run python scripts/run_evidence_eval.py --dry-run             # 예상 입력 토큰·비용
    uv run python scripts/run_evidence_eval.py --cases a,b --reps 1  # 파일럿
    uv run python scripts/run_evidence_eval.py                       # 전체 (Claude, 비용 발생)

다시 실행하면 그 variant의 결과를 덮어쓴다. 케이스는 모두 가공한 가짜 문서다.
"""

import argparse
import json
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from kompass.config import load_settings
from kompass.evals.evidence import (
    EvidenceCase,
    NullProvider,
    OracleProvider,
    case_report,
    load_cases,
    regrade,
    run,
    summarize,
    write_files,
)
from kompass.interpreter.documents import load_submission
from kompass.interpreter.evidence_reviewer import estimate_review
from kompass.interpreter.llm import ClaudeProvider, LLMError, LLMProvider
from kompass.interpreter.sources import SourceIndexError, SourceLookup, load_index
from kompass.mappings.data import load_mappings
from kompass.snapshots import project_root

ROOT = project_root() or Path.cwd()
EVAL_DIR = ROOT / "evals" / "evidence"
OUT_DIR = ROOT / ".claude" / "hillclimb" / "evidence"
OUTPUT_TOKENS = 3000  # 시도당 출력 토큰 가정


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--variant", default="baseline", help="결과 폴더 이름")
    parser.add_argument("--reps", type=int, default=2)
    parser.add_argument("--cases", help="쉼표로 구분한 케이스 ID (파일럿). 없으면 전체")
    parser.add_argument("--provider", choices=("claude", "oracle", "null"), default="claude")
    parser.add_argument("--config", type=Path, help="kompass.yaml (llm 설정)")
    parser.add_argument("--dry-run", action="store_true", help="검토를 요청하지 않고 토큰만 센다")
    parser.add_argument(
        "--regrade", action="store_true", help="기록된 응답으로 다시 채점한다 (API 호출 없음)"
    )
    args = parser.parse_args()

    llm = load_settings(args.config).llm
    cases = load_cases(EVAL_DIR / "cases")
    if args.cases:
        wanted = {c.strip() for c in args.cases.split(",")}
        unknown = wanted - {c.id for c in cases}
        if unknown:
            print(f"오류: 없는 케이스: {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        cases = [c for c in cases if c.id in wanted]
    if args.regrade:
        variant_dir = OUT_DIR / args.variant
        summary = summarize(regrade(cases, variant_dir))
        (variant_dir / "metrics.md").write_text(summary, encoding="utf-8")
        print(summary)
        return 0
    try:
        lookup = SourceLookup(load_index())
    except SourceIndexError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 2

    make_provider: Callable[[EvidenceCase], LLMProvider]
    if args.provider == "oracle":
        make_provider = OracleProvider
    elif args.provider == "null":
        make_provider = lambda case: NullProvider()  # noqa: E731
    else:
        try:
            ClaudeProvider(llm)  # API 키 확인
        except LLMError as exc:
            print(f"오류: {exc}", file=sys.stderr)
            return 2
        make_provider = lambda case: ClaudeProvider(llm)  # noqa: E731

    if args.dry_run:
        return _dry_run(cases, make_provider, lookup, args.reps)

    variant_dir = run(cases, make_provider, lookup, OUT_DIR / args.variant, reps=args.reps)
    rows = [
        json.loads(line)
        for line in (variant_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    summary = summarize(rows)
    (variant_dir / "metrics.md").write_text(summary, encoding="utf-8")
    print(summary)
    return 0


def _dry_run(
    cases: list[EvidenceCase],
    make_provider: Callable[[EvidenceCase], LLMProvider],
    lookup: SourceLookup,
    reps: int,
) -> int:
    catalog = load_mappings().evidence
    request_ids = [r.id for item in catalog.values() for r in item.requests]
    tokens = 0
    requests = 0
    cost = 0.0
    for case in cases:
        with tempfile.TemporaryDirectory() as tmp:
            write_files(case, Path(tmp))
            submission = load_submission(Path(tmp), request_ids)
        estimate = estimate_review(
            case_report(case), submission, catalog, make_provider(case), lookup,
            terms=case.terms, output_tokens_per_request=OUTPUT_TOKENS,
        )  # fmt: skip
        if estimate.blocked:
            print(f"경고: {case.id} 마스킹 검증 실패로 보내지 않음: {', '.join(estimate.blocked)}")
        tokens += estimate.input_tokens
        requests += estimate.requests
        cost += estimate.cost_usd or 0.0
    print(f"케이스 {len(cases)}개(요청 {requests}개) × {reps}회, 입력 토큰 {tokens * reps:,}")
    print(
        f"예상 비용: 약 ${cost * reps:.2f} (출력 시도당 {OUTPUT_TOKENS:,} 토큰 가정, 재시도 제외)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
