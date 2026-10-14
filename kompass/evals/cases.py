"""평가 케이스 읽기·쓰기, 케이스로 보고서 만들기, 검토용 목록 (ADR-033).

케이스 파일은 `evals/explain/cases/<id>.json` 하나씩이다. 실행기는 케이스마다 실제 매핑을 붙인
보고서(`case_report`)를 만들어 실제 해설 흐름에 넣는다.
"""

import json
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from kompass.mappings.data import load_mappings
from kompass.mappings.mapper import build_report
from kompass.models import AuditReport, EvalCase, EvaluationReport, ScanManifest, Status

EVAL_ACCOUNT = "123456789012"  # 평가 케이스의 가짜 계정 ID
EVAL_TIME = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
NEEDS_ACTION = frozenset({Status.FAIL, Status.ERROR, Status.REVIEW})
_MARKDOWN_FULL = 5  # 해설 대상이 이보다 많으면 검토 목록에는 앞의 일부만 보여준다
_MARKDOWN_SAMPLE = 3


class CaseError(ValueError):
    """케이스 파일이 규칙에 맞지 않는다."""


def validate_case(case: EvalCase) -> None:
    foreign = {f.rule_id for f in case.findings} - {case.rule_id}
    if foreign:
        raise CaseError(f"{case.id}: 다른 룰의 finding이 섞여 있다: {sorted(foreign)}")
    if not any(f.status in NEEDS_ACTION for f in case.findings):
        raise CaseError(f"{case.id}: 해설 대상(FAIL·ERROR·REVIEW) finding이 없다")
    keys = [f.key for f in case.findings]
    if len(keys) != len(set(keys)):
        raise CaseError(f"{case.id}: finding 식별자가 중복된다")
    if not re.fullmatch(r"[a-z0-9-]+", case.id):
        raise CaseError(f"케이스 ID는 소문자·숫자·하이픈만 쓴다: {case.id}")


def write_cases(cases: Iterable[EvalCase], directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for case in cases:
        validate_case(case)
        path = directory / f"{case.id}.json"
        path.write_text(case.model_dump_json(indent=1) + "\n", encoding="utf-8")
        paths.append(path)
    return paths


def load_cases(directory: Path) -> list[EvalCase]:
    cases = [
        EvalCase.model_validate_json(path.read_bytes()) for path in sorted(directory.glob("*.json"))
    ]
    for case in cases:
        validate_case(case)
    ids = [c.id for c in cases]
    if len(ids) != len(set(ids)):
        raise CaseError("케이스 ID가 중복된다")
    return cases


def case_report(case: EvalCase) -> AuditReport:
    """케이스의 finding에 실제 매핑을 붙인 보고서. 실행기와 테스트가 같은 경로를 쓴다."""
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
        findings=case.findings,
    )
    return build_report(manifest, evaluation, load_mappings())


def cases_markdown(cases: Sequence[EvalCase]) -> str:
    """검토용 목록 (사용자 승인 1). 케이스마다 해설 대상 finding의 내용과 증적을 보여준다."""
    sources = Counter(c.source for c in cases)
    lines = [
        "# 해설 평가 케이스",
        "",
        f"총 {len(cases)}개 (실습 가공 {sources['lab']}, 보강 {sources['synthetic']}). "
        "모두 가짜 데이터임. 케이스 하나 = 룰 묶음 하나, "
        "해설 대상은 FAIL·ERROR·REVIEW finding임.",
        "",
        "| ID | 출처 | 룰 | 해설 대상 | 전체 | 태그 | 상황 |",
        "|---|---|---|---|---|---|---|",
    ]
    for case in cases:
        action = Counter(f.status.value for f in case.findings if f.status in NEEDS_ACTION)
        counts = ", ".join(f"{k} {v}" for k, v in sorted(action.items()))
        lines.append(
            f"| {case.id} | {case.source} | {case.rule_id} | {counts} | {len(case.findings)} "
            f"| {', '.join(case.tags)} | {case.title} |"
        )
    for case in cases:
        lines += ["", f"## {case.id} — {case.title}", ""]
        targets = [f for f in case.findings if f.status in NEEDS_ACTION]
        shown = targets if len(targets) <= _MARKDOWN_FULL else targets[:_MARKDOWN_SAMPLE]
        for finding in shown:
            body = json.dumps(finding.evidence, ensure_ascii=False, indent=1)
            fence = "`" * max(3, max((len(r) for r in re.findall(r"`+", body)), default=0) + 1)
            lines += [
                f"- **{finding.status.value}** `{finding.key}` — {finding.message}",
                "",
                f"{fence}json",
                body,
                fence,
                "",
            ]
        if len(shown) < len(targets):
            lines += [
                f"- 같은 형태의 해설 대상 {len(targets) - len(shown)}건 더 있음 (케이스 파일 참고)",
                "",
            ]
        others = Counter(f.status.value for f in case.findings if f.status not in NEEDS_ACTION)
        if others:
            lines.append(
                "함께 담긴 다른 finding: "
                + ", ".join(f"{k} {v}" for k, v in sorted(others.items()))
            )
    return "\n".join(lines) + "\n"
