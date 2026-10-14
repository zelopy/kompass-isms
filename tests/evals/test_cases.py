"""평가 케이스 로더·검증·보고서 변환 (ADR-033)."""

from pathlib import Path

import pytest

from kompass.evals.cases import (
    CaseError,
    case_report,
    cases_markdown,
    load_cases,
    validate_case,
    write_cases,
)
from kompass.models import EvalCase, Status
from tests.reporters.sample import finding

CASES_DIR = Path(__file__).parents[2] / "evals" / "explain" / "cases"


def _case(**overrides: object) -> EvalCase:
    fields: dict[str, object] = {
        "id": "syn-sg-001",
        "title": "관리 포트 전체 개방",
        "source": "synthetic",
        "rule_id": "SG-001",
        "tags": ("ec2", "fail"),
        "findings": (
            finding("SG-001", Status.FAIL, "sg-0123456789abcdef0", "ap-northeast-2"),
            finding("SG-001", Status.PASS, "sg-0fedcba9876543210", "ap-northeast-2"),
        ),
    }
    return EvalCase.model_validate({**fields, **overrides})


def test_round_trip(tmp_path: Path) -> None:
    write_cases([_case()], tmp_path)
    assert load_cases(tmp_path) == [_case()]


def test_case_must_need_action() -> None:
    with pytest.raises(CaseError, match="해설 대상"):
        validate_case(_case(findings=(finding("SG-001", Status.PASS, "sg-1"),)))


def test_case_must_hold_one_rule() -> None:
    with pytest.raises(CaseError, match="다른 룰"):
        validate_case(_case(findings=(finding("SG-002", Status.FAIL, "sg-1"),)))


def test_case_id_format() -> None:
    with pytest.raises(CaseError, match="케이스 ID"):
        validate_case(_case(id="Bad_ID"))


def test_case_report_attaches_real_mappings() -> None:
    report = case_report(_case())
    [fail] = [f for f in report.findings if f.status == Status.FAIL]
    assert fail.mappings is not None and "CA-09" in fail.mappings.kisa
    assert report.scan.account_id == "123456789012"


def test_markdown_lists_action_findings() -> None:
    text = cases_markdown([_case()])
    assert "| syn-sg-001 | synthetic | SG-001 | FAIL 1 | 2 |" in text
    assert "`SG-001:ap-northeast-2:sg-0123456789abcdef0`" in text
    assert "함께 담긴 다른 finding: PASS 1" in text


@pytest.mark.skipif(not CASES_DIR.is_dir(), reason="평가 케이스가 아직 없음")
def test_committed_cases_are_valid() -> None:
    cases = load_cases(CASES_DIR)
    assert len(cases) >= 30
    for case in cases:
        case_report(case)  # 매핑이 모두 붙는다
