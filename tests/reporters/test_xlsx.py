"""Excel 점검표 리포터."""

import io
from typing import Any

from openpyxl import load_workbook

from kompass.models import Status
from kompass.reporters.xlsx_reporter import render_xlsx
from tests.reporters.sample import DEFAULT, EXPLAINED, finding, sample_report

SHEETS = ["요약", "KISA 항목", "점검 결과", "ISMS-P (초안)"]


def _book(report: Any = DEFAULT) -> Any:
    return load_workbook(io.BytesIO(render_xlsx(report)))


def _rows(sheet: Any) -> list[tuple[Any, ...]]:
    return [tuple(row) for row in sheet.iter_rows(values_only=True)]


def test_sheets() -> None:
    assert _book().sheetnames == SHEETS


def test_summary_sheet() -> None:
    values = [v for row in _rows(_book()["요약"]) for v in row if v is not None]
    assert any("인증 심사 결과를 보장하지 않는다" in str(v) for v in values)
    assert "123456789012" in values
    assert "2026-10-14 08:07:54 KST ~ 2026-10-14 08:07:54 KST" in values


def test_kisa_sheet_has_19_items_with_labels() -> None:
    sheet = _book()["KISA 항목"]
    rows = _rows(sheet)
    assert rows[0][:5] == ("코드", "항목", "중요도", "분류", "결과")
    assert len(rows) == 1 + 19
    ca09 = next(r for r in rows if r[0] == "CA-09")
    assert ca09[4] == "취약"
    assert sheet.freeze_panes == "A2"
    assert sheet.auto_filter.ref is not None


def test_findings_sheet_lists_every_finding() -> None:
    rows = _rows(_book()["점검 결과"])
    assert len(rows) == 1 + len(DEFAULT.findings)
    header = rows[0]
    sg = next(r for r in rows[1:] if r[header.index("리소스")] == "sg-1" and r[0] == "SG-001")
    assert sg[header.index("결과")] == "취약"
    assert sg[header.index("KISA")] == "CA-09"
    assert "open|ssh" in sg[header.index("증적")]


def test_isms_p_sheet_has_all_controls() -> None:
    rows = _rows(_book()["ISMS-P (초안)"])
    assert len(rows) == 1 + 101
    first = rows[1]
    assert first[0] == "1.1.1"
    assert first[1] == "관리체계 수립 및 운영"
    assert first[2] == "경영진의 참여"


def test_status_cells_are_colored() -> None:
    sheet = _book()["KISA 항목"]
    header = [c.value for c in sheet[1]]
    col = header.index("결과") + 1
    fills = {sheet.cell(row=r, column=col).value: sheet.cell(row=r, column=col).fill.fgColor.rgb
             for r in range(2, sheet.max_row + 1)}  # fmt: skip
    assert fills["취약"] != fills["양호"]


def test_formula_injection_is_neutralized() -> None:
    # 점검 대상 계정의 누군가가 정할 수 있는 값(ENI 설명, 태그 등)이 수식으로 실행되면 안 된다
    malicious = '=HYPERLINK("http://evil.example","click")'
    report = sample_report(
        finding("VPC-002", Status.REVIEW, "eni-1", "ap-northeast-2", malicious, {"d": malicious})
    )
    sheet = _book(report)["점검 결과"]
    cells = [c for row in sheet.iter_rows(min_row=2) for c in row if c.value == malicious]
    assert cells, "악성 문자열이 그대로 보존되어야 한다"
    assert all(c.data_type == "s" for c in cells)


def test_long_evidence_is_truncated_to_excel_limit() -> None:
    report = sample_report(finding("S3-004", Status.FAIL, "b", None, "m", {"x": "a" * 40000}))
    rows = _rows(_book(report)["점검 결과"])
    header = rows[0]
    assert len(rows[1][header.index("증적")]) <= 32767


# --- AI 해설 ---


def test_explanation_sheet_only_when_explained() -> None:
    assert "AI 해설 (참고)" not in _book().sheetnames
    assert _book(EXPLAINED).sheetnames == [*SHEETS, "AI 해설 (참고)"]


def test_explanation_sheet_rows() -> None:
    rows = _rows(_book(EXPLAINED)["AI 해설 (참고)"])
    header, *body = rows
    assert header[:4] == ("룰", "검증", "우선순위", "대상 finding")
    assert [(r[0], r[1]) for r in body] == [
        ("SG-001", "검증됨"),
        ("S3-004", "검증되지 않음"),
        ("IAM-008", "해설 실패"),
    ]


def test_explanation_commands_are_not_formulas() -> None:
    sheet = _book(EXPLAINED)["AI 해설 (참고)"]
    cells = [
        c for row in sheet.iter_rows(min_row=2) for c in row if str(c.value).startswith("=cmd")
    ]
    assert cells and all(c.data_type == "s" for c in cells)


def test_summary_mentions_explanations() -> None:
    values = [v for row in _rows(_book(EXPLAINED)["요약"]) for v in row if v is not None]
    assert any("검증됨 1" in str(v) and "실패 1" in str(v) for v in values)
