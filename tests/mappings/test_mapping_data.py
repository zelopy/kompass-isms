"""매핑 데이터 무결성 테스트.

매핑은 코드와 분리된 데이터다 (ADR-002). 문서(RULES.md, COVERAGE.md)·룰 레지스트리·ISMS-P
항목 목록과 어긋나면 보고서가 잘못된 항목에 결과를 붙이므로 여기서 모두 대조한다.
"""

import re
from pathlib import Path

import pytest

from kompass.mappings.data import load_mappings
from kompass.models import Automation
from kompass.rules.registry import RULES

DOCS = Path(__file__).parents[2] / "docs"
DATA = load_mappings()


def test_counts() -> None:
    assert len(DATA.kisa_items) == 19
    assert len(DATA.isms_p_controls) == 101
    assert set(DATA.isms_p_areas) == {"1", "2", "3"}


def test_every_registered_rule_is_mapped_and_vice_versa() -> None:
    assert set(DATA.rules) == {rule.id for rule in RULES}


def test_rule_kisa_codes_exist() -> None:
    for rule_id, mapping in DATA.rules.items():
        assert set(mapping.kisa) <= set(DATA.kisa_items), rule_id


@pytest.mark.parametrize("source", ["rules", "items"])
def test_isms_p_codes_exist(source: str) -> None:
    mappings = DATA.rules if source == "rules" else DATA.kisa_items
    for key, mapping in mappings.items():
        assert set(mapping.isms_p) <= set(DATA.isms_p_controls), key


def test_isms_p_codes_are_ordered_by_area() -> None:
    for code in DATA.isms_p_controls:
        assert code.split(".")[0] in DATA.isms_p_areas


def test_isms_p_mappings_are_marked_unverified() -> None:
    # ISMS-P 매핑은 사용자가 확인하기 전까지 초안이다 (원칙 7)
    assert not any(m.isms_p_verified for m in DATA.rules.values())
    assert not any(i.isms_p_verified for i in DATA.kisa_items.values())


def test_digest_is_sha256() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", DATA.digest)


# --- 문서와의 일치 ---


def _rule_sections(text: str) -> dict[str, str]:
    parts = re.split(r"^### ", text, flags=re.M)
    return {p.split(" ", 1)[0]: p for p in parts[1:] if re.match(r"[A-Z][A-Z0-9]*-\d{3} ", p)}


def test_rules_md_kisa_matches() -> None:
    sections = _rule_sections((DOCS / "RULES.md").read_text(encoding="utf-8"))
    for rule_id, mapping in DATA.rules.items():
        line = re.search(r"^- KISA: (.+)$", sections[rule_id], re.M)
        assert line is not None, rule_id
        documented = re.findall(r"CA-\d{2}", line.group(1).split("—")[0])
        if "대응 항목 없음" in line.group(1):
            documented = []
        assert tuple(documented) == mapping.kisa, rule_id


def _expand(cell: str) -> set[str]:
    """COVERAGE.md 룰 칸의 "SG-001~003, S3-006" 같은 표기를 펼친다."""
    rules: set[str] = set()
    for part in re.findall(r"[A-Z][A-Z0-9]*-\d{3}(?:~\d{3})?", cell):
        if "~" in part:
            prefix, rest = part.split("-")
            start, end = (int(x) for x in rest.split("~"))
            rules |= {f"{prefix}-{n:03d}" for n in range(start, end + 1)}
        else:
            rules.add(part)
    return rules


def test_coverage_md_summary_matches() -> None:
    text = (DOCS / "COVERAGE.md").read_text(encoding="utf-8")
    rows = re.findall(
        r"^\| (CA-\d{2}) \| [^|]+ \| (상|중|하) \| (\d+) \| (\w+) \| ([^|]+) \|", text, re.M
    )
    assert len(rows) == 19
    for code, importance, page, automation, rule_cell in rows:
        item = DATA.kisa_items[code]
        assert item.importance == importance, code
        assert item.page == int(page), code
        assert item.automation == Automation(automation), code
        assert _expand(rule_cell) == set(DATA.rules_for_item(code)), code


# --- 증적 요청 카탈로그 (ADR-037) ---


def test_every_kisa_item_has_evidence_requests() -> None:
    assert set(DATA.evidence) == set(DATA.kisa_items)
    for code, item in DATA.evidence.items():
        assert item.requests, code
        assert [r.id for r in item.requests] == [
            f"{code}-{n}" for n in range(1, len(item.requests) + 1)
        ]


def test_evidence_requests_are_marked_unverified() -> None:
    # 요청 문구는 원문을 근거로 작성한 것이라 사용자가 확인하기 전까지 초안이다 (원칙 7)
    assert not any(item.verified for item in DATA.evidence.values())


def test_evidence_request_sentences_are_terse() -> None:
    # 보고서 문장은 개조식 명사형으로 끝맺는다 (CLAUDE.md)
    for item in DATA.evidence.values():
        for r in item.requests:
            for text in (r.request, r.purpose):
                assert not text.rstrip(".").endswith(("다", "요")), text


def test_evidence_basis_quotes_exist_in_source() -> None:
    # 원문 색인은 커밋하지 않으므로(ADR-012) 색인이 있는 환경에서만 대조한다
    from kompass.interpreter.sources import SourceIndexError, SourceLookup, load_index

    try:
        lookup = SourceLookup(load_index())
    except SourceIndexError:
        pytest.skip("원문 색인 없음 (knowledge/SOURCES.md)")
    for code, item in DATA.evidence.items():
        for r in item.requests:
            assert lookup.contains_quote("kisa", code, r.basis), (r.id, r.basis)
            assert not lookup.is_boilerplate("kisa", r.basis), (r.id, r.basis)
