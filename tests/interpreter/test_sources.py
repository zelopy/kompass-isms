"""기준 문서 원문 색인: PDF 텍스트를 항목 코드 단위로 자르기, 인용 검증 (ADR-029).

픽스처는 실제 PDF 추출 결과의 구조(쪽 머리글, 줄바꿈, 분야 표기)만 흉내 낸 가공 텍스트다.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kompass.interpreter.sources import (
    INDEX_ENV,
    SourceIndexError,
    SourceLookup,
    default_index_path,
    load_index,
    normalize_for_match,
    split_isms_p,
    split_kisa,
)
from kompass.models import SourceDocument, SourceEntry, SourceIndex

KISA_PAGES = [
    (
        854,
        "| 한국인터넷진흥원 |\n854 \nCA-01\n(상)\n클라우드 > 1. 계정 관리\n사용자 계정 관리\n"
        "개요\n점검 내용 불필요한 계정 존재 여부 점검\n"
        "판단 기준\n양호 : 불필요한 계정이 존재하지 않는 경우\n"
        "§ 퇴사자 및 장기 미사용 계정은 삭제 또는 비활성화 하여 클라우드 서비\n스를 운영해야 함\n",
    ),
    (
        855,
        "12. 클라우드\n2026  주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드\n855 \n"
        "CA-02\n(중)\n클라우드 > 1. 계정 관리\n사용자 정책 관리\n개요\n점검 내용 권한 부여 점검\n",
    ),
    (
        856,
        "| 한국인터넷진흥원 |\n856 \n§ 관리자 권한은 분리하여 운영해야 함\n",
    ),
]
KISA_TITLES = {"CA-01": "사용자 계정 관리", "CA-02": "사용자 정책 관리"}

ANNEX_PAGES = [
    (
        1,
        "[별표 7] <전문개정>\n인증기준(제23조 관련)\n"
        "가. 관리체계 수립 및 운영\n분야 항목 상세 내용\n"
        "1.1.  관리체계 기반 마련 1.1.1 경영진의 참여 최고경영자는 보고 및 의사결정 체계를 "
        "수립하여 운영하여야 한다.\n"
        "　 　 1.1.2 최고책임자의 지정\n최고경영자는 정보보호 최고책\n임자를 임원급으로 \n"
        "지정하여야 한다.\n",
    ),
    (
        2,
        "나. 보호대책 요구사항\n분야 항목 상세 내용\n"
        "2.5. 인증 및 권한관리 2.5.1 사용자 계정 관리\n사용자 계정은 승인 절차를 거쳐 \n"
        "부여하여야 한다.\n3.3. \n개인정보 \n제공 시 \n보호조치\n"
        "3.3.1 개인정보 제3자 제공\n법적 근거에 의하거나 동의를 받아야 한다.\n",
    ),
]
ANNEX_TITLES = {
    "1.1.1": "경영진의 참여",
    "1.1.2": "최고책임자의 지정",
    "2.5.1": "사용자 계정 관리",
    "3.3.1": "개인정보 제3자 제공",
}


# --- KISA ---


def test_kisa_items_split_by_code_without_page_headers() -> None:
    entries = split_kisa(KISA_PAGES, KISA_TITLES)
    assert set(entries) == {"CA-01", "CA-02"}
    first = entries["CA-01"]
    assert first.title == "사용자 계정 관리"
    assert first.page == 854
    assert "양호 : 불필요한 계정이 존재하지 않는 경우" in first.text
    assert "한국인터넷진흥원" not in first.text
    assert "CA-02" not in first.text


def test_kisa_item_spanning_pages_keeps_continuation() -> None:
    second = split_kisa(KISA_PAGES, KISA_TITLES)["CA-02"]
    assert "관리자 권한은 분리하여 운영해야 함" in second.text
    assert "상세가이드" not in second.text and "856" not in second.text


def test_kisa_missing_item_is_an_error() -> None:
    with pytest.raises(SourceIndexError, match="CA-03"):
        split_kisa(KISA_PAGES, {**KISA_TITLES, "CA-03": "MFA 설정"})


def test_kisa_title_mismatch_is_an_error() -> None:
    # 판이 바뀌어 항목 이름이 달라졌으면 색인을 만들지 않는다
    with pytest.raises(SourceIndexError, match="CA-02"):
        split_kisa(KISA_PAGES, {**KISA_TITLES, "CA-02": "다른 이름"})


# --- ISMS-P 별표 7 ---


def test_annex_controls_split_by_code_and_name() -> None:
    entries = split_isms_p(ANNEX_PAGES, ANNEX_TITLES)
    assert set(entries) == set(ANNEX_TITLES)
    assert entries["1.1.1"].text == "최고경영자는 보고 및 의사결정 체계를 수립하여 운영하여야 한다."
    assert entries["2.5.1"].page == 2


def test_annex_wrapped_lines_are_joined() -> None:
    # 끝에 공백이 없는 줄바꿈은 단어 중간에서 끊긴 것이다
    entries = split_isms_p(ANNEX_PAGES, ANNEX_TITLES)
    assert entries["1.1.2"].text == "최고경영자는 정보보호 최고책임자를 임원급으로 지정하여야 한다."


def test_annex_area_and_section_labels_are_removed() -> None:
    entries = split_isms_p(ANNEX_PAGES, ANNEX_TITLES)
    assert entries["1.1.2"].text.endswith("지정하여야 한다.")
    assert entries["2.5.1"].text == "사용자 계정은 승인 절차를 거쳐 부여하여야 한다."
    assert "보호대책 요구사항" not in entries["1.1.2"].text


def test_annex_area_label_split_across_lines_is_removed() -> None:
    # 실제 별표 7: "2.10" / "." / "시스템 및 " … 처럼 분야 표기가 여러 줄로 끊긴다
    pages = [
        (
            6,
            "2.9.7 정보자산의 재사용 및 폐기 폐기 절차를 수립하여야 한다.\n"
            "2.10\n.\n시스템 및 \n서비스 \n보안관리\n"
            "2.10.1 보안시스템 운영\n정책을 수립하여야 한다.\n",
        )
    ]
    entries = split_isms_p(
        pages, {"2.9.7": "정보자산의 재사용 및 폐기", "2.10.1": "보안시스템 운영"}
    )
    assert entries["2.9.7"].text == "폐기 절차를 수립하여야 한다."


def test_annex_name_matches_across_dot_variants() -> None:
    # 매핑 YAML은 "·"(U+00B7), 별표 7은 "ㆍ"(U+318D)를 쓴다
    pages = [(9, "3.1.1 개인정보 수집ㆍ이용\n개인정보는 적법하게 수집하여야 한다.\n")]
    entries = split_isms_p(pages, {"3.1.1": "개인정보 수집·이용"})
    assert entries["3.1.1"].text == "개인정보는 적법하게 수집하여야 한다."


def test_annex_missing_control_is_an_error() -> None:
    with pytest.raises(SourceIndexError, match=r"2\.5\.3"):
        split_isms_p(ANNEX_PAGES, {**ANNEX_TITLES, "2.5.3": "사용자 인증"})


# --- 인용 검증 ---


def _index() -> SourceIndex:
    return SourceIndex(
        built_at=datetime(2026, 10, 14, tzinfo=UTC),
        documents={"kisa": SourceDocument(file="kisa.pdf", sha256="0" * 64)},
        kisa=split_kisa(KISA_PAGES, KISA_TITLES),
        isms_p=split_isms_p(ANNEX_PAGES, ANNEX_TITLES),
    )


def test_normalize_ignores_whitespace_and_dot_variants() -> None:
    assert normalize_for_match("예산ㆍ인력  등\n자원") == normalize_for_match("예산·인력 등 자원")


def test_quote_found_across_line_breaks() -> None:
    lookup = SourceLookup(_index())
    assert lookup.contains_quote("kisa", "CA-01", "클라우드 서비스를 운영해야 함")
    assert lookup.contains_quote("isms_p", "1.1.2", "정보보호 최고책임자를 임원급으로")


def test_quote_from_another_item_is_rejected() -> None:
    lookup = SourceLookup(_index())
    assert not lookup.contains_quote("kisa", "CA-02", "불필요한 계정이 존재하지 않는 경우")


def test_unknown_code_and_too_short_quote_are_rejected() -> None:
    lookup = SourceLookup(_index())
    assert not lookup.contains_quote("kisa", "CA-99", "계정")
    assert not lookup.contains_quote("kisa", "CA-01", "계정")  # 너무 짧으면 근거가 아니다
    assert not lookup.contains_quote("kisa", "CA-01", "  ")


def test_entry_lookup() -> None:
    lookup = SourceLookup(_index())
    entry = lookup.entry("isms_p", "2.5.1")
    assert isinstance(entry, SourceEntry) and entry.title == "사용자 계정 관리"
    assert lookup.entry("isms_p", "9.9.9") is None


# --- 색인 파일 ---


def test_load_index_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "index.json"
    path.write_text(_index().model_dump_json(), encoding="utf-8")
    assert load_index(path) == _index()


def test_missing_index_explains_how_to_build(tmp_path: Path) -> None:
    with pytest.raises(SourceIndexError, match="build_source_index"):
        load_index(tmp_path / "index.json")


def test_invalid_index_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "index.json"
    path.write_text(json.dumps({"format_version": 1}), encoding="utf-8")
    with pytest.raises(SourceIndexError):
        load_index(path)


def test_default_index_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(INDEX_ENV, str(tmp_path / "x.json"))
    assert default_index_path() == tmp_path / "x.json"
    monkeypatch.delenv(INDEX_ENV)
    assert default_index_path().parts[-2:] == ("knowledge", "index.json")
