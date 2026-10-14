"""기준 문서 원문 색인: 항목 코드로 원문을 꺼내고, LLM 인용이 원문에 있는지 확인한다 (ADR-029).

색인(`knowledge/index.json`)은 `scripts/build_source_index.py`가 PDF에서 만든다. 이 모듈의
자르기 함수는 PDF 라이브러리 없이 쪽별 텍스트만 받으므로 가공 텍스트로 시험할 수 있다.
원문을 담은 색인은 커밋하지 않는다 (ADR-012).

인용 비교는 공백과 가운뎃점 변형(ㆍ, ·)을 무시한다. PDF 추출 텍스트는 줄바꿈 위치가 원문 표의
폭에 따라 정해지므로 LLM이 옮긴 구절과 공백이 다를 수 있다.
"""

import os
import re
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from kompass.models import SourceEntry, SourceIndex
from kompass.snapshots import project_root

SourceScheme = Literal["kisa", "isms_p"]
Page = tuple[int, str]  # (PDF 쪽 번호, 그 쪽의 텍스트)

INDEX_ENV = "KOMPASS_SOURCE_INDEX"
BUILD_COMMAND = "uv run --with pypdf python scripts/build_source_index.py"
MIN_QUOTE_LENGTH = 6  # 공백을 뺀 글자 수. 이보다 짧은 구절은 근거로 보지 않는다

_DOTS = str.maketrans({"ㆍ": "·", "ᆞ": "·", "‧": "·", "・": "·"})
_DOT_CLASS = "[·ㆍᆞ‧・]"
_WHITESPACE = re.compile(r"\s+")


class SourceIndexError(Exception):
    """색인을 만들거나 읽을 수 없다."""


# --- 인용 검증 ---


def normalize_for_match(text: str) -> str:
    return _WHITESPACE.sub("", unicodedata.normalize("NFKC", text).translate(_DOTS))


class SourceLookup:
    """항목 코드로 원문을 꺼내고 인용 구절이 그 항목 원문에 있는지 확인한다."""

    def __init__(self, index: SourceIndex) -> None:
        self.documents = index.documents
        self._entries: dict[SourceScheme, Mapping[str, SourceEntry]] = {
            "kisa": index.kisa,
            "isms_p": index.isms_p,
        }
        self._normalized = {
            (scheme, code): normalize_for_match(entry.text)
            for scheme, entries in self._entries.items()
            for code, entry in entries.items()
        }

    def entry(self, scheme: SourceScheme, code: str) -> SourceEntry | None:
        return self._entries[scheme].get(code)

    def contains_quote(self, scheme: SourceScheme, code: str, quote: str) -> bool:
        needle = normalize_for_match(quote)
        haystack = self._normalized.get((scheme, code))
        return haystack is not None and len(needle) >= MIN_QUOTE_LENGTH and needle in haystack


# --- 색인 파일 ---


def default_index_path(cwd: Path | None = None) -> Path:
    configured = os.environ.get(INDEX_ENV)
    if configured:
        return Path(configured)
    start = (cwd or Path.cwd()).resolve()
    return (project_root(start) or start) / "knowledge" / "index.json"


def load_index(path: Path | None = None) -> SourceIndex:
    path = path or default_index_path()
    if not path.is_file():
        raise SourceIndexError(f"원문 색인이 없다: {path}. `{BUILD_COMMAND}`로 만든다")
    try:
        return SourceIndex.model_validate_json(path.read_bytes())
    except ValidationError as exc:
        raise SourceIndexError(
            f"원문 색인 형식이 맞지 않는다: {path}. 다시 만든다 ({exc})"
        ) from exc


# --- KISA 가이드 ---

_KISA_CODE = re.compile(r"CA-\d{2}")
_KISA_IMPORTANCE = re.compile(r"\((상|중|하)\)")
_KISA_NOISE = (
    re.compile(r"\| 한국인터넷진흥원 \|"),
    re.compile(r"\d{1,4}"),  # 쪽 번호
    re.compile(r"12\. 클라우드"),
    re.compile(r"\d{4}\s+주요정보통신기반시설.*상세가이드"),
)
_TITLE_WINDOW = 4  # 항목 코드 뒤 몇 줄 안에 항목 이름이 있어야 하는가


def split_kisa(pages: Sequence[Page], titles: Mapping[str, str]) -> dict[str, SourceEntry]:
    """KISA 클라우드 장을 항목(CA-xx) 단위로 자른다. `titles`는 kisa_items.yaml의 이름.

    항목은 `CA-xx` 줄 다음에 `(상|중|하)` 줄이 오는 곳에서 시작한다. 쪽 머리글·쪽 번호는 버린다.
    """
    lines: list[tuple[int, str]] = []
    for number, text in pages:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not any(p.fullmatch(stripped) for p in _KISA_NOISE):
                lines.append((number, stripped))

    starts = [
        i
        for i, (_, line) in enumerate(lines)
        if _KISA_CODE.fullmatch(line)
        and i + 1 < len(lines)
        and _KISA_IMPORTANCE.fullmatch(lines[i + 1][1])
    ]
    entries: dict[str, SourceEntry] = {}
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        page, code = lines[start]
        if code in entries:
            raise SourceIndexError(f"KISA 항목 {code}가 원문에 두 번 나온다")
        if code not in titles:
            raise SourceIndexError(f"kisa_items.yaml에 없는 KISA 항목이 원문에 있다: {code}")
        body = [line for _, line in lines[start:end]]
        head = normalize_for_match("".join(body[: _TITLE_WINDOW + 2]))
        if normalize_for_match(titles[code]) not in head:
            raise SourceIndexError(f"KISA 항목 {code}의 이름이 원문과 다르다: {titles[code]}")
        entries[code] = SourceEntry(title=titles[code], page=page, text="\n".join(body))
    _require_all("KISA 항목", titles, entries)
    return entries


# --- ISMS-P 인증기준 (고시 별표 7) ---

_ANNEX_NOISE = (
    re.compile(r"\[별표 7\].*"),
    re.compile(r"인증기준\(제23조 관련\)"),
    re.compile(r"[가-하]\. .+"),  # "나. 보호대책 요구사항"
    re.compile(r"분야 항목 상세 내용"),
)
# 분야 표기 "2.5. 인증 및 권한관리" (항목 번호 아님). 표 칸이 좁으면 "2.10" / "." 처럼 끊긴다
_AREA_LABEL = re.compile(r"(?:^|\s)\d\.\d{1,2}\s*\.(?=\s|$)")


def split_isms_p(pages: Sequence[Page], titles: Mapping[str, str]) -> dict[str, SourceEntry]:
    """별표 7을 통제항목 단위로 자른다. `titles`는 isms_p_controls.yaml의 번호 → 명칭.

    항목은 "번호 명칭"으로 찾는다. 본문은 다음 항목까지이며, 그 사이의 분야 표기("2.5. …")는
    버린다. 표 칸 폭 때문에 생긴 줄바꿈은 끝에 공백이 없으면 단어 중간으로 보고 붙인다.
    """
    text_parts: list[str] = []
    page_starts: list[tuple[int, int]] = []  # (텍스트 오프셋, 쪽 번호)
    offset = 0
    for number, text in pages:
        page_starts.append((offset, number))
        for line in text.replace("　", " ").splitlines():
            if any(p.fullmatch(line.strip()) for p in _ANNEX_NOISE):
                continue
            text_parts.append(line + "\n")
            offset += len(line) + 1
    text = "".join(text_parts)

    found: list[tuple[int, int, str]] = []  # (항목 시작, 본문 시작, 번호)
    for code, title in titles.items():
        name = r"\s*".join(_char_pattern(char) for char in title.replace(" ", ""))
        matches = list(re.finditer(rf"(?<![\d.]){re.escape(code)}\s+{name}", text))
        if len(matches) > 1:
            raise SourceIndexError(f"ISMS-P 통제항목 {code}가 원문에 두 번 나온다")
        if matches:
            found.append((matches[0].start(), matches[0].end(), code))
    _require_all("ISMS-P 통제항목", titles, {code for _, _, code in found})

    found.sort()
    entries: dict[str, SourceEntry] = {}
    for position, (start, body_start, code) in enumerate(found):
        end = found[position + 1][0] if position + 1 < len(found) else len(text)
        body = text[body_start:end]
        label = _AREA_LABEL.search(body)
        if label:
            body = body[: label.start()]
        page = max(number for page_offset, number in page_starts if page_offset <= start)
        entries[code] = SourceEntry(title=titles[code], page=page, text=_join_wrapped(body))
    return entries


def _char_pattern(char: str) -> str:
    return _DOT_CLASS if char.translate(_DOTS) == "·" else re.escape(char)


def _join_wrapped(body: str) -> str:
    joined = ""
    previous = ""
    for line in body.splitlines():
        piece = line.strip()
        if not piece:
            continue
        if joined:
            # 앞 줄이 공백이나 마침표로 끝났으면 낱말 경계, 아니면 단어 중간에서 끊긴 줄
            word_boundary = previous[-1:].isspace() or joined.endswith(".")
            joined += (" " if word_boundary else "") + piece
        else:
            joined = piece
        previous = line
    return _WHITESPACE.sub(" ", joined).strip()


def _require_all(
    kind: str, expected: Mapping[str, str], found: Mapping[str, object] | set[str]
) -> None:
    missing = sorted(set(expected) - set(found))
    if missing:
        raise SourceIndexError(f"원문에서 찾지 못한 {kind}: {', '.join(missing)}")
