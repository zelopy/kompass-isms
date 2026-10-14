"""기준 문서 PDF에서 항목 코드 단위 원문 색인(`knowledge/index.json`)을 만든다 (ADR-029).

    uv run --with pypdf python scripts/build_source_index.py

pypdf는 이 스크립트에서만 쓰므로 프로젝트 의존성에 넣지 않는다. 원문 파일은 knowledge/SOURCES.md의
출처에서 받아 두고, SHA-256이 기록과 다르면(판이 다르면) 색인을 만들지 않는다.
색인은 원문을 담으므로 커밋하지 않는다 (ADR-012, .gitignore).
"""

import argparse
import hashlib
import sys
from datetime import UTC, datetime
from pathlib import Path

from kompass.interpreter.sources import (
    Page,
    SourceIndexError,
    default_index_path,
    split_isms_p,
    split_kisa,
)
from kompass.mappings.data import load_mappings
from kompass.models import SourceDocument, SourceIndex
from kompass.snapshots import project_root

# knowledge/SOURCES.md와 같아야 한다
KISA_FILE = "kisa/주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf"
KISA_SHA256 = "44fe393981b244147be6af7423d99dc15633c089fad0bcb296cbe2371dde812d"
KISA_PAGES = (854, 872)  # XII. 클라우드 항목 본문 (CA-01 ~ CA-19). 873쪽은 뒤표지
ANNEX_FILE = (
    "isms_p/[별표 7] 인증기준(제23조 관련)"
    "(정보보호 및 개인정보보호 관리체계 인증 등에 관한 고시).pdf"
)
ANNEX_SHA256 = "0f0dc7f3a7789b75f3faaddb84e261b836a8541d9e962caacfc8e326ef69bd58"


def _read_pages(path: Path, first: int | None = None, last: int | None = None) -> list[Page]:
    from pypdf import PdfReader  # 스크립트 전용 의존성

    reader = PdfReader(path)
    first = first or 1
    last = last or len(reader.pages)
    return [(n, reader.pages[n - 1].extract_text() or "") for n in range(first, last + 1)]


def _document(knowledge: Path, relative: str, expected_sha256: str) -> tuple[Path, SourceDocument]:
    path = knowledge / relative
    if not path.is_file():
        raise SourceIndexError(f"원문 파일이 없습니다: {path} (knowledge/SOURCES.md 참고)")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise SourceIndexError(
            f"원문 파일 해시가 기록과 다릅니다: {path.name} ({digest}). "
            "판이 바뀌었으면 SOURCES.md와 매핑을 먼저 갱신해 주십시오"
        )
    return path, SourceDocument(file=relative, sha256=digest)


def build(knowledge: Path) -> SourceIndex:
    mappings = load_mappings()
    kisa_path, kisa_doc = _document(knowledge, KISA_FILE, KISA_SHA256)
    annex_path, annex_doc = _document(knowledge, ANNEX_FILE, ANNEX_SHA256)
    return SourceIndex(
        built_at=datetime.now(UTC),
        documents={"kisa": kisa_doc, "isms_p": annex_doc},
        kisa=split_kisa(
            _read_pages(kisa_path, *KISA_PAGES),
            {code: item.title for code, item in mappings.kisa_items.items()},
        ),
        isms_p=split_isms_p(_read_pages(annex_path), mappings.isms_p_controls),
    )


def main() -> int:
    root = project_root() or Path.cwd()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--knowledge", type=Path, default=root / "knowledge")
    parser.add_argument("--output", type=Path, default=default_index_path())
    args = parser.parse_args()
    try:
        index = build(args.knowledge)
    except SourceIndexError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(index.model_dump_json(indent=2), encoding="utf-8")
    print(f"KISA {len(index.kisa)}개, ISMS-P {len(index.isms_p)}개 → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
