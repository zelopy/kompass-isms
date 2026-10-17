import hashlib
from pathlib import Path

import pytest
from openpyxl import Workbook
from pypdf import PdfWriter

from kompass.interpreter.documents import EvidenceFolderError, load_submission
from kompass.models import EvidenceFileKind

REQUESTS = ("CA-01-1", "CA-02-1", "CA-09-2")


def _text_pdf(text: str) -> bytes:
    """텍스트 한 줄이 든 최소 PDF (ASCII)."""
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        b" /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for n, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)


def _write(root: Path, relative: str, data: bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _only(root: Path, request_id: str = "CA-02-1"):  # type: ignore[no-untyped-def]
    [file] = load_submission(root, REQUESTS).for_request(request_id)
    return file


def test_text_files_are_read_as_utf8(tmp_path: Path) -> None:
    data = "계정 목록\nalice\t재직\n".encode()
    _write(tmp_path, "CA-01-1/users.txt", data)
    [file] = load_submission(tmp_path, REQUESTS).for_request("CA-01-1")
    assert file.kind == EvidenceFileKind.TEXT
    assert file.text == "계정 목록\nalice\t재직\n"
    assert file.problem is None
    assert file.path == "CA-01-1/users.txt"
    assert file.sha256 == hashlib.sha256(data).hexdigest() and file.size == len(data)


def test_utf8_bom_and_cp949_csv_are_decoded(tmp_path: Path) -> None:
    _write(tmp_path, "CA-02-1/a.csv", "﻿이름,권한\n".encode())
    _write(tmp_path, "CA-09-2/b.csv", "이름,권한\n".encode("cp949"))
    submission = load_submission(tmp_path, REQUESTS)
    assert [f.text for f in submission.files] == ["이름,권한\n", "이름,권한\n"]


def test_undecodable_text_is_a_problem(tmp_path: Path) -> None:
    _write(tmp_path, "CA-02-1/a.txt", b"\xff\xfe\x00\xd8broken\x81")
    file = _only(tmp_path)
    assert file.text is None and file.problem is not None and "인코딩" in file.problem


def test_xlsx_sheets_become_tab_separated_rows(tmp_path: Path) -> None:
    book = Workbook()
    sheet = book.active
    assert sheet is not None
    sheet.title = "권한"
    sheet.append(["사용자", "그룹"])
    sheet.append(["alice", None])
    sheet.append([None, None])
    book.create_sheet("빈 시트")
    book.save(tmp_path / "x.xlsx")
    _write(tmp_path, "CA-02-1/perm.xlsx", (tmp_path / "x.xlsx").read_bytes())
    file = _only(tmp_path)
    assert file.kind == EvidenceFileKind.XLSX
    assert file.text == "[시트: 권한]\n사용자\t그룹\nalice\n\n[시트: 빈 시트]\n"


def test_pdf_text_is_extracted_with_page_markers(tmp_path: Path) -> None:
    _write(tmp_path, "CA-02-1/review.pdf", _text_pdf("Policy review 2026-09-30"))
    file = _only(tmp_path)
    assert file.kind == EvidenceFileKind.PDF and file.problem is None
    assert file.text is not None
    assert file.text.startswith("[쪽 1]\n") and "Policy review 2026-09-30" in file.text


def test_pdf_without_text_is_treated_as_scanned(tmp_path: Path) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.write(tmp_path / "blank.pdf")
    _write(tmp_path, "CA-02-1/scan.pdf", (tmp_path / "blank.pdf").read_bytes())
    file = _only(tmp_path)
    assert file.kind == EvidenceFileKind.PDF and file.text is None
    assert file.problem is not None and "스캔" in file.problem


def test_encrypted_pdf_is_a_problem(tmp_path: Path) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.encrypt("secret")
    writer.write(tmp_path / "enc.pdf")
    _write(tmp_path, "CA-02-1/enc.pdf", (tmp_path / "enc.pdf").read_bytes())
    file = _only(tmp_path)
    assert file.text is None and file.problem is not None and "암호" in file.problem


def test_broken_pdf_is_a_problem(tmp_path: Path) -> None:
    _write(tmp_path, "CA-02-1/broken.pdf", b"not a pdf")
    file = _only(tmp_path)
    assert file.text is None and file.problem is not None and "읽지 못함" in file.problem


def test_unsupported_formats_are_kept_for_human_review(tmp_path: Path) -> None:
    _write(tmp_path, "CA-02-1/screen.png", b"\x89PNG\r\n")
    file = _only(tmp_path)
    assert file.kind is None and file.text is None
    assert file.problem is not None and "지원하지 않는 형식" in file.problem


def test_large_files_are_not_read(tmp_path: Path) -> None:
    _write(tmp_path, "CA-02-1/big.txt", b"x" * 11)
    [file] = load_submission(tmp_path, REQUESTS, max_bytes=10).files
    assert file.text is None and file.problem is not None and "너무 큼" in file.problem
    assert file.size == 11


def test_nested_files_and_lowercase_folders_are_accepted(tmp_path: Path) -> None:
    _write(tmp_path, "ca-09-2/2026/q3/rules.md", b"# rules\n")
    [file] = load_submission(tmp_path, REQUESTS).files
    assert file.request_id == "CA-09-2" and file.path == "ca-09-2/2026/q3/rules.md"


def test_unknown_folders_root_files_and_lock_files_are_ignored(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    _write(root, "CA-99-1/a.txt", b"x")
    _write(root, "notes/a.txt", b"x")
    _write(root, "readme.txt", b"x")
    _write(root, "CA-02-1/~$perm.xlsx", b"x")
    _write(root, "CA-02-1/.DS_Store", b"x")
    _write(root, "CA-02-1/ok.txt", b"ok")
    submission = load_submission(root, REQUESTS)
    assert [f.path for f in submission.files] == ["CA-02-1/ok.txt"]
    assert submission.ignored == (
        "CA-02-1/.DS_Store",
        "CA-02-1/~$perm.xlsx",
        "CA-99-1",
        "notes",
        "readme.txt",
    )


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    outside = _write(tmp_path / "outside", "secret.txt", b"secret")
    root = tmp_path / "evidence"
    (root / "CA-02-1").mkdir(parents=True)
    try:
        (root / "CA-02-1" / "link.txt").symlink_to(outside)
    except OSError:
        pytest.skip("이 환경에서는 심볼릭 링크를 만들 수 없음")
    submission = load_submission(root, REQUESTS)
    assert submission.files == () and submission.ignored == ("CA-02-1/link.txt",)


def test_files_are_ordered_by_request_then_path(tmp_path: Path) -> None:
    _write(tmp_path, "CA-09-2/b.txt", b"b")
    _write(tmp_path, "CA-01-1/z.txt", b"z")
    _write(tmp_path, "CA-01-1/a.txt", b"a")
    paths = [f.path for f in load_submission(tmp_path, REQUESTS).files]
    assert paths == ["CA-01-1/a.txt", "CA-01-1/z.txt", "CA-09-2/b.txt"]


def test_missing_folder_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(EvidenceFolderError, match="증적 폴더가 없습니다"):
        load_submission(tmp_path / "nope", REQUESTS)
