"""HTML 리포터: 데이터 왕복, 신뢰할 수 없는 문자열 처리, CSP."""

import base64
import hashlib
import json
import re
from importlib.resources import files

from kompass.models import Status
from kompass.reporters._format import DISCLAIMER
from kompass.reporters.html_reporter import extract_payload, render_html
from kompass.reporters.json_reporter import render_json
from tests.reporters.sample import DEFAULT, finding, sample_report

HOSTILE = "</script><img src=x onerror=alert(1)><!--    {{SCRIPT}} &amp;"


def _b64sha(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _match(pattern: str, text: str) -> str:
    found = re.search(pattern, text, re.S)
    assert found is not None, pattern
    return found.group(1)


def test_payload_round_trips_report() -> None:
    payload = extract_payload(render_html(DEFAULT))
    assert payload["report"] == json.loads(render_json(DEFAULT))


def test_labels_come_from_format_constants() -> None:
    labels = extract_payload(render_html(DEFAULT))["labels"]
    assert labels["status"]["ERROR"] == "확인 불가"
    assert labels["outcome"]["NOT_IMPLEMENTED"] == "수동 점검 (미구현)"
    assert labels["notices"]["disclaimer"] == DISCLAIMER


def test_rule_titles_included() -> None:
    rules = extract_payload(render_html(DEFAULT))["rules"]
    assert rules["SG-001"]


def test_display_times_in_kst() -> None:
    display = extract_payload(render_html(DEFAULT))["display"]
    assert display["started_at"] == "2026-10-14 08:07:54 KST"


def test_hostile_strings_cannot_break_out() -> None:
    report = sample_report(
        finding("S3-004", Status.FAIL, HOSTILE, "ap-northeast-2", HOSTILE, {"k": HOSTILE})
    )
    html = render_html(report)
    assert html.count("<script") == 2  # 데이터 블록 1 + 뷰어 1
    assert "</script><img" not in html
    assert " " not in html and " " not in html
    [item] = extract_payload(html)["report"]["findings"]
    assert item["resource"] == HOSTILE
    assert item["message"] == HOSTILE
    assert item["evidence"]["k"] == HOSTILE


def test_csp_hashes_match_inline_code() -> None:
    html = render_html(DEFAULT)
    csp = _match(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
    script = _match(r"<script>(.*?)</script>", html)
    style = _match(r"<style>(.*?)</style>", html)
    assert f"script-src 'sha256-{_b64sha(script)}'" in csp
    assert f"style-src 'sha256-{_b64sha(style)}'" in csp
    assert "default-src 'none'" in csp
    assert "base-uri 'none'" in csp and "form-action 'none'" in csp
    assert "unsafe-inline" not in csp and "http" not in csp


def test_no_external_urls() -> None:
    assert not re.search(r"(src|href)=\"(https?:)?//", render_html(DEFAULT))


def test_viewer_js_avoids_unsafe_apis() -> None:
    js = (files("kompass.reporters") / "html" / "viewer.js").read_text(encoding="utf-8")
    for banned in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert banned not in js, banned
    assert not re.search(r"set(Timeout|Interval)\(\s*['\"`]", js)


def test_noscript_notice() -> None:
    assert "<noscript>" in render_html(DEFAULT)


def test_output_uses_lf_newlines() -> None:
    # 데모 동기화와 CSP 해시가 체크아웃 줄바꿈 설정에 따라 달라지지 않아야 한다
    assert "\r" not in render_html(DEFAULT)


def test_renders_report_without_findings() -> None:
    html = render_html(sample_report(skipped=("IAM-001",)))
    assert extract_payload(html)["report"]["findings"] == []


def test_payload_keeps_nested_evidence() -> None:
    deep = {"a": [{"b": [None, 1, {"2": "x" * 5000}]}]}
    report = sample_report(finding("S3-004", Status.FAIL, "b", "ap-northeast-2", "m", deep))
    assert extract_payload(render_html(report))["report"]["findings"][0]["evidence"] == deep
