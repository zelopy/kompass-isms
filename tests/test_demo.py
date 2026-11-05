"""공개 데모: 가공 데이터만 쓰고, 커밋된 HTML이 현재 리포터 출력과 같은지 확인한다."""

import re
from pathlib import Path

from kompass.demo import DEMO_ACCOUNT, DEMO_PATH, demo_report
from kompass.models import Status
from kompass.reporters.html_reporter import extract_payload, render_html

ROOT = Path(__file__).resolve().parents[1]


def test_demo_report_is_deterministic() -> None:
    assert render_html(demo_report()) == render_html(demo_report())


def test_demo_uses_example_account_only() -> None:
    assert demo_report().scan.account_id == DEMO_ACCOUNT == "123456789012"
    # 화면에 나오는 12자리 숫자(계정 ID 모양)는 예시 계정뿐이어야 한다
    assert set(
        re.findall(r"(?<![0-9A-Za-z])\d{12}(?![0-9A-Za-z])", render_html(demo_report()))
    ) == {DEMO_ACCOUNT}


def test_demo_covers_every_view() -> None:
    report = demo_report()
    assert {f.status for f in report.findings} == set(Status)
    assert report.scan.excluded_regions
    assert report.evaluation.skipped_rules
    assert report.explanations is not None and report.explanations.assessment is not None
    assert any(not e.verified and e.problems for e in report.explanations.explanations)
    assert report.investigations is not None and report.investigations.investigations
    assert report.evidence_reviews is not None and report.evidence_reviews.unreadable


def test_demo_citations_are_short() -> None:
    explanations = demo_report().explanations
    assert explanations is not None
    for item in explanations.explanations:
        assert all(len(c.quote) <= 20 for c in item.explanation.citations)


def test_demo_explanations_point_at_demo_findings() -> None:
    report = demo_report()
    keys = {f.key for f in report.findings}
    assert report.explanations is not None and report.investigations is not None
    for item in report.explanations.explanations:
        assert set(item.finding_keys) <= keys
    for inv in report.investigations.investigations:
        assert set(inv.finding_keys) <= keys


def test_demo_is_up_to_date() -> None:
    committed = (ROOT / DEMO_PATH).read_text(encoding="utf-8")
    assert committed == render_html(demo_report()), (
        "docs/demo/index.html이 현재 리포터 출력과 다름. "
        "`uv run python scripts/build_demo.py`로 다시 생성 필요"
    )
    assert extract_payload(committed)["report"]["scan"]["account_id"] == DEMO_ACCOUNT
