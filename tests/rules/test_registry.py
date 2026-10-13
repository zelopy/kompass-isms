"""룰 레지스트리·실행기 테스트."""

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

import pytest

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule
from kompass.rules.registry import RULES, evaluate

T0 = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
RULES_DOC = Path(__file__).parents[2] / "docs" / "RULES.md"


def _snapshot(service: str) -> Snapshot:
    return Snapshot(
        service=service, account_id="123456789012", regions=(), collected_at=T0, data={}
    )


class _PassRule(BaseRule):
    id: ClassVar[str] = "TST-001"
    service: ClassVar[str] = "test"
    title: ClassVar[str] = "테스트 룰"
    severity: ClassVar[Severity] = Severity.LOW

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        return [
            self.finding(
                snapshot,
                resource=ACCOUNT_RESOURCE,
                region=None,
                status=Status.PASS,
                message="ok",
                evidence={},
            )
        ]


class _SilentRule(_PassRule):
    id: ClassVar[str] = "TST-002"

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        return []


class _WrongIdRule(_PassRule):
    id: ClassVar[str] = "TST-003"

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        [finding] = super().evaluate(snapshot, settings)
        return [Finding.model_validate({**finding.model_dump(), "rule_id": "TST-999"})]


# --- 실행기 ---


def test_finding_uses_rule_metadata_and_snapshot_time() -> None:
    result = evaluate({"test": _snapshot("test")}, Settings(), rules=(_PassRule(),))
    [finding] = result.findings
    assert finding.rule_id == "TST-001"
    assert finding.severity == Severity.LOW
    assert finding.collected_at == T0  # 판정 시각이 아니라 증적 수집 시각
    assert result.skipped == ()


def test_rule_without_snapshot_is_skipped_not_passed() -> None:
    # 수집하지 않은 서비스의 룰은 PASS가 아니라 "건너뜀"이다
    result = evaluate({}, Settings(), rules=(_PassRule(),))
    assert result.findings == ()
    assert result.skipped == ("TST-001",)


def test_rule_must_emit_at_least_one_finding() -> None:
    # finding이 없으면 항목 집계에서 "점검하지 않음"과 구분할 수 없다
    with pytest.raises(RuntimeError, match="TST-002"):
        evaluate({"test": _snapshot("test")}, Settings(), rules=(_SilentRule(),))


def test_rule_must_emit_its_own_id() -> None:
    with pytest.raises(RuntimeError, match="TST-003"):
        evaluate({"test": _snapshot("test")}, Settings(), rules=(_WrongIdRule(),))


def test_duplicate_rule_ids_rejected() -> None:
    with pytest.raises(ValueError, match="TST-001"):
        evaluate({}, Settings(), rules=(_PassRule(), _PassRule()))


# --- 등록된 룰 ---


def test_registered_rule_ids_are_unique() -> None:
    ids = [rule.id for rule in RULES]
    assert len(ids) == len(set(ids))


def test_registered_rules_are_documented() -> None:
    # 룰 ID는 docs/RULES.md와 일치해야 한다 (CLAUDE.md 코드 규칙)
    documented = set(
        re.findall(r"^### ([A-Z][A-Z0-9]*-\d{3}) ", RULES_DOC.read_text("utf-8"), re.M)
    )
    assert {rule.id for rule in RULES} <= documented


def test_registered_rule_titles_match_docs() -> None:
    text = RULES_DOC.read_text(encoding="utf-8")
    for rule in RULES:
        assert f"### {rule.id} {rule.title}\n" in text
