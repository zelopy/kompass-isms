"""공용 모델과 항목 단위 집계 테스트."""

from datetime import UTC, datetime
from itertools import combinations
from typing import Any

import pytest
from pydantic import ValidationError

from kompass.models import (
    Automation,
    CollectError,
    Finding,
    Mappings,
    Severity,
    Snapshot,
    Status,
    aggregate_status,
)

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)


def _finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "rule_id": "S3-001",
        "resource": "account",
        "region": None,
        "status": Status.FAIL,
        "severity": Severity.HIGH,
        "message": "계정 수준 퍼블릭 액세스 차단이 설정되지 않음",
        "evidence": {"PublicAccessBlockConfiguration": None},
        "collected_at": NOW,
    }
    fields.update(overrides)
    return Finding(**fields)


def _snapshot(**overrides: Any) -> Snapshot:
    fields: dict[str, Any] = {
        "service": "s3",
        "account_id": "123456789012",
        "regions": ["ap-northeast-2"],
        "collected_at": NOW,
        "data": {},
    }
    fields.update(overrides)
    return Snapshot(**fields)


# --- Status / Severity ---


def test_status_values_match_report_format() -> None:
    assert [s.value for s in Status] == ["PASS", "FAIL", "ERROR", "REVIEW", "N/A"]


def test_severity_values() -> None:
    assert [s.value for s in Severity] == ["critical", "high", "medium", "low", "info"]


# --- Finding ---


def test_finding_is_immutable() -> None:
    finding = _finding()
    with pytest.raises(ValidationError):
        finding.status = Status.PASS  # type: ignore[misc]  # mypy도 막는다: 의도된 위반


def test_finding_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        _finding(llm_opinion="양호로 보임")


def test_finding_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError):
        _finding(collected_at=datetime(2026, 10, 13, 12, 0))


def test_finding_mappings_default_to_none() -> None:
    assert _finding().mappings is None


def test_finding_accepts_mappings() -> None:
    mappings = Mappings(kisa=["CA-10"], isms_p=["2.10.2"], verified=False)
    assert _finding(mappings=mappings).mappings == mappings


def test_finding_round_trips_through_json() -> None:
    finding = _finding(region="ap-northeast-2", status=Status.NOT_APPLICABLE)
    assert Finding.model_validate_json(finding.model_dump_json()) == finding


# --- Snapshot ---


def test_snapshot_errors_default_to_empty() -> None:
    assert _snapshot().errors == []


def test_snapshot_records_collect_errors() -> None:
    error = CollectError(
        operation="s3control:GetPublicAccessBlock",
        region=None,
        error_code="AccessDenied",
        message="User is not authorized",
    )
    assert _snapshot(errors=[error]).errors == [error]


@pytest.mark.parametrize("account_id", ["12345678901", "1234567890123", "12345678901a", ""])
def test_snapshot_rejects_invalid_account_id(account_id: str) -> None:
    with pytest.raises(ValidationError):
        _snapshot(account_id=account_id)


def test_snapshot_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError):
        _snapshot(collected_at=datetime(2026, 10, 13, 12, 0))


# --- aggregate_status: 대표 사례 ---


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([Status.FAIL, Status.ERROR, Status.PASS], Status.FAIL),
        ([Status.ERROR, Status.REVIEW, Status.PASS], Status.ERROR),
        ([Status.REVIEW, Status.PASS, Status.NOT_APPLICABLE], Status.REVIEW),
        ([Status.PASS, Status.NOT_APPLICABLE], Status.PASS),
        ([Status.PASS], Status.PASS),
        ([Status.NOT_APPLICABLE, Status.NOT_APPLICABLE], Status.NOT_APPLICABLE),
    ],
)
def test_aggregate_full(statuses: list[Status], expected: Status) -> None:
    assert aggregate_status(statuses, Automation.FULL) == expected


def test_aggregate_defaults_to_full() -> None:
    assert aggregate_status([Status.PASS]) == Status.PASS


@pytest.mark.parametrize("automation", [Automation.PARTIAL, Automation.MANUAL])
def test_aggregate_caps_pass_at_review_when_not_full(automation: Automation) -> None:
    assert aggregate_status([Status.PASS, Status.NOT_APPLICABLE], automation) == Status.REVIEW


@pytest.mark.parametrize("automation", [Automation.PARTIAL, Automation.MANUAL])
def test_aggregate_keeps_not_applicable_when_not_full(automation: Automation) -> None:
    assert aggregate_status([Status.NOT_APPLICABLE], automation) == Status.NOT_APPLICABLE


def test_aggregate_rejects_empty() -> None:
    with pytest.raises(ValueError, match="finding"):
        aggregate_status([])


def test_aggregate_accepts_generator() -> None:
    assert aggregate_status(s for s in [Status.PASS, Status.FAIL]) == Status.FAIL


# --- aggregate_status: 모든 조합에 대한 불변 조건 (ADR-005, ADR-009, ADR-013) ---

ALL_COMBINATIONS = [
    list(combo) for size in range(1, len(Status) + 1) for combo in combinations(Status, size)
]


@pytest.mark.parametrize("automation", list(Automation))
@pytest.mark.parametrize("statuses", ALL_COMBINATIONS, ids=lambda c: "+".join(s.value for s in c))
def test_aggregate_invariants(statuses: list[Status], automation: Automation) -> None:
    result = aggregate_status(statuses, automation)
    present = set(statuses)

    # 집계 결과는 항상 입력에 있던 상태이거나, PASS가 REVIEW로 낮아진 것이다
    assert result in present or (result == Status.REVIEW and Status.PASS in present)
    # 확인된 취약점이 있으면 항목은 취약이다
    if Status.FAIL in present:
        assert result == Status.FAIL
    # 확인하지 못한 것이 섞이면 절대 양호가 아니다
    if Status.ERROR in present:
        assert result in (Status.FAIL, Status.ERROR)
    # full이 아닌 항목은 자동으로 양호가 되지 않는다
    if automation is not Automation.FULL:
        assert result != Status.PASS
    # 해당 없음은 모든 finding이 해당 없음일 때만이다
    if result == Status.NOT_APPLICABLE:
        assert present == {Status.NOT_APPLICABLE}
