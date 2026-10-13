"""룰 공용 부품 테스트."""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from kompass.rules.base import parse_aws_datetime


@pytest.mark.parametrize("value", [None, "", "N/A", "no_information", "not_supported"])
def test_special_values_are_none(value: str | None) -> None:
    # 자격증명 보고서의 특수 값. "사용 안 함"이 아니라 "날짜 없음"이다
    assert parse_aws_datetime(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-13T08:38:24Z", datetime(2026, 10, 13, 8, 38, 24, tzinfo=UTC)),
        ("2026-10-13T08:38:24+00:00", datetime(2026, 10, 13, 8, 38, 24, tzinfo=UTC)),
        ("2026-10-13T17:38:24+09:00", datetime(2026, 10, 13, 8, 38, 24, tzinfo=UTC)),
        ("2026-10-13T08:38:24.123Z", datetime(2026, 10, 13, 8, 38, 24, 123000, tzinfo=UTC)),
    ],
)
def test_iso_values_are_utc(value: str, expected: datetime) -> None:
    parsed = parse_aws_datetime(value)
    assert parsed == expected
    assert parsed is not None and parsed.utcoffset() == timedelta(0)


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValueError):
        parse_aws_datetime("2026-10-13T08:38:24")


def test_garbage_rejected() -> None:
    # 예상하지 못한 값은 조용히 None으로 만들지 않는다 (ADR-023)
    with pytest.raises(ValueError):
        parse_aws_datetime("yesterday")


def test_offset_timezone_preserved_as_utc() -> None:
    kst = timezone(timedelta(hours=9))
    assert parse_aws_datetime("2026-10-13T09:00:00+09:00") == datetime(2026, 10, 13, 9, tzinfo=kst)
