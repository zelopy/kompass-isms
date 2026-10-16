"""IAM-005 장기 미사용 자격증명 (KISA CA-01, docs/RULES.md).

활성 자격증명(콘솔 비밀번호, 활성 액세스 키)별 마지막 사용일이 기준 일수를 넘으면 사용자 단위
FAIL. 한 번도 쓰지 않았으면 비밀번호는 설정일, 액세스 키는 생성(교체)일을 기준으로 한다.
기준 시각은 스냅샷 수집 시각이다.
"""

from datetime import datetime
from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import BaseRule, parse_aws_datetime
from kompass.rules.iam import _iam


def _credentials(row: dict[str, str]) -> list[tuple[str, str | None]]:
    """(자격증명 이름, 마지막 사용일 또는 대체 기준일) 목록."""
    items: list[tuple[str, str | None]] = []
    if _iam.is_true(row.get("password_enabled")):
        used = row.get("password_last_used")
        basis = used if parse_aws_datetime(used) else row.get("password_last_changed")
        items.append(("password", basis))
    for slot in _iam.active_key_slots(row):
        used = row.get(f"access_key_{slot}_last_used_date")
        basis = used if parse_aws_datetime(used) else row.get(f"access_key_{slot}_last_rotated")
        items.append((f"access_key_{slot}", basis))
    return items


class Iam005UnusedCredentials(BaseRule):
    id: ClassVar[str] = "IAM-005"
    service: ClassVar[str] = "iam"
    title: ClassVar[str] = "장기 미사용 자격증명"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        rows = _iam.report_rows(snapshot)
        if rows is None:
            return [_iam.missing_section(self, snapshot, "credential_report", "자격증명 보고서")]
        users = [r for r in _iam.user_rows(rows) if _iam.has_credentials(r)]
        limit = settings.iam.unused_credential_days
        findings = [self._judge(snapshot, row, limit) for row in users]
        findings += _iam.unreported_users(self, snapshot, rows)
        return findings or [
            _iam.account_finding(
                self, snapshot, Status.NOT_APPLICABLE, "활성 자격증명을 가진 사용자가 없음", {}
            )
        ]

    def _judge(self, snapshot: Snapshot, row: dict[str, str], limit: int) -> Finding:
        now: datetime = snapshot.collected_at
        credentials: list[dict[str, Any]] = []
        for name, basis in _credentials(row):
            when = parse_aws_datetime(basis)
            credentials.append(
                {
                    "credential": name,
                    "last_activity": basis,
                    "days_since_last_use": None if when is None else _iam.days_between(when, now),
                }
            )
        stale = [c for c in credentials if (c["days_since_last_use"] or 0) > limit]
        unknown = [c for c in credentials if c["days_since_last_use"] is None]
        user = row["user"]
        if stale:
            status = Status.FAIL
            message = f"{limit}일 넘게 쓰지 않은 자격증명이 있음: {user}"
        elif unknown:
            status = Status.ERROR
            message = f"자격증명의 마지막 사용일을 확인하지 못함: {user}"
        else:
            status = Status.PASS
            message = f"모든 활성 자격증명을 최근 {limit}일 안에 사용함: {user}"
        return self.finding(
            snapshot,
            resource=row["arn"],
            region=None,
            status=status,
            message=message,
            evidence={"user": user, "threshold_days": limit, "credentials": credentials},
        )
