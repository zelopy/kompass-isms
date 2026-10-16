"""IAM-006 액세스 키 교체 주기 초과 (KISA 매핑 없음, docs/RULES.md).

IAM 사용자의 활성 액세스 키별로 마지막 교체일이 기준 일수를 넘으면 FAIL. 루트 키는 IAM-002가
다룬다. `resource`는 `<사용자 ARN>#access_key_<번호>`다.
"""

from typing import ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import BaseRule, parse_aws_datetime
from kompass.rules.iam import _iam


class Iam006AccessKeyRotation(BaseRule):
    id: ClassVar[str] = "IAM-006"
    service: ClassVar[str] = "iam"
    title: ClassVar[str] = "액세스 키 교체 주기 초과"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        rows = _iam.report_rows(snapshot)
        if rows is None:
            return [_iam.missing_section(self, snapshot, "credential_report", "자격증명 보고서")]
        keys = [(row, slot) for row in _iam.user_rows(rows) for slot in _iam.active_key_slots(row)]
        limit = settings.iam.access_key_rotation_days
        findings = [self._judge(snapshot, row, slot, limit) for row, slot in keys]
        findings += _iam.unreported_users(self, snapshot, rows)
        return findings or [
            _iam.account_finding(self, snapshot, Status.NOT_APPLICABLE, "활성 액세스 키가 없음", {})
        ]

    def _judge(self, snapshot: Snapshot, row: dict[str, str], slot: int, limit: int) -> Finding:
        rotated = row.get(f"access_key_{slot}_last_rotated")
        when = parse_aws_datetime(rotated)
        days = None if when is None else _iam.days_between(when, snapshot.collected_at)
        label = f"{row['user']} access_key_{slot}"
        if days is None:
            status, message = Status.ERROR, f"액세스 키의 교체일을 확인하지 못함: {label}"
        elif days > limit:
            status, message = Status.FAIL, f"액세스 키를 {days}일째 교체하지 않음: {label}"
        else:
            status, message = Status.PASS, f"액세스 키를 {limit}일 안에 교체함: {label}"
        return self.finding(
            snapshot,
            resource=f"{row['arn']}#access_key_{slot}",
            region=None,
            status=status,
            message=message,
            evidence={
                "user": row["user"],
                "key_slot": slot,
                "last_rotated": rotated,
                "days_since_rotation": days,
                "threshold_days": limit,
            },
        )
