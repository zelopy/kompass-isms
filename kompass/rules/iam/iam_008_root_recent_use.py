"""IAM-008 루트 계정 최근 사용 (KISA CA-02, docs/RULES.md).

루트의 비밀번호·액세스 키 마지막 사용일 중 가장 최근 값이 기준 일수 이내면 REVIEW.
비밀번호가 있는데 `password_last_used`가 `no_information`이면 사용 이력을 확인할 수 없으므로
REVIEW다 (사용자 결정, 2026-10-14: 실습 계정에서 루트로 로그인한 직후에도 no_information이었다).
"""

from datetime import datetime
from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import BaseRule, parse_aws_datetime
from kompass.rules.iam import _iam

_NO_INFORMATION = "no_information"


class Iam008RootRecentUse(BaseRule):
    id: ClassVar[str] = "IAM-008"
    service: ClassVar[str] = "iam"
    title: ClassVar[str] = "루트 계정 최근 사용"
    severity: ClassVar[Severity] = Severity.HIGH

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        rows = _iam.report_rows(snapshot)
        if rows is None:
            return [_iam.missing_section(self, snapshot, "credential_report", "자격증명 보고서")]
        root = _iam.root_row(rows)
        if root is None:
            return [
                _iam.account_finding(
                    self, snapshot, Status.ERROR, "자격증명 보고서에 루트 계정 행이 없다", {}
                )
            ]
        if not _iam.has_credentials(root):
            return [
                _iam.account_finding(
                    self, snapshot, Status.NOT_APPLICABLE, "루트 계정에 자격증명이 없다", {}
                )
            ]

        limit = settings.iam.root_recent_use_days
        uses = {
            "password_last_used": root.get("password_last_used"),
            "access_key_1_last_used_date": root.get("access_key_1_last_used_date"),
            "access_key_2_last_used_date": root.get("access_key_2_last_used_date"),
        }
        dates: list[datetime] = [d for v in uses.values() if (d := parse_aws_datetime(v))]
        latest = max(dates, default=None)
        days = None if latest is None else _iam.days_between(latest, snapshot.collected_at)
        password_unknown = _iam.is_true(root.get("password_enabled")) and (
            uses["password_last_used"] == _NO_INFORMATION
        )
        evidence: dict[str, Any] = {
            **uses,
            "last_used": None if latest is None else latest.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days_since_last_use": days,
            "threshold_days": limit,
        }
        if days is not None and days <= limit:
            status = Status.REVIEW
            message = f"루트 계정을 최근 {days}일 전에 사용했다. 운영 목적 사용인지 확인이 필요하다"
        elif password_unknown:
            status = Status.REVIEW
            message = "루트 비밀번호 사용 이력을 자격증명 보고서로 확인할 수 없다"
        else:
            status = Status.PASS
            message = f"루트 계정을 최근 {limit}일 안에 사용하지 않았다"
        return [_iam.account_finding(self, snapshot, status, message, evidence)]
