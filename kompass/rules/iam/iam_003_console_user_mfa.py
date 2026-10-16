"""IAM-003 콘솔 사용자 MFA 미설정 (KISA CA-03, docs/RULES.md).

콘솔 비밀번호가 있는 IAM 사용자별로 MFA가 없으면 FAIL. 루트(IAM-001 담당)와 프로그래밍 방식
접근 전용 사용자는 제외한다. 외부 IdP 사용자는 IAM-009가 다룬다.
"""

from typing import ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import BaseRule
from kompass.rules.iam import _iam


class Iam003ConsoleUserMfa(BaseRule):
    id: ClassVar[str] = "IAM-003"
    service: ClassVar[str] = "iam"
    title: ClassVar[str] = "콘솔 사용자 MFA 미설정"
    severity: ClassVar[Severity] = Severity.HIGH

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        rows = _iam.report_rows(snapshot)
        if rows is None:
            return [_iam.missing_section(self, snapshot, "credential_report", "자격증명 보고서")]
        console = [r for r in _iam.user_rows(rows) if _iam.is_true(r.get("password_enabled"))]
        findings = [self._judge(snapshot, row) for row in console]
        findings += _iam.unreported_users(self, snapshot, rows)
        return findings or [
            _iam.account_finding(
                self, snapshot, Status.NOT_APPLICABLE, "콘솔 비밀번호가 있는 사용자가 없음", {}
            )
        ]

    def _judge(self, snapshot: Snapshot, row: dict[str, str]) -> Finding:
        mfa = _iam.is_true(row.get("mfa_active"))
        user = row["user"]
        return self.finding(
            snapshot,
            resource=row["arn"],
            region=None,
            status=Status.PASS if mfa else Status.FAIL,
            message=(
                f"콘솔 사용자에 MFA가 설정되어 있음: {user}"
                if mfa
                else f"콘솔 사용자에 MFA가 설정되지 않음: {user}"
            ),
            evidence={
                "user": user,
                "password_enabled": True,
                "mfa_active": mfa,
                "password_last_used": row.get("password_last_used"),
                "report_generated_time": snapshot.data["credential_report"]["generated_time"],
            },
        )
