"""IAM-001 루트 계정 MFA 미설정 (KISA CA-03, docs/RULES.md).

`AccountMFAEnabled == 1`이면 PASS. 자격증명 보고서상 루트에 비밀번호도 활성 액세스 키도 없으면
(Organizations의 루트 자격증명 중앙 관리로 삭제된 멤버 계정) NOT_APPLICABLE. 보고서를 수집하지
못해 루트 자격증명 여부를 모르면 요약만으로 판정한다.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import BaseRule
from kompass.rules.iam import _iam


class Iam001RootMfa(BaseRule):
    id: ClassVar[str] = "IAM-001"
    service: ClassVar[str] = "iam"
    title: ClassVar[str] = "루트 계정 MFA 미설정"
    severity: ClassVar[Severity] = Severity.CRITICAL

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        summary = snapshot.data.get("account_summary")
        if summary is None:
            return [_iam.missing_section(self, snapshot, "account_summary", "계정 요약")]
        rows = _iam.report_rows(snapshot)
        root = None if rows is None else _iam.root_row(rows)
        root_has_credentials = None if root is None else _iam.has_credentials(root)
        evidence: dict[str, Any] = {
            "AccountMFAEnabled": summary.get("AccountMFAEnabled"),
            "root_has_credentials": root_has_credentials,
        }
        if root_has_credentials is False:
            status, message = Status.NOT_APPLICABLE, "루트 계정에 자격증명이 없다"
        elif summary.get("AccountMFAEnabled") == 1:
            status, message = Status.PASS, "루트 계정에 MFA가 설정되어 있다"
        else:
            status, message = Status.FAIL, "루트 계정에 MFA가 설정되지 않았다"
        return [_iam.account_finding(self, snapshot, status, message, evidence)]
