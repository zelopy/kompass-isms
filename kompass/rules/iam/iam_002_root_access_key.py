"""IAM-002 루트 계정 액세스 키 존재 (KISA CA-02, docs/RULES.md)."""

from typing import ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import BaseRule
from kompass.rules.iam import _iam


class Iam002RootAccessKey(BaseRule):
    id: ClassVar[str] = "IAM-002"
    service: ClassVar[str] = "iam"
    title: ClassVar[str] = "루트 계정 액세스 키 존재"
    severity: ClassVar[Severity] = Severity.CRITICAL

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        summary = snapshot.data.get("account_summary")
        if summary is None:
            return [_iam.missing_section(self, snapshot, "account_summary", "계정 요약")]
        present = summary.get("AccountAccessKeysPresent")
        evidence = {"AccountAccessKeysPresent": present}
        if present == 0:
            status, message = Status.PASS, "루트 계정에 액세스 키가 없음"
        else:
            status, message = Status.FAIL, "루트 계정에 액세스 키가 있음"
        return [_iam.account_finding(self, snapshot, status, message, evidence)]
