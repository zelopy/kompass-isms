"""RDS-003 데이터베이스 로그 내보내기 미설정 (KISA CA-15, docs/RULES.md).

로그 내보내기가 없으면 응답에서 `EnabledCloudwatchLogsExports` 키가 빠지므로 키가 없는 것을
"내보내기 없음"으로 본다 (다른 RDS 룰과 달리 ERROR가 아니다).
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Severity, Status
from kompass.rules.rds._rds import RdsRule, Target


class Rds003LogExports(RdsRule):
    id: ClassVar[str] = "RDS-003"
    title: ClassVar[str] = "데이터베이스 로그 내보내기 미설정"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def _assess(self, target: Target, settings: Settings) -> tuple[Status, str, dict[str, Any]]:
        exports = list(target.item.get("EnabledCloudwatchLogsExports") or [])
        evidence = {"log_exports": exports}
        if exports:
            return Status.PASS, f"로그 내보내기 설정됨: {', '.join(exports)}", evidence
        return Status.FAIL, f"로그 내보내기 미설정: {target.resource}", evidence
