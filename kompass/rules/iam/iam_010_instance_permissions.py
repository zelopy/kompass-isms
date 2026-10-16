"""IAM-010 인스턴스 생성·접근 권한 보유 주체 현황 (KISA CA-05, docs/RULES.md).

`iam.instance_actions` 중 하나라도 허용된 사용자·역할마다 REVIEW. 권한의 적절성은 사람이
판단한다. 정적 분석 규칙은 `_permissions.py`.
"""

from typing import ClassVar

from kompass.config import Settings
from kompass.models import Severity
from kompass.rules.iam._permissions import PermissionHolderRule


class Iam010InstancePermissions(PermissionHolderRule):
    id: ClassVar[str] = "IAM-010"
    title: ClassVar[str] = "인스턴스 생성·접근 권한 보유 주체 현황"
    severity: ClassVar[Severity] = Severity.MEDIUM
    _what = "인스턴스 생성·접근"

    def _actions(self, settings: Settings) -> tuple[str, ...]:
        return settings.iam.instance_actions
