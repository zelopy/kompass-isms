"""IAM-011 네트워크 리소스 변경 권한 보유 주체 현황 (KISA CA-06, docs/RULES.md).

`iam.network_actions`(보안그룹·라우팅·VPC·로드 밸런서·DNS 등) 중 하나라도 허용된 사용자·역할마다
REVIEW. 권한의 적절성은 사람이 판단한다. 정적 분석 규칙은 `_permissions.py`.
"""

from typing import ClassVar

from kompass.config import Settings
from kompass.models import Severity
from kompass.rules.iam._permissions import PermissionHolderRule


class Iam011NetworkPermissions(PermissionHolderRule):
    id: ClassVar[str] = "IAM-011"
    title: ClassVar[str] = "네트워크 리소스 변경 권한 보유 주체 현황"
    severity: ClassVar[Severity] = Severity.MEDIUM
    _what = "네트워크 리소스 변경"

    def _actions(self, settings: Settings) -> tuple[str, ...]:
        return settings.iam.network_actions
