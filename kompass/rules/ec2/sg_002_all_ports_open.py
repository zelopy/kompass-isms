"""SG-002 전체 포트·프로토콜 개방 (KISA CA-09, docs/RULES.md)."""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Severity
from kompass.rules.ec2 import _network as net
from kompass.rules.ec2._open_ports import OpenPortRule


class Sg002AllPortsOpen(OpenPortRule):
    id: ClassVar[str] = "SG-002"
    title: ClassVar[str] = "전체 포트·프로토콜 개방"
    severity: ClassVar[Severity] = Severity.CRITICAL
    _violation = "모든 포트·프로토콜이 전체 개방된 인바운드 규칙"

    def _matches(self, permission: dict[str, Any], settings: Settings) -> bool:
        return net.is_all_ports(permission)
