"""SG-003 데이터베이스 포트 전체 개방 (KISA CA-09, docs/RULES.md)."""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Severity
from kompass.rules.ec2 import _network as net
from kompass.rules.ec2._open_ports import OpenPortRule


class Sg003DbPortOpen(OpenPortRule):
    id: ClassVar[str] = "SG-003"
    title: ClassVar[str] = "데이터베이스 포트 전체 개방"
    severity: ClassVar[Severity] = Severity.HIGH
    _violation = "데이터베이스 포트가 전체 개방된 인바운드 규칙"

    def _matches(self, permission: dict[str, Any], settings: Settings) -> list[int]:
        return net.matched_ports(permission, settings.ec2.db_ports)

    def _extra_evidence(self, settings: Settings) -> dict[str, Any]:
        return {"db_ports": list(settings.ec2.db_ports)}
