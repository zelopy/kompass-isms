"""RDS-002 데이터베이스 퍼블릭 접근 허용 (KISA CA-08, docs/RULES.md)."""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Severity, Status
from kompass.rules.rds._rds import RdsRule, Target


class Rds002PublicAccess(RdsRule):
    id: ClassVar[str] = "RDS-002"
    title: ClassVar[str] = "데이터베이스 퍼블릭 접근 허용"
    severity: ClassVar[Severity] = Severity.HIGH
    cluster_level = False  # 퍼블릭 접근은 인스턴스 설정이다

    def _assess(self, target: Target, settings: Settings) -> tuple[Status, str, dict[str, Any]]:
        item = target.item
        public = item.get("PubliclyAccessible")
        evidence = {
            "publicly_accessible": public,
            "endpoint": (item.get("Endpoint") or {}).get("Address"),
            "subnet_group": (item.get("DBSubnetGroup") or {}).get("DBSubnetGroupName"),
            "vpc_id": (item.get("DBSubnetGroup") or {}).get("VpcId"),
            "security_groups": [
                g.get("VpcSecurityGroupId") for g in item.get("VpcSecurityGroups", [])
            ],
        }
        if not isinstance(public, bool):
            return Status.ERROR, f"퍼블릭 접근 여부를 확인할 수 없음: {target.resource}", evidence
        if public:
            return Status.FAIL, f"퍼블릭 접근 허용: {target.resource}", evidence
        return Status.PASS, "퍼블릭 접근 허용 안 함", evidence
