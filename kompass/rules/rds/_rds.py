"""RDS-001~005 공통: 대상 데이터베이스 선정과 리전 단위 오류·해당 없음 처리 (ADR-039).

- 관계형 데이터베이스만 본다. DocumentDB·Neptune은 같은 API로 조회되지만 뺀다.
- 클러스터 단위 룰은 클러스터에 속하지 않은 인스턴스와 클러스터를 판정한다. 클러스터 finding의
  resource는 `cluster:<식별자>`로 써서 같은 이름의 인스턴스와 구분한다.
- 인스턴스 단위 룰(RDS-002)은 클러스터 소속 인스턴스까지 모든 인스턴스를 판정한다.
"""

from dataclasses import dataclass
from typing import Any

from kompass.config import Settings
from kompass.models import Finding, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence

OPERATIONS = {
    "db_instances": "rds:DescribeDBInstances",
    "db_clusters": "rds:DescribeDBClusters",
}
_NON_RELATIONAL = ("docdb", "neptune")


@dataclass(frozen=True)
class Target:
    resource: str  # 인스턴스 식별자 또는 "cluster:<클러스터 식별자>"
    kind: str  # "instance" | "cluster"
    identifier: str
    item: dict[str, Any]

    def base_evidence(self) -> dict[str, Any]:
        evidence: dict[str, Any] = {
            "kind": self.kind,
            "db_identifier": self.identifier,
            "engine": self.item.get("Engine"),
        }
        if self.kind == "instance" and self.item.get("DBClusterIdentifier"):
            evidence["db_cluster"] = self.item["DBClusterIdentifier"]
        return evidence


def _relational(item: dict[str, Any]) -> bool:
    engine = str(item.get("Engine") or "")
    return not engine.startswith(_NON_RELATIONAL)


class RdsRule(BaseRule):
    """하위 룰은 `_assess`로 대상 하나의 (상태, 메시지, evidence)만 정한다."""

    service = "rds"
    cluster_level = True  # False면 모든 인스턴스를 인스턴스 단위로 판정

    def _assess(self, target: Target, settings: Settings) -> tuple[Status, str, dict[str, Any]]:
        raise NotImplementedError

    def _assess_in_region(
        self, target: Target, data: dict[str, Any], snapshot: Snapshot, settings: Settings
    ) -> tuple[Status, str, dict[str, Any]]:
        """리전의 다른 수집 데이터(파라미터 그룹 등)가 필요한 룰은 이것을 재정의한다."""
        return self._assess(target, settings)

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        kinds = ("db_instances", "db_clusters") if self.cluster_level else ("db_instances",)
        for region, data in snapshot.data.get("regions", {}).items():
            missing = [kind for kind in kinds if kind not in data]
            if missing:
                operations = {OPERATIONS[kind] for kind in missing}
                errors = [
                    e for e in snapshot.errors if e.region == region and e.operation in operations
                ]
                findings.append(
                    self._region_finding(
                        snapshot,
                        region,
                        Status.ERROR,
                        "데이터베이스 목록을 수집하지 못함",
                        {"errors": errors_evidence(errors)},
                    )
                )
                continue
            targets, excluded = self._targets(data)
            if not targets:
                findings.append(
                    self._region_finding(
                        snapshot,
                        region,
                        Status.NOT_APPLICABLE,
                        "점검 대상 관계형 데이터베이스가 없음",
                        {"excluded": excluded},
                    )
                )
                continue
            for target in targets:
                status, message, evidence = self._assess_in_region(target, data, snapshot, settings)
                findings.append(
                    self.finding(
                        snapshot,
                        resource=target.resource,
                        region=region,
                        status=status,
                        message=message,
                        evidence={**target.base_evidence(), **evidence},
                    )
                )
        return findings

    def _targets(self, data: dict[str, Any]) -> tuple[list[Target], list[str]]:
        targets: list[Target] = []
        excluded: list[str] = []
        for item in data.get("db_instances", []):
            identifier = item["DBInstanceIdentifier"]
            if not _relational(item):
                excluded.append(identifier)
            elif not self.cluster_level or not item.get("DBClusterIdentifier"):
                targets.append(Target(identifier, "instance", identifier, item))
        if self.cluster_level:
            for item in data.get("db_clusters", []):
                identifier = item["DBClusterIdentifier"]
                if not _relational(item):
                    excluded.append(f"cluster:{identifier}")
                else:
                    targets.append(Target(f"cluster:{identifier}", "cluster", identifier, item))
        return targets, excluded

    def _region_finding(
        self,
        snapshot: Snapshot,
        region: str,
        status: Status,
        message: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return self.finding(
            snapshot,
            resource=ACCOUNT_RESOURCE,
            region=region,
            status=status,
            message=message,
            evidence=evidence,
        )
