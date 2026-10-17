"""RDS-006 데이터베이스 스냅샷 공개 (KISA CA-10, docs/RULES.md, ADR-053).

계정이 소유한 수동 스냅샷마다 공유 속성 `restore`를 본다. 값에 `all`이 있으면 모든 AWS 계정이
복원할 수 있다. 대상이 데이터베이스가 아니라 스냅샷이므로 공통 대상 선정(`RdsRule._targets`)은
쓰지 않고, 리전 단위 오류·해당 없음 처리만 같게 둔다. 원본 데이터베이스를 지운 뒤 남은 스냅샷도
판정하므로 인스턴스·클러스터 목록에는 의존하지 않는다.
"""

from dataclasses import dataclass
from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import errors_evidence, errors_for
from kompass.rules.rds._rds import RdsRule, _relational

PUBLIC = "all"
RESTORE = "restore"


@dataclass(frozen=True)
class _Kind:
    """스냅샷 종류별 데이터 키와 응답 필드."""

    name: str  # evidence의 kind
    list_key: str
    list_operation: str
    attributes_key: str
    attributes_operation: str
    identifier_field: str
    source_field: str
    source_evidence: str
    encrypted_field: str
    resource_prefix: str


KINDS = (
    _Kind(
        name="snapshot",
        list_key="db_snapshots",
        list_operation="rds:DescribeDBSnapshots",
        attributes_key="db_snapshot_attributes",
        attributes_operation="rds:DescribeDBSnapshotAttributes",
        identifier_field="DBSnapshotIdentifier",
        source_field="DBInstanceIdentifier",
        source_evidence="db_identifier",
        encrypted_field="Encrypted",
        resource_prefix="",
    ),
    _Kind(
        name="cluster_snapshot",
        list_key="db_cluster_snapshots",
        list_operation="rds:DescribeDBClusterSnapshots",
        attributes_key="db_cluster_snapshot_attributes",
        attributes_operation="rds:DescribeDBClusterSnapshotAttributes",
        identifier_field="DBClusterSnapshotIdentifier",
        source_field="DBClusterIdentifier",
        source_evidence="db_cluster",
        encrypted_field="StorageEncrypted",
        resource_prefix="cluster-snapshot:",
    ),
)


class Rds006PublicSnapshot(RdsRule):
    id: ClassVar[str] = "RDS-006"
    title: ClassVar[str] = "데이터베이스 스냅샷 공개"
    severity: ClassVar[Severity] = Severity.HIGH

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        for region, data in snapshot.data.get("regions", {}).items():
            missing = [kind for kind in KINDS if kind.list_key not in data]
            if missing:
                operations = {kind.list_operation for kind in missing}
                errors = [
                    e for e in snapshot.errors if e.region == region and e.operation in operations
                ]
                findings.append(
                    self._region_finding(
                        snapshot,
                        region,
                        Status.ERROR,
                        "데이터베이스 스냅샷 목록을 수집하지 못함",
                        {"errors": errors_evidence(errors)},
                    )
                )
                continue
            judged: list[Finding] = []
            excluded: list[str] = []
            for kind in KINDS:
                for item in data[kind.list_key]:
                    resource = kind.resource_prefix + item[kind.identifier_field]
                    if not _relational(item):
                        excluded.append(resource)
                        continue
                    status, message, evidence = self._assess_snapshot(kind, item, data, snapshot)
                    judged.append(
                        self.finding(
                            snapshot,
                            resource=resource,
                            region=region,
                            status=status,
                            message=message,
                            evidence=evidence,
                        )
                    )
            if not judged:
                judged.append(
                    self._region_finding(
                        snapshot,
                        region,
                        Status.NOT_APPLICABLE,
                        "점검 대상 수동 데이터베이스 스냅샷이 없음",
                        {"excluded": excluded},
                    )
                )
            findings.extend(judged)
        return findings

    def _assess_snapshot(
        self, kind: _Kind, item: dict[str, Any], data: dict[str, Any], snapshot: Snapshot
    ) -> tuple[Status, str, dict[str, Any]]:
        identifier = item[kind.identifier_field]
        evidence: dict[str, Any] = {
            "kind": kind.name,
            "snapshot": identifier,
            kind.source_evidence: item.get(kind.source_field),
            "engine": item.get("Engine"),
            "encrypted": item.get(kind.encrypted_field),
            "created_at": item.get("SnapshotCreateTime"),
        }
        attributes = data.get(kind.attributes_key, {}).get(identifier)
        if attributes is None:
            errors = errors_for(snapshot, kind.attributes_operation, identifier)
            evidence["errors"] = errors_evidence(errors)
            return Status.ERROR, f"스냅샷 공유 설정을 수집하지 못함: {identifier}", evidence

        values = next(
            (a.get("AttributeValues") for a in attributes if a.get("AttributeName") == RESTORE),
            None,
        )
        if not isinstance(values, list):
            return Status.ERROR, f"스냅샷 공유 설정을 확인할 수 없음: {identifier}", evidence
        public = PUBLIC in values
        evidence.update(public=public, shared_accounts=[v for v in values if v != PUBLIC])
        if public:
            return Status.FAIL, f"모든 AWS 계정에 공개된 스냅샷: {identifier}", evidence
        if evidence["shared_accounts"]:
            count = len(evidence["shared_accounts"])
            return Status.PASS, f"공개 안 함 (특정 계정 {count}개에 공유)", evidence
        return Status.PASS, "공개 안 함", evidence
