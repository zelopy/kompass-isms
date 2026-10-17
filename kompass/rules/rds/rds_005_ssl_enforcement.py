"""RDS-005 데이터베이스 SSL 연결 미강제 (KISA CA-12, docs/RULES.md, ADR-051).

엔진마다 SSL 강제 파라미터가 다르다. 클러스터 소속이면 클러스터 파라미터 그룹을, 아니면 인스턴스의
DB 파라미터 그룹을 본다. 값이 없는 파라미터는 엔진 기본값이며 강제하지 않는 것으로 본다
(`ParameterValue`는 그룹이나 시스템이 값을 정했을 때만 응답에 있다).
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Severity, Snapshot, Status
from kompass.rules.base import errors_evidence, errors_for
from kompass.rules.rds._rds import RdsRule, Target

FORCE_SSL = "rds.force_ssl"
SECURE_TRANSPORT = "require_secure_transport"
# collector가 저장하는 파라미터(`collectors.rds.SSL_PARAMETERS`)와 같아야 한다 (테스트로 검사)
ENGINE_PARAMETERS = {
    "postgres": FORCE_SSL,
    "aurora-postgresql": FORCE_SSL,
    "mysql": SECURE_TRANSPORT,
    "mariadb": SECURE_TRANSPORT,
    "aurora-mysql": SECURE_TRANSPORT,
}
_SQLSERVER_PREFIX = "sqlserver-"  # sqlserver-ee·se·ex·web
_ON = frozenset({"1", "on", "true"})
_OFF = frozenset({"0", "off", "false"})


def ssl_parameter(engine: str) -> str | None:
    """엔진의 SSL 강제 파라미터 이름. 파라미터 그룹으로 강제하지 않는 엔진이면 None."""
    if engine.startswith(_SQLSERVER_PREFIX):
        return FORCE_SSL
    return ENGINE_PARAMETERS.get(engine)


class Rds005SslEnforcement(RdsRule):
    id: ClassVar[str] = "RDS-005"
    title: ClassVar[str] = "데이터베이스 SSL 연결 미강제"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def _assess_in_region(
        self, target: Target, data: dict[str, Any], snapshot: Snapshot, settings: Settings
    ) -> tuple[Status, str, dict[str, Any]]:
        engine = str(target.item.get("Engine") or "")
        name = ssl_parameter(engine)
        if name is None:
            return (
                Status.REVIEW,
                f"파라미터 그룹으로 SSL 강제를 확인하지 않는 엔진: {engine or '알 수 없음'}",
                {},
            )

        if target.kind == "cluster":
            group = target.item.get("DBClusterParameterGroup")
            groups_key, operation = "db_cluster_parameter_groups", "rds:DescribeDBClusterParameters"
            apply_status = None
        else:
            attached = target.item.get("DBParameterGroups") or [{}]
            group = attached[0].get("DBParameterGroupName")
            groups_key, operation = "db_parameter_groups", "rds:DescribeDBParameters"
            apply_status = attached[0].get("ParameterApplyStatus")
        evidence: dict[str, Any] = {"parameter_group": group, "parameter": name}
        if apply_status:
            evidence["parameter_apply_status"] = apply_status
        if not isinstance(group, str) or not group:
            return Status.ERROR, f"파라미터 그룹을 확인할 수 없음: {target.resource}", evidence

        parameters = data.get(groups_key, {}).get(group)
        if parameters is None:
            errors = errors_for(snapshot, operation, group)
            evidence["errors"] = errors_evidence(errors)
            return Status.ERROR, f"파라미터 그룹 설정을 수집하지 못함: {group}", evidence
        parameter = parameters.get(name)
        if parameter is None:
            return Status.ERROR, f"SSL 강제 파라미터가 파라미터 그룹에 없음: {name}", evidence

        value = parameter.get("ParameterValue")
        evidence.update(value=value, source=parameter.get("Source"))
        if value is None:
            return Status.FAIL, f"SSL 연결 강제 설정되지 않음 (엔진 기본값): {name}", evidence
        normalized = str(value).strip().lower()
        if normalized in _ON:
            return Status.PASS, f"SSL 연결 강제 설정됨: {name}={value}", evidence
        if normalized in _OFF:
            return Status.FAIL, f"SSL 연결 강제 꺼짐: {name}={value}", evidence
        return Status.ERROR, f"SSL 강제 값을 해석할 수 없음: {name}={value}", evidence
