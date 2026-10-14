"""IAM-007 관리자 권한 사용자 현황 (KISA CA-02, docs/RULES.md).

관리자 권한 경로 네 가지(사용자 관리형·인라인, 그룹 관리형·인라인)를 모두 본다.
- 관리자: AWS 관리형 `AdministratorAccess`, 또는 Allow 문의 Action과 Resource에 모두 `*`
- 애매함: Allow + `NotAction`/`NotResource`, 본문을 확인할 수 없는 관리형 정책
사용자에게 직접 관리자 권한이 있으면 FAIL, 그룹을 거치거나 애매하면 REVIEW. 관리자 권한
사용자가 없으면 계정 단위 PASS 하나. `Deny` 문으로 일부를 막은 경우도 보수적으로 관리자로 본다.
역할(role)은 1단계에서 판정하지 않는다.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import BaseRule
from kompass.rules.iam import _iam

_ADMIN_POLICY_SUFFIX = ":iam::aws:policy/AdministratorAccess"
ADMIN, AMBIGUOUS = "admin", "ambiguous"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def classify_document(document: dict[str, Any] | None) -> str | None:
    """정책 문서가 관리자 권한인지. 관리자면 "admin", 확정할 수 없으면 "ambiguous"."""
    if document is None:
        return AMBIGUOUS
    result: str | None = None
    for statement in _as_list(document.get("Statement")):
        if statement.get("Effect") != "Allow":
            continue
        if "NotAction" in statement or "NotResource" in statement:
            result = result or AMBIGUOUS
            continue
        if "*" in _as_list(statement.get("Action")) and "*" in _as_list(statement.get("Resource")):
            return ADMIN
    return result


class _PolicyIndex:
    def __init__(self, details: dict[str, Any]):
        self._documents = {p["Arn"]: p.get("Document") for p in details.get("policies", [])}
        self.groups = {g["GroupName"]: g for g in details.get("groups", [])}

    def managed(self, arn: str) -> str | None:
        if arn.endswith(_ADMIN_POLICY_SUFFIX):
            return ADMIN
        return classify_document(self._documents.get(arn))


def _sources(
    index: _PolicyIndex, attached: list[dict[str, Any]], inline: list[dict[str, Any]], via: str
) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for policy in attached:
        kind = index.managed(policy["PolicyArn"])
        if kind:
            found.append({"via": via, "policy": policy["PolicyArn"], "kind": kind})
    for policy in inline:
        kind = classify_document(policy.get("PolicyDocument"))
        if kind:
            found.append({"via": via, "policy": f"inline:{policy['PolicyName']}", "kind": kind})
    return found


class Iam007AdminUsers(BaseRule):
    id: ClassVar[str] = "IAM-007"
    service: ClassVar[str] = "iam"
    title: ClassVar[str] = "관리자 권한 사용자 현황"
    severity: ClassVar[Severity] = Severity.HIGH

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        details = snapshot.data.get("authorization_details")
        if details is None:
            return [_iam.missing_section(self, snapshot, "authorization_details", "IAM 권한 정보")]
        index = _PolicyIndex(details)
        findings = [
            finding
            for user in details.get("users", [])
            if (finding := self._judge(snapshot, index, user)) is not None
        ]
        return findings or [
            _iam.account_finding(
                self, snapshot, Status.PASS, "관리자 권한을 가진 IAM 사용자가 없음", {}
            )
        ]

    def _judge(
        self, snapshot: Snapshot, index: _PolicyIndex, user: dict[str, Any]
    ) -> Finding | None:
        sources = _sources(
            index, user.get("AttachedManagedPolicies", []), user.get("UserPolicyList", []), "user"
        )
        for group_name in user.get("GroupList", []):
            group = index.groups.get(group_name, {})
            sources += _sources(
                index,
                group.get("AttachedManagedPolicies", []),
                group.get("GroupPolicyList", []),
                f"group:{group_name}",
            )
        if not sources:
            return None
        name = user["UserName"]
        direct_admin = any(s["via"] == "user" and s["kind"] == ADMIN for s in sources)
        if direct_admin:
            status, message = Status.FAIL, f"사용자에게 관리자 권한이 직접 연결되어 있음: {name}"
        elif any(s["kind"] == ADMIN for s in sources):
            status, message = Status.REVIEW, f"그룹을 통해 관리자 권한을 가진 사용자: {name}"
        else:
            status, message = (
                Status.REVIEW,
                f"관리자 권한 여부를 확정할 수 없는 정책이 있음: {name}",
            )
        return self.finding(
            snapshot,
            resource=user["Arn"],
            region=None,
            status=status,
            message=message,
            evidence={
                "user": name,
                "sources": sources,
                "permissions_boundary": user.get("PermissionsBoundary", {}).get(
                    "PermissionsBoundaryArn"
                ),
            },
        )
