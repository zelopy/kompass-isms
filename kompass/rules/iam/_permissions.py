"""IAM-010~011 공통: 정책 문서 정적 분석으로 특정 작업 권한을 가진 주체를 찾는다 (ADR-044).

근사 규칙 (보수적):
- `Allow` 문의 `Action`(와일드카드 `*`·`?`, 대소문자 무시)이 작업과 일치하면 권한이 있다고 본다.
  `Allow` + `NotAction`은 그 목록에 없는 작업을 모두 허용한 것으로 본다.
- `Resource`는 보지 않는다 (일부 리소스만 허용해도 권한 보유로 본다).
- `Condition`이 있는 문은 권한으로 세되 evidence에 조건부임을 남긴다.
- `Deny` 문과 권한 경계(permissions boundary)는 판정에 쓰지 않고 evidence에만 남긴다.
- 본문을 확인할 수 없는 관리형 정책은 `unknown_policies`로 남긴다.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import cache
from typing import Any

from kompass.config import Settings
from kompass.models import Finding, Snapshot, Status
from kompass.rules.base import BaseRule
from kompass.rules.iam import _iam

SERVICE_ROLE_PATH = "/aws-service-role/"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@cache
def _pattern(pattern: str) -> re.Pattern[str]:
    escaped = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(f"^{escaped}$", re.IGNORECASE)


def action_matches(pattern: str, action: str) -> bool:
    return bool(_pattern(pattern).match(action))


def granted_actions(
    document: dict[str, Any], actions: tuple[str, ...]
) -> dict[str, dict[str, bool]]:
    """문서가 허용하는 대상 작업 → {"conditional", "not_action"}.

    conditional은 그 작업을 허용한 문이 모두 조건부인지, not_action은 NotAction 경유가 있는지다.
    """
    grants: dict[str, dict[str, bool]] = {}
    for statement in _as_list(document.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        conditional = bool(statement.get("Condition"))
        if "NotAction" in statement:
            excluded = _as_list(statement["NotAction"])
            matched = [a for a in actions if not any(action_matches(p, a) for p in excluded)]
            via_not_action = True
        else:
            patterns = _as_list(statement.get("Action"))
            matched = [a for a in actions if any(action_matches(p, a) for p in patterns)]
            via_not_action = False
        for action in matched:
            current = grants.get(action)
            if current is None:
                grants[action] = {"conditional": conditional, "not_action": via_not_action}
            else:
                current["conditional"] = current["conditional"] and conditional
                current["not_action"] = current["not_action"] or via_not_action
    return grants


@dataclass
class Holding:
    """주체 하나가 가진 대상 작업 권한."""

    actions: set[str] = field(default_factory=set)
    sources: list[dict[str, Any]] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)


class _Policies:
    def __init__(self, details: dict[str, Any]):
        self._documents = {p["Arn"]: p.get("Document") for p in details.get("policies", [])}
        self.groups = {g["GroupName"]: g for g in details.get("groups", [])}

    def document(self, arn: str) -> dict[str, Any] | None:
        document = self._documents.get(arn)
        return document if isinstance(document, dict) else None


def _collect(
    holding: Holding,
    policies: _Policies,
    attached: list[dict[str, Any]],
    inline: list[dict[str, Any]],
    via: str,
    actions: tuple[str, ...],
) -> None:
    documents: list[tuple[str, dict[str, Any] | None]] = [
        (p["PolicyArn"], policies.document(p["PolicyArn"])) for p in attached
    ]
    documents += [(f"inline:{p['PolicyName']}", p.get("PolicyDocument")) for p in inline]
    for name, document in documents:
        if document is None:
            holding.unknown.append(name)
            continue
        grants = granted_actions(document, actions)
        if not grants:
            continue
        holding.actions |= set(grants)
        holding.sources.append(
            {
                "via": via,
                "policy": name,
                "actions": sorted(grants),
                "conditional": all(g["conditional"] for g in grants.values()),
                "not_action": any(g["not_action"] for g in grants.values()),
            }
        )


def _principals(
    details: dict[str, Any], policies: _Policies, actions: tuple[str, ...]
) -> Iterator[tuple[str, dict[str, Any], Holding]]:
    for user in details.get("users", []):
        holding = Holding()
        _collect(
            holding,
            policies,
            user.get("AttachedManagedPolicies", []),
            user.get("UserPolicyList", []),
            "user",
            actions,
        )
        for name in user.get("GroupList", []):
            group = policies.groups.get(name, {})
            _collect(
                holding,
                policies,
                group.get("AttachedManagedPolicies", []),
                group.get("GroupPolicyList", []),
                f"group:{name}",
                actions,
            )
        yield "user", user, holding
    for role in details.get("roles", []):
        if str(role.get("Path", "")).startswith(SERVICE_ROLE_PATH):
            continue
        holding = Holding()
        _collect(
            holding,
            policies,
            role.get("AttachedManagedPolicies", []),
            role.get("RolePolicyList", []),
            "role",
            actions,
        )
        yield "role", role, holding


class PermissionHolderRule(BaseRule):
    """하위 룰은 대상 작업 목록과 메시지만 정한다."""

    service = "iam"
    _what: str  # "인스턴스 생성·접근" 등

    def _actions(self, settings: Settings) -> tuple[str, ...]:
        raise NotImplementedError

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        details = snapshot.data.get("authorization_details")
        if details is None:
            return [_iam.missing_section(self, snapshot, "authorization_details", "IAM 권한 정보")]
        actions = self._actions(settings)
        policies = _Policies(details)
        findings = [
            self._holder(snapshot, kind, principal, holding)
            for kind, principal, holding in _principals(details, policies, actions)
            if holding.actions or holding.unknown
        ]
        if findings:
            return findings
        excluded = sum(
            1
            for r in details.get("roles", [])
            if str(r.get("Path", "")).startswith(SERVICE_ROLE_PATH)
        )
        return [
            _iam.account_finding(
                self,
                snapshot,
                Status.PASS,
                f"{self._what} 권한을 가진 사용자·역할이 없음",
                {"checked_actions": list(actions), "excluded_service_roles": excluded},
            )
        ]

    def _holder(
        self, snapshot: Snapshot, kind: str, principal: dict[str, Any], holding: Holding
    ) -> Finding:
        name = principal["UserName"] if kind == "user" else principal["RoleName"]
        label = "사용자" if kind == "user" else "역할"
        if holding.actions:
            message = f"{self._what} 권한을 가진 {label}: {name} (작업 {len(holding.actions)}개)"
        else:
            message = f"{self._what} 권한 여부를 확정할 수 없는 정책이 있는 {label}: {name}"
        boundary = principal.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
        return self.finding(
            snapshot,
            resource=principal["Arn"],
            region=None,
            status=Status.REVIEW,
            message=message,
            evidence={
                "principal_type": kind,
                "name": name,
                "actions": sorted(holding.actions),
                "sources": holding.sources,
                "unknown_policies": holding.unknown,
                "permissions_boundary": boundary,
            },
        )
