"""IAM-009 외부 자격증명 공급자 사용 (MFA 확인 필요) (KISA CA-03, docs/RULES.md).

SAML·OIDC 공급자, Identity Center 인스턴스마다 REVIEW. 조직의 멤버 계정처럼 인스턴스는 없지만
Identity Center가 만든 역할(`/aws-reserved/sso.amazonaws.com/`)이 있으면 그 역할들로 REVIEW 하나
(사용자 결정, 2026-10-14). 하나도 없으면 N/A이지만, 조회에 실패한 곳이 있으면 ERROR다.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule
from kompass.rules.iam import _iam

_SSO_ROLE_PATH = "/aws-reserved/sso.amazonaws.com/"
_SECTIONS = (
    "saml_providers",
    "oidc_providers",
    "identity_center_instances",
    "authorization_details",
)


class Iam009ExternalIdentity(BaseRule):
    id: ClassVar[str] = "IAM-009"
    service: ClassVar[str] = "iam"
    title: ClassVar[str] = "외부 자격증명 공급자 사용 (MFA 확인 필요)"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        data = snapshot.data
        found: list[tuple[str, str, dict[str, Any]]] = []
        for provider in data.get("saml_providers") or []:
            found.append(("saml", provider["Arn"], {}))
        for provider in data.get("oidc_providers") or []:
            found.append(("oidc", provider["Arn"], {}))
        for region, instances in (data.get("identity_center_instances") or {}).items():
            for instance in instances:
                found.append(("identity_center", instance["InstanceArn"], {"region": region}))
        roles = [
            role["Arn"]
            for role in (data.get("authorization_details") or {}).get("roles", [])
            if role.get("Path", "").startswith(_SSO_ROLE_PATH)
        ]
        if roles:
            found.append(("identity_center_roles", ACCOUNT_RESOURCE, {"roles": roles}))

        if found:
            return [
                self._review(snapshot, kind, resource, extra) for kind, resource, extra in found
            ]
        errors = _iam.section_errors(snapshot, *_SECTIONS)
        if errors or any(key not in data for key in _SECTIONS):
            return [
                _iam.account_finding(
                    self,
                    snapshot,
                    Status.ERROR,
                    "외부 자격증명 공급자 조회 중 실패한 곳이 있다",
                    {"errors": errors},
                )
            ]
        return [
            _iam.account_finding(
                self, snapshot, Status.NOT_APPLICABLE, "외부 자격증명 공급자가 없다", {}
            )
        ]

    def _review(
        self, snapshot: Snapshot, kind: str, resource: str, extra: dict[str, Any]
    ) -> Finding:
        return self.finding(
            snapshot,
            resource=resource,
            region=None,
            status=Status.REVIEW,
            message=(
                f"외부 자격증명 공급자로 로그인하는 사용자의 MFA는 IdP에서 확인해야 한다 ({kind})"
            ),
            evidence={"kind": kind, **extra},
        )
