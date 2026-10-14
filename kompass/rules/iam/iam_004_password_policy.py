"""IAM-004 비밀번호 정책 미흡 (KISA CA-04, ADR-014, docs/RULES.md).

요구 문자 종류를 KISA 분류(영문자·숫자·특수문자)로 세어, 3종이면 8자, 2종이면 10자 이상일 때
PASS. 대문자와 소문자는 영문자 1종이다. 정책이 없으면(`NoSuchEntity`) FAIL.
로그인 시도 제한은 IAM에 설정 항목이 없어 evidence에 남기고, 항목은 partial 상한으로
"검토 필요"가 된다.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import BaseRule
from kompass.rules.iam import _iam

_LOGIN_LIMIT_NOTE = "IAM 비밀번호 정책으로 확인할 수 없음"


def character_types(policy: dict[str, Any]) -> int:
    letters = policy.get("RequireUppercaseCharacters") is True or (
        policy.get("RequireLowercaseCharacters") is True
    )
    return sum(
        [letters, policy.get("RequireNumbers") is True, policy.get("RequireSymbols") is True]
    )


class Iam004PasswordPolicy(BaseRule):
    id: ClassVar[str] = "IAM-004"
    service: ClassVar[str] = "iam"
    title: ClassVar[str] = "비밀번호 정책 미흡"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        if "password_policy" not in snapshot.data:
            return [_iam.missing_section(self, snapshot, "password_policy", "비밀번호 정책")]
        policy = snapshot.data["password_policy"]
        criteria = settings.iam.password_policy
        evidence: dict[str, Any] = {
            "password_policy": policy,
            "criteria": {
                "min_length_two_types": criteria.min_length_two_types,
                "min_length_three_types": criteria.min_length_three_types,
            },
            "login_attempt_limit": _LOGIN_LIMIT_NOTE,
        }
        if policy is None:
            evidence["character_types"] = 0
            return [
                _iam.account_finding(
                    self, snapshot, Status.FAIL, "비밀번호 정책이 설정되지 않음", evidence
                )
            ]

        types = character_types(policy)
        length = int(policy.get("MinimumPasswordLength", 0))
        evidence["character_types"] = types
        required = {3: criteria.min_length_three_types, 2: criteria.min_length_two_types}.get(types)
        if required is not None and length >= required:
            status = Status.PASS
            message = f"비밀번호 정책이 기준을 충족함 ({types}종 {length}자)"
        elif required is None:
            status = Status.FAIL
            message = f"요구 문자 종류가 부족함 ({types}종, 2종 이상 필요)"
        else:
            status = Status.FAIL
            message = f"최소 길이가 부족함 ({types}종 {length}자, {required}자 이상 필요)"
        return [_iam.account_finding(self, snapshot, status, message, evidence)]
