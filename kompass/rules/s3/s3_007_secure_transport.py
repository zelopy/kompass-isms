"""S3-007 버킷 정책 HTTPS 미강제 (KISA CA-12, docs/RULES.md).

S3 API는 HTTP 요청도 받으므로, 버킷 정책에 `aws:SecureTransport = false`인 요청을 모든 주체·
모든 S3 작업·객체에 대해 거부하는 문장이 있어야 PASS다. 최소 TLS 버전 조건은 판정하지 않는다.
"""

import json
from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.s3._buckets import MISSING, BucketRule

_BOOL_OPERATORS = ("bool", "boolifexists")
_SECURE_TRANSPORT = "aws:securetransport"


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _all_principals(principal: Any) -> bool:
    if principal == "*":
        return True
    return isinstance(principal, dict) and "*" in _as_list(principal.get("AWS"))


def _covers_objects(resources: Any, bucket: str) -> bool:
    return any(
        r == "*" or (isinstance(r, str) and r.endswith(f":s3:::{bucket}/*"))
        for r in _as_list(resources)
    )


def _denies_http(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False
    for operator, keys in condition.items():
        if operator.lower() not in _BOOL_OPERATORS or not isinstance(keys, dict):
            continue
        for key, value in keys.items():
            if key.lower() == _SECURE_TRANSPORT and any(
                str(v).lower() == "false" for v in _as_list(value)
            ):
                return True
    return False


def enforcing_statements(document: dict[str, Any], bucket: str) -> list[dict[str, Any]]:
    """HTTPS를 강제하는(HTTP 요청을 거부하는) 문장."""
    return [
        s
        for s in _as_list(document.get("Statement", []))
        if isinstance(s, dict)
        and s.get("Effect") == "Deny"
        and _all_principals(s.get("Principal"))
        and any(a in ("s3:*", "*") for a in _as_list(s.get("Action")))
        and _covers_objects(s.get("Resource"), bucket)
        and _denies_http(s.get("Condition"))
    ]


class S3007SecureTransport(BucketRule):
    id: ClassVar[str] = "S3-007"
    title: ClassVar[str] = "버킷 정책 HTTPS 미강제"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def judge(
        self,
        snapshot: Snapshot,
        settings: Settings,
        name: str,
        region: str | None,
        details: dict[str, Any],
    ) -> Finding:
        policy = details.get("policy", MISSING)
        if policy is MISSING:
            return self.bucket_error(snapshot, name, region, "s3:GetBucketPolicy", "버킷 정책")
        if policy is None:
            return self.bucket_finding(
                snapshot,
                name,
                region,
                Status.FAIL,
                f"버킷 정책이 없어 HTTP 요청을 거부하지 않음: {name}",
                {"has_policy": False, "statement_sids": []},
            )
        try:
            document = json.loads(policy)
        except (TypeError, json.JSONDecodeError):
            return self.bucket_finding(
                snapshot,
                name,
                region,
                Status.ERROR,
                f"버킷 정책 문서를 해석할 수 없음: {name}",
                {"has_policy": True},
            )
        statements = enforcing_statements(document if isinstance(document, dict) else {}, name)
        evidence = {"has_policy": True, "statement_sids": [s.get("Sid") for s in statements]}
        if statements:
            return self.bucket_finding(
                snapshot, name, region, Status.PASS, f"HTTPS가 아닌 요청을 거부함: {name}", evidence
            )
        return self.bucket_finding(
            snapshot,
            name,
            region,
            Status.FAIL,
            f"버킷 정책이 HTTP 요청을 거부하지 않음: {name}",
            evidence,
        )
