"""ELB-002 로드 밸런서 TLS 정책 취약 (KISA CA-12, docs/RULES.md, ADR-052).

정책 이름을 목록으로 두지 않고, 정책이 실제로 허용하는 프로토콜을 기준 버전과 비교한다.
- ALB·NLB: HTTPS·TLS 리스너의 `SslPolicy` → `DescribeSSLPolicies`의 `SslProtocols`
- Classic: HTTPS·SSL 리스너의 `PolicyNames` 중 SSL 협상 정책 → `Protocol-…` 속성이 true인 것
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Severity, Snapshot, Status
from kompass.rules.base import errors_evidence, errors_for
from kompass.rules.elb._elb import ElbRule, Listener, ListenerResult, Target, labels, worst

TLS_LISTENERS = frozenset({"HTTPS", "TLS", "SSL"})
PROTOCOL_ORDER = ("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_CLASSIC = "classic"
_NEGOTIATION = "SSLNegotiationPolicyType"
_PROTOCOL_ATTRIBUTE = "Protocol-"
_REFERENCE = "Reference-Security-Policy"


class Elb002TlsPolicy(ElbRule):
    id: ClassVar[str] = "ELB-002"
    title: ClassVar[str] = "로드 밸런서 TLS 정책 취약"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def _assess(
        self,
        target: Target,
        listeners: list[Listener],
        data: dict[str, Any],
        snapshot: Snapshot,
        settings: Settings,
    ) -> tuple[Status, str, dict[str, Any]]:
        minimum = settings.elb.min_tls_version
        tls = [x for x in listeners if x.protocol in TLS_LISTENERS]
        evidence: dict[str, Any] = {"min_tls_version": minimum}
        if not tls:
            evidence["listeners"] = []
            return Status.NOT_APPLICABLE, "TLS 리스너가 없음", evidence

        if target.kind == _CLASSIC:
            policies = target.item.get("Policies")
            if policies is None:
                errors = errors_for(snapshot, "elb:DescribeLoadBalancerPolicies", target.name)
                evidence.update(listeners=[], errors=errors_evidence(errors))
                return Status.ERROR, "SSL 협상 정책을 수집하지 못함", evidence
            results = [_classic_listener(x, policies, minimum) for x in tls]
        else:
            ssl_policies = data.get("ssl_policies", {})
            results = [_v2_listener(x, ssl_policies, snapshot, minimum) for x in tls]

        evidence["listeners"] = [{**r.evidence, "status": r.status.value} for r in results]
        status = worst([r.status for r in results])
        if status == Status.FAIL:
            weak = ", ".join(
                f"{r.listener.label} {_policy_name(r)} ({', '.join(r.evidence['weak_protocols'])})"
                for r in results
                if r.status == Status.FAIL
            )
            message = f"{minimum} 미만 프로토콜을 허용하는 보안 정책 사용: {weak}"
        elif status == Status.ERROR:
            message = f"TLS 보안 정책을 확인할 수 없음: {labels(results, status)}"
        else:
            message = f"모든 TLS 리스너가 {minimum} 이상만 허용"
        return status, message, evidence


def _policy_name(result: ListenerResult) -> Any:
    return result.evidence.get("ssl_policy") or result.evidence.get("policy_name")


def _judge(
    listener: Listener, protocols: list[str], minimum: str, evidence: dict[str, Any]
) -> ListenerResult:
    evidence["protocols"] = protocols
    unknown = [p for p in protocols if p not in PROTOCOL_ORDER]
    if unknown or not protocols:
        evidence["unknown_protocols"] = unknown
        return ListenerResult(listener, Status.ERROR, evidence)
    floor = PROTOCOL_ORDER.index(minimum)
    weak = [p for p in PROTOCOL_ORDER if p in protocols and PROTOCOL_ORDER.index(p) < floor]
    if weak:
        evidence["weak_protocols"] = weak
        return ListenerResult(listener, Status.FAIL, evidence)
    return ListenerResult(listener, Status.PASS, evidence)


def _v2_listener(
    listener: Listener,
    ssl_policies: dict[str, Any],
    snapshot: Snapshot,
    minimum: str,
) -> ListenerResult:
    name = listener.item.get("SslPolicy")
    evidence: dict[str, Any] = {
        "protocol": listener.protocol,
        "port": listener.port,
        "ssl_policy": name,
    }
    if not isinstance(name, str) or not name:
        return ListenerResult(listener, Status.ERROR, evidence)
    policy = ssl_policies.get(name)
    if policy is None:
        errors = errors_for(snapshot, "elbv2:DescribeSSLPolicies", name)
        evidence["errors"] = errors_evidence(errors)
        return ListenerResult(listener, Status.ERROR, evidence)
    return _judge(listener, list(policy.get("SslProtocols", [])), minimum, evidence)


def _classic_listener(
    listener: Listener, policies: list[dict[str, Any]], minimum: str
) -> ListenerResult:
    evidence: dict[str, Any] = {"protocol": listener.protocol, "port": listener.port}
    names = set(listener.item.get("PolicyNames", []))
    negotiation = [
        p
        for p in policies
        if p.get("PolicyName") in names and p.get("PolicyTypeName") == _NEGOTIATION
    ]
    if not negotiation:
        return ListenerResult(listener, Status.ERROR, evidence)
    policy = negotiation[0]
    attributes = {
        a.get("AttributeName"): a.get("AttributeValue")
        for a in policy.get("PolicyAttributeDescriptions", [])
    }
    evidence["policy_name"] = policy.get("PolicyName")
    if attributes.get(_REFERENCE):
        evidence["reference_policy"] = attributes[_REFERENCE]
    protocols = [
        str(name).removeprefix(_PROTOCOL_ATTRIBUTE)
        for name, value in attributes.items()
        if str(name).startswith(_PROTOCOL_ATTRIBUTE) and str(value).lower() == "true"
    ]
    return _judge(listener, protocols, minimum, evidence)
