"""ELB-001 로드 밸런서 평문 리스너 사용 (KISA CA-12, docs/RULES.md, ADR-052).

HTTPS·TLS·SSL 리스너는 통신 구간이 암호화된다. ALB의 HTTP 리스너는 모든 규칙(기본 규칙 포함)의
동작이 HTTPS 리디렉션이나 고정 응답뿐이면 요청을 대상으로 넘기지 않으므로 양호로 본다. Classic의
HTTP 리스너는 리디렉션 기능이 없어 취약이다. TCP·UDP 리스너는 대상 서버가 TLS를 처리하는지
설정만으로 알 수 없어 검토 필요다.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Severity, Snapshot, Status
from kompass.rules.base import errors_evidence, errors_for
from kompass.rules.elb._elb import ElbRule, Listener, ListenerResult, Target, labels, worst

ENCRYPTED = frozenset({"HTTPS", "TLS", "SSL"})
_HTTP = "HTTP"
_HTTPS = "HTTPS"
_CLASSIC = "classic"


def _safe_action(action: dict[str, Any]) -> bool:
    """요청을 대상으로 넘기지 않는 동작인가: HTTPS 리디렉션, 고정 응답.

    리디렉션의 `Protocol`을 지정하지 않으면 원래 프로토콜(`#{protocol}`)을 유지하므로 HTTP다.
    """
    kind = action.get("Type")
    if kind == "fixed-response":
        return True
    return kind == "redirect" and action.get("RedirectConfig", {}).get("Protocol") == _HTTPS


def _actions(actions: list[dict[str, Any]]) -> list[str]:
    return [
        f"redirect:{a.get('RedirectConfig', {}).get('Protocol', '#{protocol}')}"
        if a.get("Type") == "redirect"
        else str(a.get("Type"))
        for a in actions
    ]


class Elb001PlaintextListener(ElbRule):
    id: ClassVar[str] = "ELB-001"
    title: ClassVar[str] = "로드 밸런서 평문 리스너 사용"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def _assess(
        self,
        target: Target,
        listeners: list[Listener],
        data: dict[str, Any],
        snapshot: Snapshot,
        settings: Settings,
    ) -> tuple[Status, str, dict[str, Any]]:
        results = [self._listener(target, x, snapshot) for x in listeners]
        evidence = {"listeners": [{**r.evidence, "status": r.status.value} for r in results]}
        status = worst([r.status for r in results])
        if status == Status.FAIL:
            message = f"평문 리스너가 HTTPS 리디렉션 없이 요청을 처리함: {labels(results, status)}"
        elif status == Status.ERROR:
            message = f"HTTP 리스너 규칙을 수집하지 못함: {labels(results, status)}"
        elif status == Status.REVIEW:
            message = (
                "리스너 설정만으로 통신 암호화 여부를 확인할 수 없어 검토 필요: "
                f"{labels(results, status)}"
            )
        else:
            message = "평문 리스너 없음 (HTTP 리스너는 HTTPS 리디렉션만 수행)"
        return status, message, evidence

    @staticmethod
    def _listener(target: Target, listener: Listener, snapshot: Snapshot) -> ListenerResult:
        evidence: dict[str, Any] = {"protocol": listener.protocol, "port": listener.port}
        if target.kind == _CLASSIC:
            evidence["instance_protocol"] = listener.item.get("Listener", {}).get(
                "InstanceProtocol"
            )
        if listener.protocol in ENCRYPTED:
            return ListenerResult(listener, Status.PASS, evidence)
        if listener.protocol != _HTTP:
            return ListenerResult(listener, Status.REVIEW, evidence)
        if target.kind == _CLASSIC:
            return ListenerResult(listener, Status.FAIL, evidence)

        default_actions = listener.item.get("DefaultActions", [])
        evidence["default_actions"] = _actions(default_actions)
        if not all(_safe_action(a) for a in default_actions):
            return ListenerResult(listener, Status.FAIL, evidence)
        rules = listener.item.get("Rules")
        if rules is None:
            arn = listener.item.get("ListenerArn")
            evidence["errors"] = errors_evidence(errors_for(snapshot, "elbv2:DescribeRules", arn))
            return ListenerResult(listener, Status.ERROR, evidence)
        forwarding = [
            str(r.get("Priority"))
            for r in rules
            if not all(_safe_action(a) for a in r.get("Actions", []))
        ]
        if forwarding:
            evidence["forwarding_rules"] = forwarding
            return ListenerResult(listener, Status.FAIL, evidence)
        return ListenerResult(listener, Status.PASS, evidence)
