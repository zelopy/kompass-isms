"""ELB-001~002 공통: 대상 로드 밸런서 선정, 리스너 정리, 리전 단위 오류·해당 없음 처리 (ADR-052).

- ALB·NLB(`elbv2`)와 Classic(`elb`)을 함께 본다. Gateway Load Balancer는 트래픽을 그대로 보안
  장비로 넘기는 용도라 대상에서 빼고, 리전 finding의 evidence에 이름을 남긴다.
- Classic finding의 resource는 `classic:<이름>`으로 써서 같은 이름의 ALB·NLB와 구분한다.
- 로드 밸런서 하나에 finding 하나. 리스너별 결과는 evidence `listeners`에 남기고, 로드 밸런서의
  상태는 FAIL > ERROR > REVIEW > PASS 순으로 가장 앞선 리스너 결과를 따른다. 취약이 확인된
  리스너가 있으면 다른 리스너를 판정하지 못했더라도 취약이다.
"""

from dataclasses import dataclass, field
from typing import Any

from kompass.config import Settings
from kompass.models import Finding, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence

OPERATIONS = {
    "load_balancers": "elbv2:DescribeLoadBalancers",
    "classic_load_balancers": "elb:DescribeLoadBalancers",
}
_GATEWAY = "gateway"
_CLASSIC = "classic"
_ORDER = (Status.FAIL, Status.ERROR, Status.REVIEW, Status.PASS)


@dataclass(frozen=True)
class Listener:
    protocol: str
    port: Any
    item: dict[str, Any]  # ALB·NLB는 리스너 항목, Classic은 ListenerDescriptions 항목

    @property
    def label(self) -> str:
        return f"{self.protocol}:{self.port}"


@dataclass(frozen=True)
class Target:
    resource: str  # 로드 밸런서 이름 또는 "classic:<이름>"
    kind: str  # "application" | "network" | "classic"
    name: str
    item: dict[str, Any]
    listeners: list[Listener] | None = field(default=None)  # None이면 리스너를 수집하지 못함

    def base_evidence(self) -> dict[str, Any]:
        return {"kind": self.kind, "load_balancer": self.name, "scheme": self.item.get("Scheme")}


@dataclass(frozen=True)
class ListenerResult:
    listener: Listener
    status: Status
    evidence: dict[str, Any]


def _v2_target(item: dict[str, Any]) -> Target:
    name = item["LoadBalancerName"]
    raw = item.get("Listeners")
    listeners = (
        None if raw is None else [Listener(str(x.get("Protocol")), x.get("Port"), x) for x in raw]
    )
    return Target(name, str(item.get("Type")), name, item, listeners)


def _classic_target(item: dict[str, Any]) -> Target:
    name = item["LoadBalancerName"]
    listeners = [
        Listener(
            str(desc.get("Listener", {}).get("Protocol")),
            desc.get("Listener", {}).get("LoadBalancerPort"),
            desc,
        )
        for desc in item.get("ListenerDescriptions", [])
    ]
    return Target(f"{_CLASSIC}:{name}", _CLASSIC, name, item, listeners)


def worst(statuses: list[Status]) -> Status:
    return next(s for s in _ORDER if s in statuses)


def labels(results: list[ListenerResult], status: Status) -> str:
    return ", ".join(r.listener.label for r in results if r.status == status)


class ElbRule(BaseRule):
    """하위 룰은 `_assess`로 로드 밸런서 하나의 (상태, 메시지, evidence)만 정한다.

    리스너를 수집하지 못한 로드 밸런서(ERROR)와 리스너가 없는 로드 밸런서(N/A)는 여기서 처리한다.
    """

    service = "elb"

    def _assess(
        self,
        target: Target,
        listeners: list[Listener],
        data: dict[str, Any],
        snapshot: Snapshot,
        settings: Settings,
    ) -> tuple[Status, str, dict[str, Any]]:
        raise NotImplementedError

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        for region, data in snapshot.data.get("regions", {}).items():
            missing = [kind for kind in OPERATIONS if kind not in data]
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
                        "로드 밸런서 목록을 수집하지 못함",
                        {"errors": errors_evidence(errors)},
                    )
                )
            targets, excluded = _targets(data)
            if not targets and not missing:
                findings.append(
                    self._region_finding(
                        snapshot,
                        region,
                        Status.NOT_APPLICABLE,
                        "점검 대상 로드 밸런서가 없음",
                        {"excluded": excluded},
                    )
                )
            for target in targets:
                status, message, evidence = self._target_result(
                    target, data, snapshot, settings, region
                )
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

    def _target_result(
        self,
        target: Target,
        data: dict[str, Any],
        snapshot: Snapshot,
        settings: Settings,
        region: str,
    ) -> tuple[Status, str, dict[str, Any]]:
        if target.listeners is None:
            arn = target.item.get("LoadBalancerArn")
            errors = [
                e
                for e in snapshot.errors
                if e.region == region
                and e.operation == "elbv2:DescribeListeners"
                and e.resource == arn
            ]
            return (
                Status.ERROR,
                "리스너 목록을 수집하지 못함",
                {"errors": errors_evidence(errors)},
            )
        if not target.listeners:
            return Status.NOT_APPLICABLE, "리스너가 없음", {"listeners": []}
        return self._assess(target, target.listeners, data, snapshot, settings)

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


def _targets(data: dict[str, Any]) -> tuple[list[Target], list[str]]:
    targets: list[Target] = []
    excluded: list[str] = []
    for item in data.get("load_balancers", []):
        if item.get("Type") == _GATEWAY:
            excluded.append(item["LoadBalancerName"])
        else:
            targets.append(_v2_target(item))
    targets.extend(_classic_target(item) for item in data.get("classic_load_balancers", []))
    return targets, excluded
