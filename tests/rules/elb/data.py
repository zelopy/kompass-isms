"""ELB 룰 테스트용 가짜 데이터. collector가 저장하는 형태를 따른다 (ADR-052).

- ALB·NLB: `DescribeLoadBalancers` 항목에 `Listeners`(`DescribeListeners`)를 더하고, HTTP 리스너에는
  `Rules`(`DescribeRules`, 기본 규칙 포함)를 더한다.
- `ssl_policies`: HTTPS·TLS 리스너가 쓰는 정책 이름 → `DescribeSSLPolicies` 항목.
- Classic: `LoadBalancerDescriptions` 항목. HTTPS·SSL 리스너가 있으면 `Policies`
  (`DescribeLoadBalancerPolicies`)를 더한다.
"""

from datetime import UTC, datetime
from typing import Any

from kompass.models import CollectError, Snapshot

T0 = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
OLD_POLICY = "ELBSecurityPolicy-2016-08"
MODERN_POLICY = "ELBSecurityPolicy-TLS13-1-2-2021-06"
TG = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/web/0123456789abcdef"


def _arn(kind: str, name: str) -> str:
    return f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:{kind}/{name}/0123456789abcdef"


def forward() -> dict[str, Any]:
    return {"Type": "forward", "TargetGroupArn": TG}


def redirect(protocol: str | None = "HTTPS") -> dict[str, Any]:
    config: dict[str, Any] = {"Port": "443", "StatusCode": "HTTP_301"}
    if protocol is not None:
        config["Protocol"] = protocol
    return {"Type": "redirect", "RedirectConfig": config}


def fixed_response() -> dict[str, Any]:
    return {"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "404"}}


def rule(priority: str, actions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "RuleArn": _arn("listener-rule/app", f"web-{priority}"),
        "Priority": priority,
        "Conditions": [] if priority == "default" else [{"Field": "path-pattern"}],
        "Actions": actions,
        "IsDefault": priority == "default",
    }


def listener(
    protocol: str,
    port: int,
    actions: list[dict[str, Any]] | None = None,
    *,
    rules: list[dict[str, Any]] | None = None,
    ssl_policy: str | None = None,
) -> dict[str, Any]:
    """HTTP 리스너는 `rules`를 주지 않으면 기본 규칙만 넣는다. 수집 실패는 `rules=[]` 대신
    `without_rules()`로 만든다."""
    default_actions = actions if actions is not None else [forward()]
    item: dict[str, Any] = {
        "ListenerArn": _arn("listener/app", f"web-{port}"),
        "Protocol": protocol,
        "Port": port,
        "DefaultActions": default_actions,
    }
    if ssl_policy is not None:
        item["SslPolicy"] = ssl_policy
    if protocol == "HTTP":
        item["Rules"] = [*(rules or []), rule("default", default_actions)]
    return item


def without_rules(item: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in item.items() if k != "Rules"}


def load_balancer(
    name: str,
    listeners: list[dict[str, Any]] | None,
    *,
    lb_type: str = "application",
    scheme: str = "internet-facing",
) -> dict[str, Any]:
    """`listeners`가 None이면 리스너 수집에 실패한 것이다 (`Listeners` 키 없음)."""
    item: dict[str, Any] = {
        "LoadBalancerArn": _arn(f"loadbalancer/{lb_type[:3]}", name),
        "LoadBalancerName": name,
        "Type": lb_type,
        "Scheme": scheme,
        "State": {"Code": "active"},
    }
    if listeners is not None:
        item["Listeners"] = listeners
    return item


def ssl_policy(name: str, protocols: list[str]) -> dict[str, Any]:
    return {"Name": name, "SslProtocols": protocols, "Ciphers": []}


DEFAULT_SSL_POLICIES = {
    OLD_POLICY: ssl_policy(OLD_POLICY, ["TLSv1.2", "TLSv1.1", "TLSv1"]),
    MODERN_POLICY: ssl_policy(MODERN_POLICY, ["TLSv1.3", "TLSv1.2"]),
}


def classic_listener(
    protocol: str, port: int, policy_names: list[str] | None = None, instance_protocol: str = "HTTP"
) -> dict[str, Any]:
    return {
        "Listener": {
            "Protocol": protocol,
            "LoadBalancerPort": port,
            "InstanceProtocol": instance_protocol,
            "InstancePort": 80,
        },
        "PolicyNames": policy_names or [],
    }


def negotiation_policy(
    name: str, protocols: list[str], reference: str | None = OLD_POLICY
) -> dict[str, Any]:
    """Classic SSL 협상 정책. `protocols`에 있는 것만 `Protocol-…` 속성이 true다."""
    attributes = [
        {"AttributeName": f"Protocol-{p}", "AttributeValue": str(p in protocols).lower()}
        for p in ("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2")
    ]
    if reference is not None:
        attributes.append(
            {"AttributeName": "Reference-Security-Policy", "AttributeValue": reference}
        )
    attributes.append({"AttributeName": "ECDHE-RSA-AES128-GCM-SHA256", "AttributeValue": "true"})
    return {
        "PolicyName": name,
        "PolicyTypeName": "SSLNegotiationPolicyType",
        "PolicyAttributeDescriptions": attributes,
    }


def classic(
    name: str,
    listeners: list[dict[str, Any]],
    policies: list[dict[str, Any]] | None = None,
    *,
    scheme: str = "internet-facing",
) -> dict[str, Any]:
    """`policies`가 None이면 정책 수집에 실패했거나 수집하지 않은 것이다 (`Policies` 키 없음)."""
    item: dict[str, Any] = {
        "LoadBalancerName": name,
        "Scheme": scheme,
        "ListenerDescriptions": listeners,
    }
    if policies is not None:
        item["Policies"] = policies
    return item


def region(
    load_balancers: list[dict[str, Any]] | None = None,
    classic_load_balancers: list[dict[str, Any]] | None = None,
    *,
    ssl_policies: dict[str, dict[str, Any]] | None = None,
    missing: tuple[str, ...] = (),
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "load_balancers": load_balancers or [],
        "ssl_policies": DEFAULT_SSL_POLICIES if ssl_policies is None else ssl_policies,
        "classic_load_balancers": classic_load_balancers or [],
    }
    for kind in missing:
        data.pop(kind)
    return data


def snapshot(regions: dict[str, dict[str, Any]], errors: tuple[CollectError, ...] = ()) -> Snapshot:
    return Snapshot(
        service="elb",
        account_id=ACCOUNT,
        regions=tuple(regions),
        collected_at=T0,
        data={"regions": regions},
        errors=errors,
    )


def collect_error(
    operation: str, region_name: str = REGION, resource: str | None = None
) -> CollectError:
    return CollectError(
        operation=operation,
        region=region_name,
        error_code="AccessDenied",
        message="no",
        resource=resource,
    )
