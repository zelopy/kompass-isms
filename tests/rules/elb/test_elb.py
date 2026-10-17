"""ELB-001 로드 밸런서 평문 리스너 사용, ELB-002 로드 밸런서 TLS 정책 취약 (ADR-052)."""

from typing import Any

import pytest

from kompass.config import Settings
from kompass.models import CollectError, Finding, Status
from kompass.rules.elb.elb_001_plaintext_listener import Elb001PlaintextListener
from kompass.rules.elb.elb_002_tls_policy import Elb002TlsPolicy
from tests.rules.elb.data import (
    MODERN_POLICY,
    OLD_POLICY,
    REGION,
    classic,
    classic_listener,
    collect_error,
    fixed_response,
    forward,
    listener,
    load_balancer,
    negotiation_policy,
    redirect,
    region,
    rule,
    snapshot,
    ssl_policy,
    without_rules,
)

ELB001 = Elb001PlaintextListener()
ELB002 = Elb002TlsPolicy()
HTTPS_443 = listener("HTTPS", 443, ssl_policy=MODERN_POLICY)


def _run(
    rule_obj: Any,
    data: dict[str, Any],
    *errors: CollectError,
    settings: Settings | None = None,
) -> list[Finding]:
    findings: list[Finding] = rule_obj.evaluate(
        snapshot({REGION: data}, errors), settings or Settings()
    )
    return findings


def _one(rule_obj: Any, data: dict[str, Any], *errors: CollectError, **kw: Any) -> Finding:
    [finding] = _run(rule_obj, data, *errors, **kw)
    assert finding.region == REGION
    return finding


# --- 공통: 대상 선정, 리전 오류, 해당 없음 ---


@pytest.mark.parametrize("rule_obj", [ELB001, ELB002])
def test_region_without_load_balancers_is_not_applicable(rule_obj: Any) -> None:
    finding = _one(rule_obj, region())
    assert finding.status == Status.NOT_APPLICABLE and finding.resource == "account"


@pytest.mark.parametrize("rule_obj", [ELB001, ELB002])
def test_gateway_load_balancer_is_excluded(rule_obj: Any) -> None:
    gwlb = load_balancer("inspect", [listener("GENEVE", 6081)], lb_type="gateway")
    finding = _one(rule_obj, region([gwlb]))
    assert finding.status == Status.NOT_APPLICABLE
    assert finding.evidence["excluded"] == ["inspect"]


@pytest.mark.parametrize("rule_obj", [ELB001, ELB002])
def test_region_error_when_list_missing_but_other_kind_still_judged(rule_obj: Any) -> None:
    data = region(
        classic_load_balancers=[
            classic(
                "old",
                [classic_listener("HTTPS", 443, ["p"])],
                [negotiation_policy("p", ["TLSv1.2"])],
            )
        ],
        missing=("load_balancers", "ssl_policies"),
    )
    findings = _run(rule_obj, data, collect_error("elbv2:DescribeLoadBalancers"))
    by_resource = {f.resource: f for f in findings}
    assert by_resource["account"].status == Status.ERROR
    assert by_resource["account"].evidence["errors"][0]["operation"] == (
        "elbv2:DescribeLoadBalancers"
    )
    assert by_resource["classic:old"].status == Status.PASS


@pytest.mark.parametrize("rule_obj", [ELB001, ELB002])
def test_region_error_when_both_lists_missing(rule_obj: Any) -> None:
    data = region(missing=("load_balancers", "ssl_policies", "classic_load_balancers"))
    finding = _one(
        rule_obj,
        data,
        collect_error("elbv2:DescribeLoadBalancers"),
        collect_error("elb:DescribeLoadBalancers"),
    )
    assert finding.status == Status.ERROR and len(finding.evidence["errors"]) == 2


@pytest.mark.parametrize("rule_obj", [ELB001, ELB002])
def test_listeners_not_collected_is_error(rule_obj: Any) -> None:
    lb = load_balancer("web", None)
    arn = lb["LoadBalancerArn"]
    finding = _one(rule_obj, region([lb]), collect_error("elbv2:DescribeListeners", resource=arn))
    assert finding.status == Status.ERROR and finding.resource == "web"
    assert finding.evidence["errors"][0]["resource"] == arn


@pytest.mark.parametrize("rule_obj", [ELB001, ELB002])
def test_load_balancer_without_listeners_is_not_applicable(rule_obj: Any) -> None:
    finding = _one(rule_obj, region([load_balancer("idle", [])]))
    assert finding.status == Status.NOT_APPLICABLE and finding.resource == "idle"


def test_evidence_has_kind_name_scheme() -> None:
    lb = load_balancer("internal-api", [HTTPS_443], scheme="internal")
    finding = _one(ELB001, region([lb]))
    assert finding.evidence["kind"] == "application"
    assert finding.evidence["load_balancer"] == "internal-api"
    assert finding.evidence["scheme"] == "internal"


# --- ELB-001 ---


def test_elb001_pass_https_only() -> None:
    finding = _one(ELB001, region([load_balancer("web", [HTTPS_443])]))
    assert finding.status == Status.PASS


def test_elb001_pass_http_redirects_to_https() -> None:
    http = listener("HTTP", 80, [redirect()], rules=[rule("1", [fixed_response()])])
    finding = _one(ELB001, region([load_balancer("web", [http, HTTPS_443])]))
    assert finding.status == Status.PASS
    [http_evidence] = [x for x in finding.evidence["listeners"] if x["protocol"] == "HTTP"]
    assert http_evidence["status"] == "PASS"


def test_elb001_fail_http_forwards() -> None:
    finding = _one(ELB001, region([load_balancer("web", [listener("HTTP", 80), HTTPS_443])]))
    assert finding.status == Status.FAIL
    assert "HTTP:80" in finding.message


def test_elb001_fail_redirect_without_https() -> None:
    # 프로토콜을 지정하지 않은 리디렉션은 원래 프로토콜(#{protocol})을 유지한다
    http = listener("HTTP", 80, [redirect(protocol=None)])
    assert _one(ELB001, region([load_balancer("web", [http])])).status == Status.FAIL


def test_elb001_fail_when_non_default_rule_forwards() -> None:
    http = listener("HTTP", 80, [redirect()], rules=[rule("10", [forward()])])
    finding = _one(ELB001, region([load_balancer("web", [http])]))
    assert finding.status == Status.FAIL
    assert finding.evidence["listeners"][0]["forwarding_rules"] == ["10"]


def test_elb001_rules_not_collected_is_error() -> None:
    http = without_rules(listener("HTTP", 80, [redirect()]))
    finding = _one(
        ELB001,
        region([load_balancer("web", [http])]),
        collect_error("elbv2:DescribeRules", resource=http["ListenerArn"]),
    )
    assert finding.status == Status.ERROR
    assert finding.evidence["listeners"][0]["errors"][0]["operation"] == "elbv2:DescribeRules"


def test_elb001_fail_from_default_action_even_without_rules() -> None:
    # 기본 동작만으로 평문 전달이 확인되면 규칙을 몰라도 FAIL
    http = without_rules(listener("HTTP", 80, [forward()]))
    assert _one(ELB001, region([load_balancer("web", [http])])).status == Status.FAIL


def test_elb001_fail_outranks_error_and_review() -> None:
    lb = load_balancer(
        "net",
        [
            without_rules(listener("HTTP", 8080, [redirect()])),
            listener("HTTP", 80),
            listener("TCP", 3306),
        ],
    )
    assert _one(ELB001, region([lb])).status == Status.FAIL


def test_elb001_nlb_tcp_is_review_tls_is_pass() -> None:
    tcp = load_balancer("db-proxy", [listener("TCP", 5432)], lb_type="network")
    tls = load_balancer("api", [listener("TLS", 443, ssl_policy=MODERN_POLICY)], lb_type="network")
    by_resource = {f.resource: f for f in _run(ELB001, region([tcp, tls]))}
    assert by_resource["db-proxy"].status == Status.REVIEW
    assert "TCP:5432" in by_resource["db-proxy"].message
    assert by_resource["api"].status == Status.PASS


def test_elb001_classic_http_fail_tcp_review_https_pass() -> None:
    lbs = [
        classic("http", [classic_listener("HTTP", 80)]),
        classic("tcp", [classic_listener("TCP", 3306, instance_protocol="TCP")]),
        classic("https", [classic_listener("HTTPS", 443, ["p"])], [negotiation_policy("p", [])]),
    ]
    by_resource = {f.resource: f for f in _run(ELB001, region(classic_load_balancers=lbs))}
    assert by_resource["classic:http"].status == Status.FAIL
    assert by_resource["classic:tcp"].status == Status.REVIEW
    assert by_resource["classic:https"].status == Status.PASS
    assert by_resource["classic:https"].evidence["kind"] == "classic"
    assert by_resource["classic:https"].evidence["listeners"][0]["instance_protocol"] == "HTTP"


# --- ELB-002 ---


def test_elb002_pass_modern_policy() -> None:
    finding = _one(ELB002, region([load_balancer("web", [HTTPS_443])]))
    assert finding.status == Status.PASS
    assert finding.evidence["listeners"][0]["ssl_policy"] == MODERN_POLICY
    assert finding.evidence["min_tls_version"] == "TLSv1.2"


def test_elb002_fail_old_policy() -> None:
    old = listener("HTTPS", 443, ssl_policy=OLD_POLICY)
    finding = _one(ELB002, region([load_balancer("web", [old])]))
    assert finding.status == Status.FAIL
    assert finding.evidence["listeners"][0]["weak_protocols"] == ["TLSv1", "TLSv1.1"]
    assert OLD_POLICY in finding.message


def test_elb002_ignores_plaintext_listeners() -> None:
    # moto처럼 HTTP 리스너에 SslPolicy가 붙어 와도 판정하지 않는다
    http = listener("HTTP", 80, ssl_policy=OLD_POLICY)
    finding = _one(ELB002, region([load_balancer("web", [http, HTTPS_443])]))
    assert finding.status == Status.PASS and len(finding.evidence["listeners"]) == 1


def test_elb002_not_applicable_without_tls_listener() -> None:
    finding = _one(ELB002, region([load_balancer("web", [listener("HTTP", 80)])]))
    assert finding.status == Status.NOT_APPLICABLE and finding.resource == "web"


def test_elb002_policy_not_collected_is_error() -> None:
    old = listener("TLS", 443, ssl_policy=OLD_POLICY)
    finding = _one(
        ELB002,
        region([load_balancer("api", [old], lb_type="network")], ssl_policies={}),
        collect_error("elbv2:DescribeSSLPolicies", resource=OLD_POLICY),
    )
    assert finding.status == Status.ERROR
    assert finding.evidence["listeners"][0]["errors"][0]["resource"] == OLD_POLICY


def test_elb002_listener_without_policy_name_is_error() -> None:
    finding = _one(ELB002, region([load_balancer("web", [listener("HTTPS", 443)])]))
    assert finding.status == Status.ERROR


def test_elb002_unknown_protocol_is_error() -> None:
    policies = {MODERN_POLICY: ssl_policy(MODERN_POLICY, ["TLSv1.2", "TLSv9"])}
    finding = _one(ELB002, region([load_balancer("web", [HTTPS_443])], ssl_policies=policies))
    assert finding.status == Status.ERROR


def test_elb002_min_version_from_settings() -> None:
    settings = Settings.model_validate({"elb": {"min_tls_version": "TLSv1.3"}})
    finding = _one(ELB002, region([load_balancer("web", [HTTPS_443])]), settings=settings)
    assert finding.status == Status.FAIL
    assert finding.evidence["listeners"][0]["weak_protocols"] == ["TLSv1.2"]


def test_elb002_classic_policy_protocols() -> None:
    lbs = [
        classic(
            "weak",
            [classic_listener("HTTPS", 443, ["old-policy"])],
            [negotiation_policy("old-policy", ["TLSv1", "TLSv1.1", "TLSv1.2"])],
        ),
        classic(
            "strong",
            [classic_listener("SSL", 443, ["strict"])],
            [
                negotiation_policy(
                    "strict", ["TLSv1.2"], reference="ELBSecurityPolicy-TLS-1-2-2017-01"
                )
            ],
        ),
    ]
    by_resource = {f.resource: f for f in _run(ELB002, region(classic_load_balancers=lbs))}
    weak = by_resource["classic:weak"]
    assert weak.status == Status.FAIL
    assert weak.evidence["listeners"][0]["weak_protocols"] == ["TLSv1", "TLSv1.1"]
    assert weak.evidence["listeners"][0]["policy_name"] == "old-policy"
    assert weak.evidence["listeners"][0]["reference_policy"] == OLD_POLICY
    assert by_resource["classic:strong"].status == Status.PASS


def test_elb002_classic_policies_not_collected_is_error() -> None:
    lb = classic("old", [classic_listener("HTTPS", 443, ["p"])])
    finding = _one(
        ELB002,
        region(classic_load_balancers=[lb]),
        collect_error("elb:DescribeLoadBalancerPolicies", resource="old"),
    )
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["operation"] == "elb:DescribeLoadBalancerPolicies"


def test_elb002_classic_listener_without_negotiation_policy_is_error() -> None:
    lb = classic("old", [classic_listener("HTTPS", 443, [])], [])
    assert _one(ELB002, region(classic_load_balancers=[lb])).status == Status.ERROR
