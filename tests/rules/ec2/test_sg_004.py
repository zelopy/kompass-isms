"""SG-004 사용 중인 기본 보안그룹에 규칙 존재."""

from kompass.config import Settings
from kompass.models import Finding, Severity, Status
from kompass.rules.ec2.sg_004_default_group_in_use import Sg004DefaultGroupInUse
from tests.rules.ec2.data import (
    REGION,
    collect_error,
    eni,
    permission,
    region,
    security_group,
    snapshot,
)

RULE = Sg004DefaultGroupInUse()
SELF_RULE = permission(protocol="-1", cidrs=(), groups=("sg-d",))
EGRESS_ALL = permission(protocol="-1")


def _default(ingress: bool = True, egress: bool = True) -> dict[str, object]:
    return security_group(
        "sg-d",
        name="default",
        ingress=[SELF_RULE] if ingress else [],
        egress=[EGRESS_ALL] if egress else [],
    )


def _findings(
    groups: list[dict[str, object]], interfaces: list[dict[str, object]]
) -> list[Finding]:
    data = snapshot({REGION: region(security_groups=groups, network_interfaces=interfaces)})
    return RULE.evaluate(data, Settings())


def test_fail_default_rules_in_use() -> None:
    [finding] = _findings([_default()], [eni("eni-1", groups=("sg-d",))])
    assert finding.status == Status.FAIL
    assert finding.resource == "sg-d"
    assert finding.severity == Severity.LOW
    assert finding.evidence["attached_interfaces"] == 1


def test_fail_egress_only_in_use() -> None:
    [finding] = _findings([_default(ingress=False)], [eni("eni-1", groups=("sg-d",))])
    assert finding.status == Status.FAIL


def test_pass_default_rules_unused() -> None:
    # 손대지 않은 기본 VPC의 기본 SG. 리전마다 FAIL이 나오지 않게 한다 (ADR-018)
    [finding] = _findings([_default()], [])
    assert finding.status == Status.PASS
    assert finding.evidence["has_rules"] is True
    assert finding.evidence["attached_interfaces"] == 0


def test_pass_default_rules_removed_in_use() -> None:
    [finding] = _findings([_default(ingress=False, egress=False)], [eni("eni-1", groups=("sg-d",))])
    assert finding.status == Status.PASS


def test_non_default_groups_are_ignored() -> None:
    findings = _findings([_default(), security_group("sg-1", ingress=[permission()])], [])
    assert [f.resource for f in findings] == ["sg-d"]


def test_error_when_usage_unknown() -> None:
    # 규칙이 있는데 연결 여부를 모르면 FAIL/PASS를 단정하지 않는다
    data = snapshot(
        {REGION: region(security_groups=[_default()], missing=("network_interfaces",))},
        errors=(collect_error("ec2:DescribeNetworkInterfaces"),),
    )
    [finding] = RULE.evaluate(data, Settings())
    assert finding.status == Status.ERROR
    assert finding.resource == "sg-d"


def test_pass_without_rules_even_if_usage_unknown() -> None:
    data = snapshot(
        {REGION: region(security_groups=[_default(False, False)], missing=("network_interfaces",))}
    )
    [finding] = RULE.evaluate(data, Settings())
    assert finding.status == Status.PASS


def test_error_when_groups_not_collected() -> None:
    data = snapshot(
        {REGION: region(missing=("security_groups",))},
        errors=(collect_error("ec2:DescribeSecurityGroups"),),
    )
    [finding] = RULE.evaluate(data, Settings())
    assert finding.status == Status.ERROR
    assert finding.resource == "account"


def test_not_applicable_without_default_group() -> None:
    [finding] = _findings([security_group("sg-1")], [])
    assert finding.status == Status.NOT_APPLICABLE
