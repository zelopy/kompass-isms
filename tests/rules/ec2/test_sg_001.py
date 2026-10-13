"""SG-001 관리 포트 전체 개방."""

from kompass.config import Ec2Settings, Settings
from kompass.models import Severity, Status
from kompass.rules.ec2.sg_001_admin_port_open import Sg001AdminPortOpen
from tests.rules.ec2.data import (
    REGION,
    WORLD6,
    collect_error,
    eni,
    permission,
    region,
    security_group,
    snapshot,
)

RULE = Sg001AdminPortOpen()


def _status(*rules: dict[str, object], settings: Settings | None = None) -> Status:
    data = snapshot({REGION: region(security_groups=[security_group("sg-1", ingress=list(rules))])})
    [finding] = RULE.evaluate(data, settings or Settings())
    return finding.status


def test_pass_restricted_ssh() -> None:
    assert _status(permission(cidrs=("10.0.0.0/8",))) == Status.PASS


def test_pass_no_rules() -> None:
    assert _status() == Status.PASS


def test_pass_other_port_open() -> None:
    assert _status(permission(from_port=443, to_port=443)) == Status.PASS


def test_pass_security_group_reference_only() -> None:
    assert _status(permission(cidrs=(), groups=("sg-2",))) == Status.PASS


def test_fail_ssh_open_ipv4() -> None:
    assert _status(permission()) == Status.FAIL


def test_fail_rdp_open_ipv6() -> None:
    assert _status(permission(from_port=3389, to_port=3389, cidrs=(WORLD6,))) == Status.FAIL


def test_fail_port_range_includes_admin_port() -> None:
    assert _status(permission(from_port=20, to_port=30)) == Status.FAIL


def test_fail_all_protocols_open() -> None:
    assert _status(permission(protocol="-1")) == Status.FAIL


def test_fail_numeric_protocol() -> None:
    assert _status(permission(protocol="6")) == Status.FAIL


def test_fail_udp_rdp() -> None:
    assert _status(permission(protocol="udp", from_port=3389, to_port=3389)) == Status.FAIL


def test_pass_icmp_open() -> None:
    assert _status(permission(protocol="icmp", from_port=-1, to_port=-1)) == Status.PASS


def test_admin_ports_from_settings() -> None:
    custom = Settings(ec2=Ec2Settings(admin_ports=(2222,)))
    assert _status(permission(), settings=custom) == Status.PASS
    assert _status(permission(from_port=2222, to_port=2222), settings=custom) == Status.FAIL


def test_finding_fields_and_evidence() -> None:
    group = security_group("sg-1", name="open-ssh", ingress=[permission()])
    data = snapshot(
        {
            REGION: region(
                security_groups=[group], network_interfaces=[eni("eni-1", groups=("sg-1",))]
            )
        }
    )
    [finding] = RULE.evaluate(data, Settings())
    assert finding.rule_id == "SG-001"
    assert finding.resource == "sg-1"
    assert finding.region == REGION
    assert finding.severity == Severity.CRITICAL
    assert finding.evidence["group_name"] == "open-ssh"
    assert finding.evidence["attached_interfaces"] == 1
    assert finding.evidence["open_rules"][0]["cidrs"] == ["0.0.0.0/0"]
    assert finding.evidence["admin_ports"] == [22, 3389]


def test_prefix_list_is_recorded_not_judged() -> None:
    group = security_group("sg-1", ingress=[permission(cidrs=(), prefix_lists=("pl-1",))])
    [finding] = RULE.evaluate(snapshot({REGION: region(security_groups=[group])}), Settings())
    assert finding.status == Status.PASS
    assert finding.evidence["prefix_lists"] == ["pl-1"]


def test_one_finding_per_group() -> None:
    groups = [security_group("sg-1", ingress=[permission()]), security_group("sg-2")]
    findings = RULE.evaluate(snapshot({REGION: region(security_groups=groups)}), Settings())
    assert {(f.resource, f.status) for f in findings} == {
        ("sg-1", Status.FAIL),
        ("sg-2", Status.PASS),
    }


def test_error_when_groups_not_collected() -> None:
    data = snapshot(
        {REGION: region(missing=("security_groups",))},
        errors=(collect_error("ec2:DescribeSecurityGroups"),),
    )
    [finding] = RULE.evaluate(data, Settings())
    assert finding.status == Status.ERROR
    assert finding.resource == "account"
    assert finding.region == REGION
    assert finding.evidence["errors"][0]["error_code"] == "UnauthorizedOperation"


def test_not_applicable_when_region_has_no_groups() -> None:
    [finding] = RULE.evaluate(snapshot({REGION: region()}), Settings())
    assert finding.status == Status.NOT_APPLICABLE


def test_attached_count_unknown_when_interfaces_missing() -> None:
    data = snapshot(
        {REGION: region(security_groups=[security_group("sg-1")], missing=("network_interfaces",))}
    )
    [finding] = RULE.evaluate(data, Settings())
    assert finding.status == Status.PASS
    assert finding.evidence["attached_interfaces"] is None
