"""SG-002 전체 포트·프로토콜 개방, SG-003 데이터베이스 포트 전체 개방."""

from kompass.config import Ec2Settings, Settings
from kompass.models import Severity, Status
from kompass.rules.base import BaseRule
from kompass.rules.ec2.sg_002_all_ports_open import Sg002AllPortsOpen
from kompass.rules.ec2.sg_003_db_port_open import Sg003DbPortOpen
from tests.rules.ec2.data import (
    REGION,
    WORLD6,
    collect_error,
    permission,
    region,
    security_group,
    snapshot,
)

SG002 = Sg002AllPortsOpen()
SG003 = Sg003DbPortOpen()


def _status(rule: BaseRule, *rules: dict[str, object], settings: Settings | None = None) -> Status:
    data = snapshot({REGION: region(security_groups=[security_group("sg-1", ingress=list(rules))])})
    [finding] = rule.evaluate(data, settings or Settings())
    return finding.status


# --- SG-002 ---


def test_sg002_fail_all_protocols() -> None:
    assert _status(SG002, permission(protocol="-1")) == Status.FAIL


def test_sg002_fail_full_tcp_range() -> None:
    assert _status(SG002, permission(from_port=0, to_port=65535)) == Status.FAIL


def test_sg002_fail_range_from_one() -> None:
    # 1~65535도 사실상 전체 개방이다 (RULES.md SG-002 해석)
    assert _status(SG002, permission(protocol="udp", from_port=1, to_port=65535)) == Status.FAIL


def test_sg002_pass_partial_range() -> None:
    assert _status(SG002, permission(from_port=1024, to_port=65535)) == Status.PASS


def test_sg002_pass_all_protocols_from_private_range() -> None:
    assert _status(SG002, permission(protocol="-1", cidrs=("10.0.0.0/8",))) == Status.PASS


def test_sg002_severity() -> None:
    data = snapshot({REGION: region(security_groups=[security_group("sg-1")])})
    assert SG002.evaluate(data, Settings())[0].severity == Severity.CRITICAL


def test_sg002_error() -> None:
    data = snapshot(
        {REGION: region(missing=("security_groups",))},
        errors=(collect_error("ec2:DescribeSecurityGroups"),),
    )
    assert SG002.evaluate(data, Settings())[0].status == Status.ERROR


# --- SG-003 ---


def test_sg003_fail_mysql_ipv6() -> None:
    assert _status(SG003, permission(from_port=3306, to_port=3306, cidrs=(WORLD6,))) == Status.FAIL


def test_sg003_fail_all_protocols() -> None:
    assert _status(SG003, permission(protocol="-1")) == Status.FAIL


def test_sg003_pass_ssh_only() -> None:
    assert _status(SG003, permission()) == Status.PASS


def test_sg003_pass_db_from_private_range() -> None:
    rule = permission(from_port=5432, to_port=5432, cidrs=("10.0.0.0/8",))
    assert _status(SG003, rule) == Status.PASS


def test_sg003_db_ports_from_settings() -> None:
    custom = Settings(ec2=Ec2Settings(db_ports=(9200,)))
    assert _status(SG003, permission(from_port=3306, to_port=3306), settings=custom) == Status.PASS
    assert _status(SG003, permission(from_port=9200, to_port=9200), settings=custom) == Status.FAIL


def test_sg003_evidence_lists_matched_ports() -> None:
    group = security_group("sg-1", ingress=[permission(from_port=3300, to_port=3310)])
    [finding] = SG003.evaluate(snapshot({REGION: region(security_groups=[group])}), Settings())
    assert finding.evidence["open_rules"][0]["matched_ports"] == [3306]
    assert finding.severity == Severity.HIGH


def test_sg003_error() -> None:
    data = snapshot(
        {REGION: region(missing=("security_groups",))},
        errors=(collect_error("ec2:DescribeSecurityGroups"),),
    )
    assert SG003.evaluate(data, Settings())[0].status == Status.ERROR
