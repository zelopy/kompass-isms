"""VPC-003 VPC 흐름 로그 미설정."""

from kompass.config import Settings
from kompass.models import Finding, Status
from kompass.rules.ec2.vpc_003_flow_logs import Vpc003FlowLogs
from tests.rules.ec2.data import REGION, collect_error, eni, flow_log, region, snapshot, vpc

VPC003 = Vpc003FlowLogs()


def _run(data: dict[str, object], *errors: object) -> list[Finding]:
    return VPC003.evaluate(snapshot({REGION: data}, errors=tuple(errors)), Settings())  # type: ignore[arg-type]


def _one(data: dict[str, object]) -> Finding:
    [finding] = _run(data)
    return finding


def test_pass_with_vpc_flow_log() -> None:
    finding = _one(
        region(
            vpcs=[vpc("vpc-1")], network_interfaces=[eni("eni-1")], flow_logs=[flow_log("vpc-1")]
        )
    )
    assert finding.status == Status.PASS and finding.resource == "vpc-1"
    assert finding.evidence["flow_logs"][0]["traffic_type"] == "ALL"


def test_pass_when_every_interface_is_covered_by_subnet_or_eni_logs() -> None:
    data = region(
        vpcs=[vpc("vpc-1")],
        network_interfaces=[eni("eni-1", "subnet-1"), eni("eni-2", "subnet-2")],
        flow_logs=[flow_log("subnet-1"), flow_log("eni-2")],
    )
    assert _one(data).status == Status.PASS


def test_fail_without_flow_logs() -> None:
    finding = _one(region(vpcs=[vpc("vpc-1")], network_interfaces=[eni("eni-1")]))
    assert finding.status == Status.FAIL
    assert finding.evidence["uncovered_interfaces"] == 1


def test_fail_when_some_interfaces_are_not_covered() -> None:
    data = region(
        vpcs=[vpc("vpc-1")],
        network_interfaces=[eni("eni-1", "subnet-1"), eni("eni-2", "subnet-2")],
        flow_logs=[flow_log("subnet-1")],
    )
    finding = _one(data)
    assert finding.status == Status.FAIL and finding.evidence["uncovered_interfaces"] == 1


def test_inactive_flow_log_does_not_count() -> None:
    data = region(
        vpcs=[vpc("vpc-1")],
        network_interfaces=[eni("eni-1")],
        flow_logs=[flow_log("vpc-1", status="INACTIVE")],
    )
    assert _one(data).status == Status.FAIL


def test_other_vpc_flow_log_does_not_count() -> None:
    data = region(
        vpcs=[vpc("vpc-1"), vpc("vpc-2")],
        network_interfaces=[eni("eni-1", vpc_id="vpc-1")],
        flow_logs=[flow_log("vpc-2")],
    )
    statuses = {f.resource: f.status for f in _run(data)}
    assert statuses == {"vpc-1": Status.FAIL, "vpc-2": Status.NOT_APPLICABLE}


def test_vpc_without_interfaces_is_not_applicable() -> None:
    assert _one(region(vpcs=[vpc("vpc-1")])).status == Status.NOT_APPLICABLE


def test_error_when_flow_logs_missing() -> None:
    data = region(vpcs=[vpc("vpc-1")], network_interfaces=[eni("eni-1")], missing=("flow_logs",))
    [finding] = _run(data, collect_error("ec2:DescribeFlowLogs"))
    assert finding.status == Status.ERROR and finding.resource == "account"
    assert finding.evidence["errors"][0]["operation"] == "ec2:DescribeFlowLogs"
