"""ELB collector 테스트 (ALB·NLB 리스너·규칙·보안 정책, Classic 리스너·정책)."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from kompass.aws.guard import read_only_session
from kompass.aws.session import ScanContext
from kompass.collectors.elb import ElbCollector
from kompass.snapshots import SnapshotStore, load_scan
from tests.collectors.stubbing import StubbingSession

ACCOUNT = "123456789012"
HOME = "ap-northeast-2"
OTHER = "us-east-1"
OLD_POLICY = "ELBSecurityPolicy-2016-08"


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


def _scan(regions: tuple[str, ...] = (HOME,), session: Any = None) -> ScanContext:
    return ScanContext(
        session=session or read_only_session(),
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region=HOME,
        regions=regions,
    )


def _build(region: str = HOME) -> None:
    ec2 = boto3.client("ec2", region_name=region)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnets = [
        ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.0.{n}.0/24", AvailabilityZone=f"{region}{az}")[
            "Subnet"
        ]["SubnetId"]
        for n, az in ((1, "a"), (2, "b"))
    ]
    elbv2 = boto3.client("elbv2", region_name=region)
    lb = elbv2.create_load_balancer(Name="web", Subnets=subnets, Type="application")[
        "LoadBalancers"
    ][0]["LoadBalancerArn"]
    tg = elbv2.create_target_group(Name="web", Protocol="HTTP", Port=80, VpcId=vpc)["TargetGroups"][
        0
    ]["TargetGroupArn"]
    cert = boto3.client("acm", region_name=region).request_certificate(DomainName="example.com")[
        "CertificateArn"
    ]
    elbv2.create_listener(
        LoadBalancerArn=lb,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}],
    )
    elbv2.create_listener(
        LoadBalancerArn=lb,
        Protocol="HTTPS",
        Port=443,
        SslPolicy=OLD_POLICY,
        Certificates=[{"CertificateArn": cert}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}],
    )
    boto3.client("elb", region_name=region).create_load_balancer(
        LoadBalancerName="old",
        Listeners=[
            {"Protocol": "HTTP", "LoadBalancerPort": 80, "InstancePort": 80},
            {
                "Protocol": "HTTPS",
                "LoadBalancerPort": 443,
                "InstanceProtocol": "HTTP",
                "InstancePort": 80,
                "SSLCertificateId": cert,
            },
        ],
        AvailabilityZones=[f"{region}a"],
    )


def test_collects_listeners_rules_policies_and_classic(aws: None) -> None:
    _build()
    snapshot = ElbCollector().collect(_scan())
    assert snapshot.service == "elb" and snapshot.errors == ()
    region = snapshot.data["regions"][HOME]
    [lb] = region["load_balancers"]
    listeners = {x["Protocol"]: x for x in lb["Listeners"]}
    assert listeners["HTTP"]["Rules"][-1]["IsDefault"] is True
    assert "Rules" not in listeners["HTTPS"]  # 규칙은 HTTP 리스너만 조회한다
    assert set(region["ssl_policies"]) == {OLD_POLICY}
    assert "TLSv1" in region["ssl_policies"][OLD_POLICY]["SslProtocols"]
    [classic] = region["classic_load_balancers"]
    assert classic["LoadBalancerName"] == "old" and "Policies" in classic


def test_region_without_load_balancers(aws: None) -> None:
    _build(OTHER)
    snapshot = ElbCollector().collect(_scan())
    assert snapshot.data["regions"][HOME] == {
        "load_balancers": [],
        "ssl_policies": {},
        "classic_load_balancers": [],
    }


def test_snapshot_round_trips_through_store(aws: None, tmp_path: Path) -> None:
    _build()
    scan = _scan()
    snapshot = ElbCollector().collect(scan)
    writer = SnapshotStore(tmp_path / ".kompass").begin(scan)
    writer.write(snapshot)
    assert load_scan(writer.finish())[1]["elb"] == snapshot


def test_failures_are_recorded_and_keys_missing(aws: None) -> None:
    session = read_only_session()
    elbv2 = session.client("elbv2", region_name=HOME)
    elb = session.client("elb", region_name=HOME)
    lb_arn = f"arn:aws:elasticloadbalancing:{HOME}:{ACCOUNT}:loadbalancer/app/web/1"
    gw_arn = f"arn:aws:elasticloadbalancing:{HOME}:{ACCOUNT}:loadbalancer/gwy/gw/1"
    http_arn = f"arn:aws:elasticloadbalancing:{HOME}:{ACCOUNT}:listener/app/web/1/80"
    with Stubber(elbv2) as v2_stub, Stubber(elb) as v1_stub:
        v2_stub.add_response(
            "describe_load_balancers",
            {
                "LoadBalancers": [
                    {"LoadBalancerArn": lb_arn, "LoadBalancerName": "web", "Type": "application"},
                    {"LoadBalancerArn": gw_arn, "LoadBalancerName": "gw", "Type": "gateway"},
                ]
            },
        )
        v2_stub.add_response(
            "describe_listeners",
            {
                "Listeners": [
                    {"ListenerArn": http_arn, "Protocol": "HTTP", "Port": 80},
                    {
                        "ListenerArn": f"{http_arn}3",
                        "Protocol": "HTTPS",
                        "Port": 443,
                        "SslPolicy": OLD_POLICY,
                    },
                ]
            },
            {"LoadBalancerArn": lb_arn},
        )
        v2_stub.add_client_error("describe_rules", service_error_code="AccessDenied")
        v2_stub.add_client_error("describe_ssl_policies", service_error_code="AccessDenied")
        v1_stub.add_response(
            "describe_load_balancers",
            {
                "LoadBalancerDescriptions": [
                    {
                        "LoadBalancerName": "old",
                        "ListenerDescriptions": [
                            {
                                "Listener": {
                                    "Protocol": "SSL",
                                    "LoadBalancerPort": 443,
                                    "InstancePort": 80,
                                },
                                "PolicyNames": ["p"],
                            }
                        ],
                    }
                ]
            },
        )
        v1_stub.add_client_error(
            "describe_load_balancer_policies", service_error_code="AccessDenied"
        )
        overrides = {("elbv2", HOME): elbv2, ("elb", HOME): elb}
        snapshot = ElbCollector().collect(_scan(session=StubbingSession(session, overrides)))

    region = snapshot.data["regions"][HOME]
    web, gw = region["load_balancers"]
    assert "Listeners" not in gw  # Gateway Load Balancer는 리스너를 조회하지 않는다
    assert "Rules" not in web["Listeners"][0]
    assert region["ssl_policies"] == {}
    assert "Policies" not in region["classic_load_balancers"][0]
    assert {(e.operation, e.resource) for e in snapshot.errors} == {
        ("elbv2:DescribeRules", http_arn),
        ("elbv2:DescribeSSLPolicies", OLD_POLICY),
        ("elb:DescribeLoadBalancerPolicies", "old"),
    }


def test_listener_list_failure_drops_key(aws: None) -> None:
    session = read_only_session()
    elbv2 = session.client("elbv2", region_name=HOME)
    elb = session.client("elb", region_name=HOME)
    lb_arn = f"arn:aws:elasticloadbalancing:{HOME}:{ACCOUNT}:loadbalancer/net/api/1"
    with Stubber(elbv2) as v2_stub, Stubber(elb) as v1_stub:
        v2_stub.add_response(
            "describe_load_balancers",
            {"LoadBalancers": [{"LoadBalancerArn": lb_arn, "LoadBalancerName": "api"}]},
        )
        v2_stub.add_client_error("describe_listeners", service_error_code="AccessDenied")
        v1_stub.add_client_error("describe_load_balancers", service_error_code="AccessDenied")
        overrides = {("elbv2", HOME): elbv2, ("elb", HOME): elb}
        snapshot = ElbCollector().collect(_scan(session=StubbingSession(session, overrides)))

    region = snapshot.data["regions"][HOME]
    assert "Listeners" not in region["load_balancers"][0]
    assert "classic_load_balancers" not in region
    assert {(e.operation, e.resource) for e in snapshot.errors} == {
        ("elbv2:DescribeListeners", lb_arn),
        ("elb:DescribeLoadBalancers", None),
    }
