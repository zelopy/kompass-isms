"""에이전트 조사 도구 (ADR-035, ADR-036). moto와 botocore Stubber만 쓴다."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from kompass.agent import tools
from kompass.agent.tools import TOOLS, Tool, ToolContext, ToolInputError, ToolResult, call_tool
from kompass.aws.guard import ReadOnlyViolation, read_only_session
from kompass.aws.session import ScanContext

ACCOUNT = "123456789012"
REGION = "ap-northeast-2"


@pytest.fixture
def context() -> Iterator[ToolContext]:
    with mock_aws():
        scan = ScanContext(
            session=read_only_session(),
            account_id=ACCOUNT,
            partition="aws",
            caller_arn=f"arn:aws:iam::{ACCOUNT}:user/audit",
            home_region=REGION,
            regions=(REGION,),
            enabled_regions=(REGION,),
        )
        yield ToolContext(scan)


def _admin(service: str, region: str = REGION) -> Any:
    """테스트 리소스를 만드는 가드 없는 클라이언트 (도구는 가드가 걸린 세션만 쓴다)."""
    return boto3.client(service, region_name=region)


# --- 도구 목록 ---


def test_tool_catalog() -> None:
    assert 10 <= len(TOOLS) <= 14
    assert len({t.name for t in TOOLS}) == len(TOOLS)
    for tool in TOOLS:
        assert tool.description and tool.input_schema["type"] == "object"
        assert set(tool.input_schema["required"]) <= set(tool.input_schema["properties"])


# --- 입력 검사 ---


def test_input_errors(context: ToolContext) -> None:
    with pytest.raises(ToolInputError, match="없는 도구"):
        call_tool(context, "s3_delete_bucket", {})
    with pytest.raises(ToolInputError, match="빠진 값"):
        call_tool(context, "s3_bucket_access", {})
    with pytest.raises(ToolInputError, match="알 수 없는 값"):
        call_tool(context, "s3_bucket_access", {"bucket": "b", "force": True})
    with pytest.raises(ToolInputError, match="string"):
        call_tool(context, "s3_bucket_access", {"bucket": 3})
    with pytest.raises(ToolInputError, match="중 하나"):
        call_tool(
            context,
            "cloudtrail_lookup_events",
            {"attribute_key": "AccessKeyId", "attribute_value": "x"},
        )


def test_region_outside_scan_is_rejected(context: ToolContext) -> None:
    with pytest.raises(ToolInputError, match="점검 범위 밖"):
        call_tool(context, "ec2_security_group", {"group_id": "sg-1", "region": "us-west-2"})


def test_aws_errors_are_results_not_exceptions(context: ToolContext) -> None:
    result = call_tool(context, "ec2_security_group", {"group_id": "sg-0123456789abcdef0"})
    assert result.data["error"].startswith("InvalidGroup")


def test_read_only_violation_is_not_swallowed(
    context: ToolContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bad(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
        ctx.client("s3").create_bucket(Bucket="x")
        return ToolResult({})

    monkeypatch.setitem(tools.TOOLS_BY_NAME, "bad", Tool("bad", "d", {"type": "object"}, bad))
    with pytest.raises(ReadOnlyViolation):
        call_tool(context, "bad", {})


# --- S3 ---


def test_s3_bucket_access(context: ToolContext) -> None:
    s3 = _admin("s3")
    s3.create_bucket(Bucket="acme-public", CreateBucketConfiguration={"LocationConstraint": REGION})
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::acme-public/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket="acme-public", Policy=json.dumps(policy))
    result = call_tool(context, "s3_bucket_access", {"bucket": "acme-public"})
    assert result.data["policy"]["Statement"][0]["Sid"] == "PublicRead"
    assert result.data["public_access_block"] is None
    assert result.data["acl_grants"]
    assert "acme-public" in result.names and "PublicRead" in result.names


def test_s3_bucket_without_policy(context: ToolContext) -> None:
    _admin("s3").create_bucket(
        Bucket="acme-private", CreateBucketConfiguration={"LocationConstraint": REGION}
    )
    result = call_tool(context, "s3_bucket_access", {"bucket": "acme-private"})
    assert result.data["policy"] is None and result.data["policy_is_public"] is None


def test_s3_account_public_access_block(context: ToolContext) -> None:
    assert call_tool(context, "s3_account_public_access_block", {}).data == {
        "public_access_block": None
    }


# --- CloudTrail ---


def test_cloudtrail_data_events(context: ToolContext) -> None:
    _admin("s3").create_bucket(
        Bucket="trail-logs", CreateBucketConfiguration={"LocationConstraint": REGION}
    )
    cloudtrail = _admin("cloudtrail")
    cloudtrail.create_trail(Name="org-trail", S3BucketName="trail-logs", IsMultiRegionTrail=True)
    cloudtrail.put_event_selectors(
        TrailName="org-trail",
        EventSelectors=[
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True,
                "DataResources": [
                    {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::acme-public/"]}
                ],
            }
        ],
    )
    logged = call_tool(context, "cloudtrail_data_events", {"bucket": "acme-public"})
    other = call_tool(context, "cloudtrail_data_events", {"bucket": "acme-other"})
    assert logged.data["trails"][0]["logs_bucket_data_events"] is True
    assert other.data["trails"][0]["logs_bucket_data_events"] is False
    assert "org-trail" in logged.names


def _stub(context: ToolContext, service: str, region: str | None = None) -> Stubber:
    client = context.client(service, region)
    stubber = Stubber(client)
    stubber.activate()
    return stubber


def test_cloudtrail_lookup_events(context: ToolContext) -> None:
    stubber = _stub(context, "cloudtrail")
    detail = {
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/alice"},
        "sourceIPAddress": "198.51.100.7",
    }
    stubber.add_response(
        "lookup_events",
        {
            "Events": [
                {
                    "EventName": "PutBucketPolicy",
                    "EventSource": "s3.amazonaws.com",
                    "Username": "alice",
                    "EventTime": datetime(2026, 10, 1, tzinfo=UTC),
                    "CloudTrailEvent": json.dumps(detail),
                    "Resources": [
                        {"ResourceType": "AWS::S3::Bucket", "ResourceName": "acme-public"}
                    ],
                }
            ]
        },
    )
    result = call_tool(
        context,
        "cloudtrail_lookup_events",
        {"attribute_key": "ResourceName", "attribute_value": "acme-public", "days": 30},
    )
    [event] = result.data["events"]
    assert event["event_name"] == "PutBucketPolicy" and event["source_ip"] == "198.51.100.7"
    assert {"alice", "acme-public"} <= set(result.names)
    stubber.assert_no_pending_responses()


def test_lookup_days_range(context: ToolContext) -> None:
    with pytest.raises(ToolInputError, match="1~90"):
        call_tool(
            context,
            "cloudtrail_lookup_events",
            {"attribute_key": "Username", "attribute_value": "root", "days": 365},
        )


# --- EC2 ---


def _network() -> dict[str, str]:
    ec2 = _admin("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    table = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=table, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=table, SubnetId=subnet)
    group = ec2.create_security_group(GroupName="bastion", Description="ssh bastion", VpcId=vpc)[
        "GroupId"
    ]
    ec2.authorize_security_group_ingress(
        GroupId=group, IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0"
    )
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    instance = ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet,
        SecurityGroupIds=[group],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "jump-host"}]}
        ],
    )
    return {
        "vpc": vpc,
        "subnet": subnet,
        "group": group,
        "instance": instance["Instances"][0]["InstanceId"],
    }


def test_ec2_tools(context: ToolContext) -> None:
    net = _network()
    group = call_tool(context, "ec2_security_group", {"group_id": net["group"]})
    assert group.data["ingress"][0]["cidrs"] == ["0.0.0.0/0"] and "bastion" in group.names
    enis = call_tool(context, "ec2_interfaces_for_security_group", {"group_id": net["group"]})
    assert (
        enis.data["items"][0]["instance_id"] == net["instance"] and enis.data["truncated"] is False
    )
    instance = call_tool(
        context, "ec2_instance", {"instance_id": net["instance"], "region": REGION}
    )
    assert instance.data["subnet_id"] == net["subnet"] and instance.names == ("jump-host",)
    routes = call_tool(context, "ec2_subnet_routes", {"subnet_id": net["subnet"]})
    assert (
        routes.data["public_via_internet_gateway"] is True and routes.data["explicit_association"]
    )


def test_subnet_without_association_uses_main_table(context: ToolContext) -> None:
    ec2 = _admin("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.1.1.0/24")["Subnet"]["SubnetId"]
    routes = call_tool(context, "ec2_subnet_routes", {"subnet_id": subnet})
    assert routes.data["explicit_association"] is False
    assert routes.data["public_via_internet_gateway"] is False


# --- IAM ---


def test_iam_user_access_and_policies(context: ToolContext) -> None:
    iam = _admin("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Passw0rd!Passw0rd")
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "BreakGlass", "Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    # moto는 AWS 관리형 정책을 싣지 않으므로 같은 내용의 고객 관리형 정책을 쓴다
    admin_arn = iam.create_policy(PolicyName="admin-all", PolicyDocument=json.dumps(doc))["Policy"][
        "Arn"
    ]
    iam.create_group(GroupName="platform-admins")
    iam.attach_group_policy(GroupName="platform-admins", PolicyArn=admin_arn)
    iam.add_user_to_group(GroupName="platform-admins", UserName="alice")
    iam.put_user_policy(UserName="alice", PolicyName="break-glass", PolicyDocument=json.dumps(doc))
    iam.create_access_key(UserName="alice")
    access = call_tool(context, "iam_user_access", {"user_name": "alice"})
    assert access.data["console_password"] is True and access.data["mfa_devices"] == 0
    assert access.data["groups"]["platform-admins"] == [admin_arn]
    assert (
        access.data["inline_policies"] == ["break-glass"] and len(access.data["access_keys"]) == 1
    )
    assert {"alice", "platform-admins", "break-glass"} <= set(access.names)
    inline = call_tool(
        context,
        "iam_inline_policy",
        {"principal_type": "user", "principal_name": "alice", "policy_name": "break-glass"},
    )
    assert (
        inline.data["document"]["Statement"][0]["Sid"] == "BreakGlass"
        and "BreakGlass" in inline.names
    )
    arn = iam.create_policy(PolicyName="power-ops", PolicyDocument=json.dumps(doc))["Policy"]["Arn"]
    managed = call_tool(context, "iam_policy_document", {"policy_arn": arn})
    assert (
        managed.data["document"]["Statement"][0]["Action"] == "*" and "power-ops" in managed.names
    )


def test_iam_simulate(context: ToolContext) -> None:
    stubber = _stub(context, "iam")
    stubber.add_response(
        "simulate_principal_policy",
        {
            "EvaluationResults": [
                {
                    "EvalActionName": "iam:CreateUser",
                    "EvalResourceName": "*",
                    "EvalDecision": "allowed",
                    "MatchedStatements": [{"SourcePolicyId": "break-glass"}],
                }
            ]
        },
    )
    result = call_tool(
        context,
        "iam_simulate_principal_policy",
        {"principal_arn": f"arn:aws:iam::{ACCOUNT}:user/alice", "actions": ["iam:CreateUser"]},
    )
    assert result.data["results"][0]["decision"] == "allowed" and result.names == ("break-glass",)
    with pytest.raises(ToolInputError, match="1~10"):
        call_tool(
            context,
            "iam_simulate_principal_policy",
            {"principal_arn": "arn", "actions": [f"s3:A{n}" for n in range(11)]},
        )
