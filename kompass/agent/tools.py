"""에이전트 조사 도구: 목적별 읽기 전용 AWS 조회 (ADR-035, ADR-036).

모든 호출은 점검 세션(`ScanContext.session`, 읽기 전용 가드)으로만 한다. 도구는 필요한 필드만
골라 돌려주고, 결과에 새로 나온 이름(버킷·사용자·그룹·정책·설명 등)을 `names`로 따로 알린다.
마스킹 다리는 이 이름을 치환표에 더한 뒤 결과를 가려서 LLM에 보낸다 (원칙 5).

- 입력이 잘못되면 `ToolInputError` (LLM에 알려 고치게 한다)
- AWS 오류(권한 없음, 없는 리소스 등)는 결과의 `error`로 돌려준다 (예외 아님)
- 읽기 전용 가드 위반(`ReadOnlyViolation`)은 도구의 버그이므로 그대로 올린다
"""

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from kompass.aws.session import ScanContext

MAX_ITEMS = 50  # 목록 결과의 상한. 넘으면 앞의 것만 돌려주고 truncated를 표시한다
MAX_EVENTS = 50
MAX_SIMULATED_ACTIONS = 10


class ToolInputError(ValueError):
    """도구 입력이 잘못되었다."""


@dataclass(frozen=True)
class ToolResult:
    data: dict[str, Any]  # 원본 값 (마스킹 전)
    names: tuple[str, ...] = ()  # 결과에 새로 나온 이름 (마스킹 다리가 치환표에 더한다)


@dataclass
class ToolContext:
    scan: ScanContext
    _clients: dict[tuple[str, str], Any] = field(default_factory=dict)

    def client(self, service: str, region: str | None = None) -> Any:
        region = region or self.scan.home_region
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.scan.session.client(service, region_name=region)
        return self._clients[key]

    def region(self, value: Any) -> str:
        """점검 범위 안의 리전만 허용한다."""
        if value is None:
            return self.scan.home_region
        if not isinstance(value, str) or value not in {*self.scan.regions, self.scan.home_region}:
            raise ToolInputError(f"점검 범위 밖의 리전: {value}")
        return value


@dataclass(frozen=True)
class Tool:
    name: str
    description: str  # LLM에 보여 주는 설명
    input_schema: dict[str, Any]
    run: Callable[[ToolContext, dict[str, Any]], ToolResult]


def call_tool(context: ToolContext, name: str, arguments: dict[str, Any]) -> ToolResult:
    tool = TOOLS_BY_NAME.get(name)
    if tool is None:
        raise ToolInputError(f"없는 도구: {name}")
    _check_input(tool.input_schema, arguments)
    try:
        return tool.run(context, arguments)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return ToolResult(
            {"error": error.get("Code", "ClientError"), "message": error.get("Message", "")}
        )
    except BotoCoreError as exc:
        return ToolResult({"error": type(exc).__name__, "message": str(exc)})


def _check_input(schema: dict[str, Any], arguments: dict[str, Any]) -> None:
    """필수 키, 알 수 없는 키, 기본 타입만 확인한다 (JSON 스키마 라이브러리 없이)."""
    properties: dict[str, Any] = schema.get("properties", {})
    missing = [key for key in schema.get("required", []) if key not in arguments]
    unknown = [key for key in arguments if key not in properties]
    if missing or unknown:
        raise ToolInputError(f"입력 오류: 빠진 값 {missing}, 알 수 없는 값 {unknown}")
    types = {"string": str, "integer": int, "array": list, "boolean": bool}
    for key, value in arguments.items():
        expected = types.get(properties[key].get("type", ""))
        if expected and not isinstance(value, expected):
            raise ToolInputError(f"입력 오류: {key}는 {properties[key]['type']}이어야 함")
        allowed = properties[key].get("enum")
        if allowed and value not in allowed:
            raise ToolInputError(f"입력 오류: {key}는 {allowed} 중 하나여야 함")


def _missing(exc: ClientError, *codes: str) -> bool:
    return exc.response.get("Error", {}).get("Code") in codes


def _limit(items: list[Any]) -> dict[str, Any]:
    return {"items": items[:MAX_ITEMS], "truncated": len(items) > MAX_ITEMS}


def _sids(document: Any) -> list[str]:
    statements = document.get("Statement", []) if isinstance(document, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    return [s["Sid"] for s in statements if isinstance(s, dict) and isinstance(s.get("Sid"), str)]


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required}


_REGION = {"type": "string", "description": "리전. 없으면 기본 리전"}


# --- S3 ---


def _bucket_region(context: ToolContext, bucket: str) -> str:
    location = context.client("s3").get_bucket_location(Bucket=bucket).get("LocationConstraint")
    return location or "us-east-1"


def _s3_bucket_access(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    bucket = args["bucket"]
    s3 = context.client("s3", _bucket_region(context, bucket))
    data: dict[str, Any] = {"bucket": bucket}
    names = [bucket]
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        data["policy"] = policy
        names += _sids(policy)
    except ClientError as exc:
        if not _missing(exc, "NoSuchBucketPolicy"):
            raise
        data["policy"] = None
    try:
        data["policy_is_public"] = s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"][
            "IsPublic"
        ]
    except ClientError as exc:
        if not _missing(exc, "NoSuchBucketPolicy"):
            raise
        data["policy_is_public"] = None
    try:
        data["public_access_block"] = s3.get_public_access_block(Bucket=bucket)[
            "PublicAccessBlockConfiguration"
        ]
    except ClientError as exc:
        if not _missing(exc, "NoSuchPublicAccessBlockConfiguration"):
            raise
        data["public_access_block"] = None
    try:
        rules = s3.get_bucket_ownership_controls(Bucket=bucket)["OwnershipControls"]["Rules"]
        data["object_ownership"] = rules[0]["ObjectOwnership"] if rules else None
    except ClientError as exc:
        if not _missing(exc, "OwnershipControlsNotFoundError"):
            raise
        data["object_ownership"] = None
    acl = s3.get_bucket_acl(Bucket=bucket)
    grants = []
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        grants.append(
            {
                "type": grantee.get("Type"),
                "uri": grantee.get("URI"),
                "id": grantee.get("ID"),
                "display_name": grantee.get("DisplayName"),
                "permission": grant.get("Permission"),
            }
        )
        names += [v for v in (grantee.get("ID"), grantee.get("DisplayName")) if v]
    data["acl_grants"] = grants
    return ToolResult(data, tuple(names))


def _s3_account_public_access_block(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    s3control = context.client("s3control")
    try:
        config = s3control.get_public_access_block(AccountId=context.scan.account_id)
        return ToolResult({"public_access_block": config["PublicAccessBlockConfiguration"]})
    except ClientError as exc:
        if not _missing(exc, "NoSuchPublicAccessBlockConfiguration"):
            raise
        return ToolResult({"public_access_block": None})


# --- CloudTrail ---


def _cloudtrail_data_events(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    """버킷의 S3 데이터 이벤트를 기록하는 추적이 있는가."""
    bucket = args["bucket"]
    prefix = f"arn:aws:s3:::{bucket}/"
    cloudtrail = context.client("cloudtrail")
    trails = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]
    result, names = [], []
    for trail in trails[:MAX_ITEMS]:
        region = trail.get("HomeRegion") or context.scan.home_region
        selectors = context.client("cloudtrail", region).get_event_selectors(
            TrailName=trail["TrailARN"]
        )
        logged = False
        for selector in selectors.get("EventSelectors") or []:
            for resource in selector.get("DataResources", []):
                values = resource.get("Values", [])
                if resource.get("Type") == "AWS::S3::Object" and any(
                    v in ("arn:aws:s3", "arn:aws:s3:::") or prefix.startswith(v) for v in values
                ):
                    logged = True
        for selector in selectors.get("AdvancedEventSelectors") or []:
            fields = {f["Field"]: f for f in selector.get("FieldSelectors", [])}
            if fields.get("eventCategory", {}).get("Equals") == [
                "Data"
            ] and "AWS::S3::Object" in fields.get("resources.type", {}).get("Equals", []):
                arns = fields.get("resources.ARN", {})
                if not arns or any(prefix.startswith(v) for v in arns.get("StartsWith", [])):
                    logged = True
        result.append(
            {
                "trail": trail["TrailARN"],
                "multi_region": trail.get("IsMultiRegionTrail"),
                "logs_bucket_data_events": logged,
            }
        )
        names.append(trail["Name"])
    return ToolResult({"bucket": bucket, "trails": result}, tuple([bucket, *names]))


_LOOKUP_KEYS = ["EventName", "Username", "ResourceName", "EventSource"]


def _cloudtrail_lookup_events(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    """관리 이벤트 이력 (최근 90일 이내). 글로벌 서비스(IAM 등) 이벤트는 us-east-1에 기록된다."""
    region = context.region(args.get("region"))
    days = args.get("days", 90)
    if not 1 <= days <= 90:
        raise ToolInputError("입력 오류: days는 1~90이어야 함")
    end = datetime.now(UTC)
    response = context.client("cloudtrail", region).lookup_events(
        LookupAttributes=[
            {"AttributeKey": args["attribute_key"], "AttributeValue": args["attribute_value"]}
        ],
        StartTime=end - timedelta(days=days),
        EndTime=end,
        MaxResults=MAX_EVENTS,
    )
    events, names = [], [args["attribute_value"]]
    for event in response.get("Events", []):
        detail = json.loads(event.get("CloudTrailEvent") or "{}")
        events.append(
            {
                "time": event["EventTime"].isoformat()
                if hasattr(event.get("EventTime"), "isoformat")
                else event.get("EventTime"),
                "event_name": event.get("EventName"),
                "event_source": event.get("EventSource"),
                "username": event.get("Username"),
                "user_arn": detail.get("userIdentity", {}).get("arn"),
                "source_ip": detail.get("sourceIPAddress"),
                "error_code": detail.get("errorCode"),
                "resources": [
                    {"type": r.get("ResourceType"), "name": r.get("ResourceName")}
                    for r in event.get("Resources", [])
                ],
            }
        )
        names += [v for v in (event.get("Username"),) if v]
        names += [r["ResourceName"] for r in event.get("Resources", []) if r.get("ResourceName")]
    return ToolResult(
        {"region": region, "events": events, "more": "NextToken" in response}, tuple(names)
    )


# --- EC2 ---


def _rules(permissions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "protocol": p.get("IpProtocol"),
            "from_port": p.get("FromPort"),
            "to_port": p.get("ToPort"),
            "cidrs": [r["CidrIp"] for r in p.get("IpRanges", [])]
            + [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])],
            "groups": [g["GroupId"] for g in p.get("UserIdGroupPairs", [])],
            "prefix_lists": [g["PrefixListId"] for g in p.get("PrefixListIds", [])],
        }
        for p in permissions
    ]


def _ec2_security_group(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    region = context.region(args.get("region"))
    [group] = context.client("ec2", region).describe_security_groups(GroupIds=[args["group_id"]])[
        "SecurityGroups"
    ]
    data = {
        "group_id": group["GroupId"],
        "name": group.get("GroupName"),
        "description": group.get("Description"),
        "vpc_id": group.get("VpcId"),
        "ingress": _rules(group.get("IpPermissions", [])),
        "egress": _rules(group.get("IpPermissionsEgress", [])),
    }
    return ToolResult(
        data, tuple(v for v in (group.get("GroupName"), group.get("Description")) if v)
    )


def _ec2_interfaces_for_security_group(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    region = context.region(args.get("region"))
    interfaces = context.client("ec2", region).describe_network_interfaces(
        Filters=[{"Name": "group-id", "Values": [args["group_id"]]}]
    )["NetworkInterfaces"]
    items, names = [], []
    for eni in interfaces:
        items.append(
            {
                "interface_id": eni["NetworkInterfaceId"],
                "status": eni.get("Status"),
                "interface_type": eni.get("InterfaceType"),
                "public_ip": eni.get("Association", {}).get("PublicIp"),
                "instance_id": eni.get("Attachment", {}).get("InstanceId"),
                "subnet_id": eni.get("SubnetId"),
                "vpc_id": eni.get("VpcId"),
                "requester_managed": eni.get("RequesterManaged"),
                "description": eni.get("Description") or None,
            }
        )
        if eni.get("Description"):
            names.append(eni["Description"])
    return ToolResult({"group_id": args["group_id"], **_limit(items)}, tuple(names))


def _ec2_instance(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    region = context.region(args.get("region"))
    reservations = context.client("ec2", region).describe_instances(
        InstanceIds=[args["instance_id"]]
    )["Reservations"]
    [instance] = [i for r in reservations for i in r["Instances"]]
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    data = {
        "instance_id": instance["InstanceId"],
        "state": instance.get("State", {}).get("Name"),
        "instance_type": instance.get("InstanceType"),
        "public_ip": instance.get("PublicIpAddress"),
        "subnet_id": instance.get("SubnetId"),
        "vpc_id": instance.get("VpcId"),
        "security_groups": [g["GroupId"] for g in instance.get("SecurityGroups", [])],
        "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn"),
        "launch_time": instance["LaunchTime"].isoformat() if "LaunchTime" in instance else None,
        "name_tag": tags.get("Name"),
    }
    return ToolResult(data, tuple(v for v in (tags.get("Name"),) if v))


def _ec2_subnet_routes(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    """서브넷에 적용되는 라우팅 테이블. 명시적 연결이 없으면 VPC의 기본 라우팅 테이블."""
    region = context.region(args.get("region"))
    ec2 = context.client("ec2", region)
    subnet_id = args["subnet_id"]
    tables = ec2.describe_route_tables(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )["RouteTables"]
    explicit = bool(tables)
    if not tables:
        [subnet] = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"]
        tables = ec2.describe_route_tables(
            Filters=[
                {"Name": "vpc-id", "Values": [subnet["VpcId"]]},
                {"Name": "association.main", "Values": ["true"]},
            ]
        )["RouteTables"]
    routes = []
    for table in tables[:1]:
        for route in table.get("Routes", []):
            routes.append(
                {
                    "destination": route.get("DestinationCidrBlock")
                    or route.get("DestinationIpv6CidrBlock")
                    or route.get("DestinationPrefixListId"),
                    "target": route.get("GatewayId")
                    or route.get("NatGatewayId")
                    or route.get("TransitGatewayId")
                    or route.get("NetworkInterfaceId")
                    or route.get("VpcPeeringConnectionId"),
                    "state": route.get("State"),
                }
            )
    public = any(str(r["target"]).startswith("igw-") for r in routes)
    data = {
        "subnet_id": subnet_id,
        "route_table_id": tables[0]["RouteTableId"] if tables else None,
        "explicit_association": explicit,
        "routes": routes,
        "public_via_internet_gateway": public,
    }
    return ToolResult(data)


# --- IAM ---


def _iam_user_access(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    iam = context.client("iam")
    name = args["user_name"]
    user = iam.get_user(UserName=name)["User"]
    groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName=name)["Groups"]]
    group_policies = {
        group: [
            p["PolicyArn"]
            for p in iam.list_attached_group_policies(GroupName=group)["AttachedPolicies"]
        ]
        + [f"inline:{p}" for p in iam.list_group_policies(GroupName=group)["PolicyNames"]]
        for group in groups[:MAX_ITEMS]
    }
    inline = iam.list_user_policies(UserName=name)["PolicyNames"]
    keys = []
    for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
        last = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"]).get(
            "AccessKeyLastUsed", {}
        )
        keys.append(
            {
                "access_key_id": key["AccessKeyId"],
                "status": key.get("Status"),
                "created": key["CreateDate"].isoformat() if "CreateDate" in key else None,
                "last_used": last["LastUsedDate"].isoformat() if "LastUsedDate" in last else None,
                "last_used_service": last.get("ServiceName"),
            }
        )
    try:
        iam.get_login_profile(UserName=name)
        console = True
    except ClientError as exc:
        if not _missing(exc, "NoSuchEntity"):
            raise
        console = False
    data = {
        "user_arn": user["Arn"],
        "created": user["CreateDate"].isoformat() if "CreateDate" in user else None,
        "password_last_used": user["PasswordLastUsed"].isoformat()
        if "PasswordLastUsed" in user
        else None,
        "console_password": console,
        "permissions_boundary": user.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn"),
        "attached_policies": [
            p["PolicyArn"]
            for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        ],
        "inline_policies": inline,
        "groups": group_policies,
        "mfa_devices": len(iam.list_mfa_devices(UserName=name)["MFADevices"]),
        "access_keys": keys,
    }
    return ToolResult(data, tuple([name, *groups, *inline]))


def _iam_policy_document(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    iam = context.client("iam")
    arn = args["policy_arn"]
    policy = iam.get_policy(PolicyArn=arn)["Policy"]
    version = iam.get_policy_version(PolicyArn=arn, VersionId=policy["DefaultVersionId"])[
        "PolicyVersion"
    ]
    document = version["Document"]
    if isinstance(document, str):
        document = json.loads(document)
    data = {
        "policy_arn": arn,
        "attachment_count": policy.get("AttachmentCount"),
        "document": document,
    }
    return ToolResult(data, tuple([policy.get("PolicyName", ""), *_sids(document)]))


_INLINE = {
    "user": ("get_user_policy", "UserName"),
    "group": ("get_group_policy", "GroupName"),
    "role": ("get_role_policy", "RoleName"),
}


def _iam_inline_policy(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    method, key = _INLINE[args["principal_type"]]
    response = getattr(context.client("iam"), method)(
        **{key: args["principal_name"], "PolicyName": args["policy_name"]}
    )
    document = response["PolicyDocument"]
    if isinstance(document, str):
        document = json.loads(document)
    data = {
        "principal_type": args["principal_type"],
        "principal_name": args["principal_name"],
        "policy_name": args["policy_name"],
        "document": document,
    }
    return ToolResult(data, (args["principal_name"], args["policy_name"], *_sids(document)))


def _iam_simulate(context: ToolContext, args: dict[str, Any]) -> ToolResult:
    """주체의 정책을 실제로 평가해 작업별 허용 여부를 본다 (SimulatePrincipalPolicy, ADR-036)."""
    actions = args["actions"]
    if not 1 <= len(actions) <= MAX_SIMULATED_ACTIONS or not all(
        isinstance(a, str) for a in actions
    ):
        raise ToolInputError(f"입력 오류: actions는 문자열 1~{MAX_SIMULATED_ACTIONS}개여야 함")
    response = context.client("iam").simulate_principal_policy(
        PolicySourceArn=args["principal_arn"],
        ActionNames=actions,
        ResourceArns=args.get("resources") or ["*"],
    )
    results = [
        {
            "action": r["EvalActionName"],
            "resource": r.get("EvalResourceName"),
            "decision": r["EvalDecision"],
            "matched_policies": [s.get("SourcePolicyId") for s in r.get("MatchedStatements", [])],
        }
        for r in response.get("EvaluationResults", [])
    ]
    names = [
        s.get("SourcePolicyId")
        for r in response.get("EvaluationResults", [])
        for s in r.get("MatchedStatements", [])
        if s.get("SourcePolicyId")
    ]
    return ToolResult({"principal_arn": args["principal_arn"], "results": results}, tuple(names))


TOOLS: tuple[Tool, ...] = (
    Tool(
        "s3_bucket_access",
        "버킷의 정책 전문, 정책 퍼블릭 여부, 버킷 퍼블릭 액세스 차단, 객체 소유권, "
        "ACL 부여 내역을 조회한다.",
        _schema({"bucket": {"type": "string"}}, ["bucket"]),
        _s3_bucket_access,
    ),
    Tool(
        "s3_account_public_access_block",
        "계정 수준 S3 퍼블릭 액세스 차단 설정을 조회한다.",
        _schema({}, []),
        _s3_account_public_access_block,
    ),
    Tool(
        "cloudtrail_data_events",
        "버킷의 S3 데이터 이벤트(객체 읽기·쓰기)를 기록하는 CloudTrail 추적이 있는지 조회한다.",
        _schema({"bucket": {"type": "string"}}, ["bucket"]),
        _cloudtrail_data_events,
    ),
    Tool(
        "cloudtrail_lookup_events",
        "최근 관리 이벤트 이력을 조회한다 (최대 90일, 50건). 누가 언제 설정을 바꿨는지, "
        "루트 사용 여부 확인에 쓴다. IAM 등 글로벌 서비스 이벤트는 us-east-1에 기록된다.",
        _schema(
            {
                "attribute_key": {"type": "string", "enum": _LOOKUP_KEYS},
                "attribute_value": {"type": "string"},
                "days": {"type": "integer", "description": "1~90, 기본 90"},
                "region": _REGION,
            },
            ["attribute_key", "attribute_value"],
        ),
        _cloudtrail_lookup_events,
    ),
    Tool(
        "ec2_security_group",
        "보안그룹의 이름·설명·VPC와 인바운드·아웃바운드 규칙을 조회한다.",
        _schema({"group_id": {"type": "string"}, "region": _REGION}, ["group_id"]),
        _ec2_security_group,
    ),
    Tool(
        "ec2_interfaces_for_security_group",
        "보안그룹이 연결된 네트워크 인터페이스와 그 공인 IP·인스턴스·서브넷을 조회한다.",
        _schema({"group_id": {"type": "string"}, "region": _REGION}, ["group_id"]),
        _ec2_interfaces_for_security_group,
    ),
    Tool(
        "ec2_instance",
        "인스턴스의 상태·공인 IP·서브넷·보안그룹·IAM 인스턴스 프로파일을 조회한다.",
        _schema({"instance_id": {"type": "string"}, "region": _REGION}, ["instance_id"]),
        _ec2_instance,
    ),
    Tool(
        "ec2_subnet_routes",
        "서브넷에 적용되는 라우팅 테이블과 인터넷 게이트웨이 경로 여부를 조회한다.",
        _schema({"subnet_id": {"type": "string"}, "region": _REGION}, ["subnet_id"]),
        _ec2_subnet_routes,
    ),
    Tool(
        "iam_user_access",
        "IAM 사용자의 연결 정책·인라인 정책·그룹(과 그룹 정책)·권한 경계·MFA·"
        "콘솔 비밀번호·액세스 키 사용 이력을 조회한다.",
        _schema({"user_name": {"type": "string"}}, ["user_name"]),
        _iam_user_access,
    ),
    Tool(
        "iam_policy_document",
        "관리형 정책의 기본 버전 문서를 조회한다.",
        _schema({"policy_arn": {"type": "string"}}, ["policy_arn"]),
        _iam_policy_document,
    ),
    Tool(
        "iam_inline_policy",
        "사용자·그룹·역할의 인라인 정책 문서를 조회한다.",
        _schema(
            {
                "principal_type": {"type": "string", "enum": list(_INLINE)},
                "principal_name": {"type": "string"},
                "policy_name": {"type": "string"},
            },
            ["principal_type", "principal_name", "policy_name"],
        ),
        _iam_inline_policy,
    ),
    Tool(
        "iam_simulate_principal_policy",
        "주체(사용자·역할 ARN)의 정책을 실제로 평가해 작업별 허용 여부를 확인한다 "
        "(작업 최대 10개).",
        _schema(
            {
                "principal_arn": {"type": "string"},
                "actions": {"type": "array", "items": {"type": "string"}},
                "resources": {"type": "array", "items": {"type": "string"}},
            },
            ["principal_arn", "actions"],
        ),
        _iam_simulate,
    ),
)
TOOLS_BY_NAME = {tool.name: tool for tool in TOOLS}
