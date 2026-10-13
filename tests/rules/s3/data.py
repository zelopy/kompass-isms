"""S3 룰 테스트용 가짜 데이터. 실습 계정에서 확인한 실제 응답 형태를 따른다.

값 None은 "설정 없음", 키 없음은 "수집 실패"다 (collector 규약).
"""

from datetime import UTC, datetime
from typing import Any

from kompass.models import CollectError, Snapshot

T0 = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
_UNSET = object()


def block(
    acls: bool = True, ignore: bool = True, policy: bool = True, restrict: bool = True
) -> dict[str, bool]:
    return {
        "BlockPublicAcls": acls,
        "IgnorePublicAcls": ignore,
        "BlockPublicPolicy": policy,
        "RestrictPublicBuckets": restrict,
    }


ALL_BLOCKED = block()
NONE_BLOCKED = block(False, False, False, False)


def acl(*public_uris: str) -> dict[str, Any]:
    grants: list[dict[str, Any]] = [
        {"Grantee": {"ID": "owner", "Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}
    ]
    grants += [
        {"Grantee": {"Type": "Group", "URI": uri}, "Permission": "READ"} for uri in public_uris
    ]
    return {"Owner": {"ID": "owner"}, "Grants": grants}


def ownership(value: str) -> dict[str, Any]:
    return {"Rules": [{"ObjectOwnership": value}]}


def encryption(algorithm: str = "AES256") -> dict[str, Any]:
    return {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algorithm}}]}


def details(
    *,
    public_access_block: Any = ALL_BLOCKED,
    policy_status: Any = None,
    encryption_config: Any = _UNSET,
    logging: Any = None,
    ownership_controls: Any = _UNSET,
    acl_config: Any = _UNSET,
    missing: tuple[str, ...] = (),
) -> dict[str, Any]:
    """버킷 상세. 기본값은 2023년 이후 새 버킷의 실제 기본 상태."""
    data: dict[str, Any] = {
        "public_access_block": public_access_block,
        "policy_status": policy_status,
        "encryption": encryption() if encryption_config is _UNSET else encryption_config,
        "logging": logging,
        "ownership_controls": (
            ownership("BucketOwnerEnforced") if ownership_controls is _UNSET else ownership_controls
        ),
        "acl": acl() if acl_config is _UNSET else acl_config,
    }
    for key in missing:
        del data[key]
    return data


def snapshot(
    buckets: dict[str, dict[str, Any]] | None,
    *,
    account_block: Any = None,
    account_missing: bool = False,
    region: str | None = REGION,
    errors: tuple[CollectError, ...] = (),
) -> Snapshot:
    data: dict[str, Any] = {}
    if not account_missing:
        data["account_public_access_block"] = account_block
    if buckets is not None:
        data["buckets"] = [
            {"Name": name, "CreationDate": "2026-10-13T00:00:00Z", "Region": region}
            for name in buckets
        ]
        data["bucket_details"] = buckets
    return Snapshot(
        service="s3",
        account_id=ACCOUNT,
        regions=(REGION,),
        collected_at=T0,
        data=data,
        errors=errors,
    )


def collect_error(operation: str, resource: str | None = None) -> CollectError:
    return CollectError(
        operation=operation,
        region=REGION,
        error_code="AccessDenied",
        message="denied",
        resource=resource,
    )
