"""S3 collector (S3-001~006).

수집 데이터 (`Snapshot.data`). 키가 있고 값이 None이면 "설정 없음", 키가 없으면 "수집 실패"다.
- `account_public_access_block`: 계정 수준 퍼블릭 액세스 차단 설정 (`s3control`)
- `buckets`: `ListBuckets` 항목에 `Region`(버킷 리전, 조회 실패 시 None)을 더한 목록
- `bucket_details.<버킷 이름>.<항목>`: 버킷별 설정. 항목은 `BUCKET_DETAILS`.
  `logging`은 로깅이 꺼져 있으면 None이다 (AWS가 빈 응답을 준다).

버킷은 `--regions`와 관계없이 모두 수집한다 (ADR-021). 버킷 단위 호출은 버킷 리전의 client로
하고, 리전 조회에 실패하면 기본 리전 client로 시도한다 (botocore가 리전 리다이렉트를 처리).
S3 Express 디렉터리 버킷은 `ListBuckets`에 나오지 않으므로 수집하지 않는다.
"""

from datetime import UTC, datetime
from typing import Any

from kompass.aws.session import ScanContext
from kompass.collectors.base import Absent, CallRecorder
from kompass.models import Snapshot

_NO_PUBLIC_ACCESS_BLOCK = "NoSuchPublicAccessBlockConfiguration"


# 데이터 키 → (메서드, 응답에서 꺼낼 키, "설정 없음" 오류 코드)
# 응답 키가 None이면 응답 전체를 쓴다.
BUCKET_DETAILS: dict[str, tuple[str, str | None, frozenset[str]]] = {
    "public_access_block": (
        "get_public_access_block",
        "PublicAccessBlockConfiguration",
        frozenset({_NO_PUBLIC_ACCESS_BLOCK}),
    ),
    "policy_status": (
        "get_bucket_policy_status",
        "PolicyStatus",
        frozenset({"NoSuchBucketPolicy"}),
    ),
    "encryption": (
        "get_bucket_encryption",
        "ServerSideEncryptionConfiguration",
        frozenset({"ServerSideEncryptionConfigurationNotFoundError"}),
    ),
    "logging": ("get_bucket_logging", "LoggingEnabled", frozenset()),
    "ownership_controls": (
        "get_bucket_ownership_controls",
        "OwnershipControls",
        frozenset({"OwnershipControlsNotFoundError"}),
    ),
    "acl": ("get_bucket_acl", None, frozenset()),
}


def bucket_region(location_constraint: str | None) -> str:
    """`GetBucketLocation`의 `LocationConstraint`를 리전 이름으로 바꾼다."""
    if not location_constraint:
        return "us-east-1"
    if location_constraint == "EU":
        return "eu-west-1"
    return location_constraint


class S3Collector:
    service = "s3"

    def collect(self, scan: ScanContext) -> Snapshot:
        collected_at = datetime.now(UTC)
        recorder = CallRecorder()
        clients: dict[str, Any] = {}

        def client(region: str) -> Any:
            if region not in clients:
                clients[region] = scan.session.client("s3", region_name=region)
            return clients[region]

        data: dict[str, Any] = {}
        control = scan.session.client("s3control", region_name=scan.home_region)
        account_block = recorder.call(
            control,
            "get_public_access_block",
            absent_codes={_NO_PUBLIC_ACCESS_BLOCK},
            AccountId=scan.account_id,
        )
        if isinstance(account_block, Absent):
            data["account_public_access_block"] = None
        elif account_block is not None:
            data["account_public_access_block"] = account_block["PublicAccessBlockConfiguration"]

        listed = recorder.paginate(client(scan.home_region), "list_buckets", "Buckets")
        if listed is not None:
            buckets: list[dict[str, Any]] = []
            details: dict[str, dict[str, Any]] = {}
            for bucket in listed:
                name: str = bucket["Name"]
                region = self._region(recorder, client(scan.home_region), name)
                buckets.append({**bucket, "Region": region})
                details[name] = self._details(recorder, client(region or scan.home_region), name)
            data["buckets"] = buckets
            data["bucket_details"] = details

        return Snapshot(
            service=self.service,
            account_id=scan.account_id,
            regions=tuple(sorted(clients)),
            collected_at=collected_at,
            data=data,
            errors=tuple(recorder.errors),
        )

    @staticmethod
    def _region(recorder: CallRecorder, client: Any, name: str) -> str | None:
        location = recorder.call(client, "get_bucket_location", resource=name, Bucket=name)
        if not isinstance(location, dict):
            return None
        return bucket_region(location.get("LocationConstraint"))

    @staticmethod
    def _details(recorder: CallRecorder, client: Any, name: str) -> dict[str, Any]:
        details: dict[str, Any] = {}
        for key, (method, response_key, absent_codes) in BUCKET_DETAILS.items():
            result = recorder.call(
                client, method, resource=name, absent_codes=absent_codes, Bucket=name
            )
            if isinstance(result, Absent):
                details[key] = None
            elif result is not None:
                details[key] = result if response_key is None else result.get(response_key)
        return details
