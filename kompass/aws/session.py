"""점검 세션 생성 (ADR-021).

`open_scan()`이 가드가 걸린 세션을 만들고, 점검 대상 계정 ID·파티션·리전을 확정한다.
모든 collector는 같은 `ScanContext`를 받으므로 스냅샷 간 계정·리전이 어긋나지 않는다.

- 자격증명: AWS 프로필(액세스 키, 또는 `role_arn` + `source_profile` 역할 프로필).
  역할 자격증명 발급·갱신은 botocore가 하며 `sts:AssumeRole`은 가드가 허용한다 (ADR-020).
  SSO 프로필은 토큰 갱신(`sso-oidc:CreateToken`)이 가드에 막힐 수 있어 1단계에서 지원하지 않는다.
- 세션 단계의 실패(자격증명 없음, 리전 없음, 잘못된 리전 지정)는 finding이 아니라
  `SessionError`로 실행을 중단한다. 계정 ID조차 모르는 상태라 스냅샷을 만들 수 없기 때문이다.
  개별 API의 권한 오류를 ERROR finding으로 기록하는 것(ADR-005)은 collector의 몫이다.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from kompass.aws.guard import read_only_session

_ENABLED_OPT_IN_STATUSES = frozenset({"opt-in-not-required", "opted-in"})


class SessionError(Exception):
    """점검을 시작할 수 없는 세션 단계 실패."""


@dataclass(frozen=True)
class ScanContext:
    """한 번의 점검 실행이 공유하는 세션과 대상 정보."""

    session: Any  # read_only_session()으로 만든 boto3 세션
    account_id: str
    partition: str  # "aws", "aws-cn", "aws-us-gov"
    caller_arn: str  # 점검 수행 주체 (보고서 증적)
    home_region: str  # 리전 조회 등 기본 호출에 쓰는 리전
    regions: tuple[str, ...]  # 리전 리소스(EC2·VPC 등)를 점검할 리전


def enabled_regions(describe_regions_response: dict[str, Any]) -> tuple[set[str], set[str]]:
    """`DescribeRegions(AllRegions=True)` 응답을 (알려진 리전, 활성 리전)으로 나눈다."""
    regions = describe_regions_response["Regions"]
    known = {r["RegionName"] for r in regions}
    enabled = {r["RegionName"] for r in regions if r.get("OptInStatus") in _ENABLED_OPT_IN_STATUSES}
    return known, enabled


def select_regions(
    known: Iterable[str], enabled: Iterable[str], requested: Sequence[str] | None
) -> tuple[str, ...]:
    """점검할 리전을 정한다.

    요청이 없으면 활성 리전 전체(정렬). 요청이 있으면 요청 순서대로 중복을 빼고, 알 수 없는
    리전이나 활성화되지 않은 리전이 섞여 있으면 점검 전에 중단한다. 그대로 진행하면 결과 전체가
    ERROR로 채워진 뒤에야 오타가 드러나기 때문이다.
    """
    known_set, enabled_set = set(known), set(enabled)
    if requested is None:
        return tuple(sorted(enabled_set))
    if not requested:
        raise SessionError("점검할 리전을 하나 이상 지정해야 한다")
    unique = tuple(dict.fromkeys(requested))
    unknown = [r for r in unique if r not in known_set]
    if unknown:
        raise SessionError(f"알 수 없는 리전: {', '.join(unknown)}")
    not_enabled = [r for r in unique if r not in enabled_set]
    if not_enabled:
        raise SessionError(f"이 계정에서 활성화되지 않은 리전: {', '.join(not_enabled)}")
    return unique


def open_scan(
    profile: str | None = None,
    region: str | None = None,
    regions: Sequence[str] | None = None,
) -> ScanContext:
    """가드가 걸린 세션을 만들고 점검 대상 계정과 리전을 확정한다.

    `region`은 기본 호출 리전이다. 지정하지 않으면 프로필의 리전을 쓰고, 둘 다 없으면 중단한다.
    다른 파티션에서 틀릴 수 있으므로 us-east-1 같은 값으로 몰래 대체하지 않는다.
    `regions`는 리전 리소스를 점검할 범위다. 지정하지 않으면 활성 리전 전체.
    """
    try:
        session = read_only_session(profile_name=profile, region_name=region)
    except ProfileNotFound as exc:
        raise SessionError(f"AWS 프로필을 찾을 수 없다: {profile}") from exc

    home_region = session.region_name
    if not home_region:
        raise SessionError(
            "기본 리전을 정할 수 없다. --region을 지정하거나 프로필에 region을 설정해야 한다"
        )

    try:
        identity = session.client("sts", region_name=home_region).get_caller_identity()
    except NoCredentialsError as exc:
        raise SessionError(f"AWS 자격증명을 찾을 수 없다 (프로필: {profile})") from exc
    except (ClientError, BotoCoreError) as exc:
        raise SessionError(f"자격증명 확인(sts:GetCallerIdentity) 실패: {exc}") from exc

    try:
        response = session.client("ec2", region_name=home_region).describe_regions(AllRegions=True)
    except (ClientError, BotoCoreError) as exc:
        raise SessionError(f"리전 목록 조회(ec2:DescribeRegions) 실패: {exc}") from exc

    known, enabled = enabled_regions(response)
    caller_arn: str = identity["Arn"]
    return ScanContext(
        session=session,
        account_id=identity["Account"],
        partition=caller_arn.split(":")[1],
        caller_arn=caller_arn,
        home_region=home_region,
        regions=select_regions(known, enabled, regions),
    )
