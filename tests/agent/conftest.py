"""에이전트 테스트 공용: moto 위의 읽기 전용 점검 세션."""

from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from moto import mock_aws

from kompass.agent.tools import ToolContext
from kompass.aws.guard import read_only_session
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


def admin(service: str, region: str = REGION) -> Any:
    """테스트 리소스를 만드는 가드 없는 클라이언트 (도구는 가드가 걸린 세션만 쓴다)."""
    return boto3.client(service, region_name=region)
