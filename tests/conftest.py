"""모든 테스트에 자동 적용되는 AWS 환경 격리.

개발자 PC의 실제 `~/.aws` 프로필과 `AWS_*` 환경 변수가 테스트에 보이지 않게 한다.
moto가 꺼진 상태로 요청이 나가는 실수가 있어도 가짜 키라서 AWS가 거부한다.
"""

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass(frozen=True)
class AwsFiles:
    """테스트용 AWS 설정 파일. 내용은 각 테스트가 쓴다."""

    config: Path
    credentials: Path


@pytest.fixture(autouse=True)
def isolated_aws_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[AwsFiles]:
    for name in list(os.environ):
        if name.startswith("AWS_"):
            monkeypatch.delenv(name)
    files = AwsFiles(config=tmp_path / "aws_config", credentials=tmp_path / "aws_credentials")
    files.config.write_text("", encoding="utf-8")
    files.credentials.write_text("", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(files.config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(files.credentials))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    yield files
