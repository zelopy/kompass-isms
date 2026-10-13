"""테스트가 개발자 PC의 실제 AWS 설정에 닿지 않는지 확인한다 (tests/conftest.py)."""

import os

import boto3


def test_real_aws_profiles_are_hidden() -> None:
    assert boto3.Session().available_profiles == []


def test_only_fake_credentials_are_visible() -> None:
    credentials = boto3.Session().get_credentials()
    assert credentials is not None
    assert credentials.access_key == "testing"


def test_aws_profile_env_is_cleared() -> None:
    assert "AWS_PROFILE" not in os.environ
    assert "AWS_DEFAULT_REGION" not in os.environ
