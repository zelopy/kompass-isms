"""S3-007 버킷 정책 HTTPS 미강제."""

import json
from typing import Any

import pytest

from kompass.config import Settings
from kompass.models import Finding, Status
from kompass.rules.s3.s3_007_secure_transport import S3007SecureTransport
from tests.rules.s3.data import collect_error, details, snapshot

S3007 = S3007SecureTransport()
BUCKET = "orders"


def deny_http(**overrides: Any) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Sid": "DenyInsecureTransport",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [f"arn:aws:s3:::{BUCKET}", f"arn:aws:s3:::{BUCKET}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }
    statement.update(overrides)
    return statement


def policy(*statements: dict[str, Any]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _judge(bucket: dict[str, Any], *errors: Any) -> Finding:
    [finding] = S3007.evaluate(snapshot({BUCKET: bucket}, errors=errors), Settings())
    assert finding.resource == BUCKET
    return finding


def test_pass_with_deny_insecure_transport() -> None:
    finding = _judge(details(policy=policy(deny_http())))
    assert finding.status == Status.PASS
    assert finding.evidence["statement_sids"] == ["DenyInsecureTransport"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"Principal": {"AWS": "*"}},
        {"Principal": {"AWS": ["*"]}},
        {"Action": ["s3:GetObject", "s3:*"]},
        {"Action": "*"},
        {"Resource": "*"},
        {"Resource": f"arn:aws:s3:::{BUCKET}/*"},
        {"Condition": {"BoolIfExists": {"aws:securetransport": False}}},
        {"Condition": {"Bool": {"aws:SecureTransport": ["false"]}}},
    ],
)
def test_pass_variants(overrides: dict[str, Any]) -> None:
    assert _judge(details(policy=policy(deny_http(**overrides)))).status == Status.PASS


def test_fail_without_policy() -> None:
    finding = _judge(details(policy=None))
    assert finding.status == Status.FAIL and finding.evidence["has_policy"] is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"Effect": "Allow"},
        {"Principal": {"AWS": "arn:aws:iam::123456789012:root"}},
        {"Action": "s3:GetObject"},
        {"Resource": f"arn:aws:s3:::{BUCKET}"},  # 객체가 빠짐
        {"Condition": {"Bool": {"aws:SecureTransport": "true"}}},
        {"Condition": {"NumericLessThan": {"s3:TlsVersion": "1.2"}}},
    ],
)
def test_fail_when_statement_does_not_enforce_https(overrides: dict[str, Any]) -> None:
    allow = {"Sid": "Read", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
    finding = _judge(details(policy=policy(allow, deny_http(**overrides))))
    assert finding.status == Status.FAIL


def test_error_when_policy_not_collected() -> None:
    error = collect_error("s3:GetBucketPolicy", BUCKET)
    finding = _judge(details(missing=("policy",)), error)
    assert finding.status == Status.ERROR


def test_error_when_policy_is_not_json() -> None:
    assert _judge(details(policy="{broken")).status == Status.ERROR
