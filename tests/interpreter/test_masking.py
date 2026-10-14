"""마스킹: LLM에 보내기 전 식별정보 치환, 응답 복원 (원칙 5, ADR-007)."""

import json
from typing import Any

import pytest

from kompass.interpreter.masking import Masker

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"

FINDING_LIKE: dict[str, Any] = {
    "rule_id": "IAM-007",
    "resource": f"arn:aws:iam::{ACCOUNT}:user/kompass-lab-admin",
    "region": None,
    "message": "그룹을 통해 관리자 권한을 가진 사용자: kompass-lab-admin",
    "evidence": {
        "user": "kompass-lab-admin",
        "sources": [
            {"via": "group:admins-team", "policy": "arn:aws:iam::aws:policy/AdministratorAccess"},
            {"via": "user", "policy": f"arn:aws:iam::{ACCOUNT}:policy/wildcard-policy"},
        ],
        "public_ip": "203.0.113.10",
        "cidrs": ["0.0.0.0/0", "::/0", "10.10.0.0/16"],
        "group_id": "sg-0a1b2c3d4e5f67890",
        "vpc_id": "vpc-0123456789abcdef0",
        "description": "kompass lab: workload in public-only VPC",
        "bucket": "kompass-lab-public-acl-0e094f74",
        "trail": f"arn:aws:cloudtrail:ap-northeast-2:{ACCOUNT}:trail/kompass-lab-trail",
        "bucket_arn": "arn:aws:s3:::kompass-lab-public-acl-0e094f74",
        "port": 22,
        "flag": True,
    },
}
SENSITIVE = [
    ACCOUNT,
    "kompass-lab-admin",
    "admins-team",
    "wildcard-policy",
    "203.0.113.10",
    "10.10.0.0/16",
    "sg-0a1b2c3d4e5f67890",
    "vpc-0123456789abcdef0",
    "kompass lab: workload in public-only VPC",
    "kompass-lab-public-acl-0e094f74",
    "kompass-lab-trail",
]


def _masked() -> tuple[Masker, Any]:
    masker = Masker.for_values([FINDING_LIKE])
    return masker, masker.mask(FINDING_LIKE)


def test_no_sensitive_value_survives() -> None:
    _, masked = _masked()
    text = json.dumps(masked, ensure_ascii=False)
    leaked = [value for value in SENSITIVE if value in text]
    assert leaked == []


def test_round_trip_restores_exactly() -> None:
    masker, masked = _masked()
    assert masker.unmask(masked) == FINDING_LIKE


def test_semantic_values_are_kept() -> None:
    _, masked = _masked()
    evidence = masked["evidence"]
    assert evidence["cidrs"][:2] == ["0.0.0.0/0", "::/0"]  # 판정의 의미 자체
    assert evidence["sources"][0]["policy"] == "arn:aws:iam::aws:policy/AdministratorAccess"
    assert evidence["port"] == 22 and evidence["flag"] is True
    assert masked["rule_id"] == "IAM-007"


def test_arn_keeps_type_and_masks_account_and_name() -> None:
    _, masked = _masked()
    resource = masked["resource"]
    assert resource.startswith("arn:aws:iam::MASKED_ACCOUNT_")
    assert ":user/MASKED_NAME_" in resource


def test_resource_ids_keep_kind() -> None:
    _, masked = _masked()
    assert masked["evidence"]["group_id"].startswith("MASKED_SG_")
    assert masked["evidence"]["vpc_id"].startswith("MASKED_VPC_")


def test_same_value_gets_same_token() -> None:
    # 메시지 속 사용자 이름과 증적의 사용자 이름이 같은 자리표시자여야 LLM이 연결할 수 있다
    _, masked = _masked()
    token = masked["evidence"]["user"]
    assert token.startswith("MASKED_NAME_")
    assert token in masked["message"]
    assert masked["resource"].endswith(f"user/{token}")


def test_unmask_text_restores_tokens_in_llm_output() -> None:
    masker, masked = _masked()
    sg = masked["evidence"]["group_id"]
    command = f"aws ec2 revoke-security-group-ingress --group-id {sg} --protocol tcp --port 22"
    restored = masker.unmask_text(command)
    assert "sg-0a1b2c3d4e5f67890" in restored


def test_unknown_tokens_are_left_alone() -> None:
    # LLM이 지어낸 자리표시자는 복원하지 않고 그대로 둔다 (검증 단계에서 드러나게)
    masker, _ = _masked()
    assert masker.unmask_text("MASKED_SG_999") == "MASKED_SG_999"


def test_other_account_ids_in_free_text_are_masked() -> None:
    masker = Masker.for_values([{"message": f"trust from {OTHER_ACCOUNT}"}])
    assert OTHER_ACCOUNT not in masker.mask_text(f"trust from {OTHER_ACCOUNT}")


def test_short_names_do_not_corrupt_words() -> None:
    # 너무 짧은 이름은 다른 단어 속에서 치환하지 않는다
    data = {"evidence": {"user": "ab"}, "message": "tab and ab"}
    masker = Masker.for_values([data])
    masked = masker.mask(data)
    assert "tab" in masked["message"]
    assert masker.unmask(masked) == data


def test_name_inside_longer_name_is_masked_consistently() -> None:
    data = {
        "evidence": {"bucket": "logs", "target_bucket": "logs-archive"},
        "message": "logs to logs-archive",
    }
    masker = Masker.for_values([data])
    masked = masker.mask(data)
    assert "logs" not in json.dumps(masked)
    assert masker.unmask(masked) == data


@pytest.mark.parametrize("ip", ["198.51.100.7", "2001:db8::1", "172.16.0.0/12"])
def test_ip_addresses_and_cidrs_masked(ip: str) -> None:
    masker = Masker.for_values([])
    masked = masker.mask_text(f"from {ip} allowed")
    assert ip not in masked
    assert masker.unmask_text(masked) == f"from {ip} allowed"


def test_table_is_not_shared_between_maskers() -> None:
    a = Masker.for_values([FINDING_LIKE])
    b = Masker.for_values([])
    assert b.unmask_text(a.mask_text(ACCOUNT)) != ACCOUNT


def test_unknown_tokens_detects_invented_placeholders() -> None:
    masker, masked = _masked()
    sg = masked["evidence"]["group_id"]
    assert masker.unknown_tokens(f"{sg} and MASKED_SG_999") == {"MASKED_SG_999"}
