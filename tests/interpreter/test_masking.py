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


# --- 실제 증적 형태 회귀 테스트 (실습 계정에서 노출이 확인된 경로) ---

ACL_BUCKET = "kompass-lab-public-acl-0e094f74"
LOG_BUCKET = "kompass-lab-logs-0e094f74"
PRIVATE_BUCKET = "kompass-lab-private-0e094f74"


def test_resource_field_names_are_masked() -> None:
    # S3 finding은 버킷 이름이 resource에만 있다
    data = {"resource": LOG_BUCKET, "message": f"서버 액세스 로깅이 꺼져 있음: {LOG_BUCKET}"}
    masker = Masker.for_values([data])
    text = json.dumps(masker.mask(data), ensure_ascii=False)
    assert LOG_BUCKET not in text
    assert masker.unmask(masker.mask(data)) == data


def test_account_resource_is_not_a_name() -> None:
    masker = Masker.for_values([{"resource": "account"}])
    assert masker.mask_text("IAM-004:-:account") == "IAM-004:-:account"


def test_names_referenced_from_other_findings() -> None:
    # 다른 finding의 이름(log_target_for, target_prefix 안)도 마스킹한다
    group = {"resource": LOG_BUCKET, "evidence": {"log_target_for": [PRIVATE_BUCKET]}}
    other = {
        "resource": PRIVATE_BUCKET,
        "evidence": {"target_prefix": f"s3-access/{PRIVATE_BUCKET}/"},
    }
    masker = Masker.for_values([group, other])
    text = json.dumps(masker.mask([group, other]), ensure_ascii=False)
    assert PRIVATE_BUCKET not in text and LOG_BUCKET not in text


def test_id_like_suffix_inside_name_is_not_a_resource_id() -> None:
    # "...-acl-0e094f74"는 네트워크 ACL ID가 아니라 버킷 이름의 일부다
    masker = Masker.for_values([{"resource": ACL_BUCKET}])
    masked = masker.mask_text(f"버킷 {ACL_BUCKET}의 ACL")
    assert "MASKED_ACL" not in masked and "kompass" not in masked
    assert masker.mask_text("acl-0123abcd 와 sg-0123456789abcdef0") == "MASKED_ACL_1 와 MASKED_SG_1"


def test_dict_keys_are_masked() -> None:
    data = {"subnets": {"subnet-074cf8448312397c5": {"public": True}}}
    masker = Masker.for_values([data])
    masked = masker.mask(data)
    assert "subnet-074cf8448312397c5" not in json.dumps(masked)
    assert masker.unmask(masked) == data


def test_arn_path_segments_are_masked() -> None:
    masker = Masker.for_values([])
    role = masker.mask_text(f"arn:aws:sts::{ACCOUNT}:assumed-role/kompass-audit-role/alice-session")
    assert role.startswith("arn:aws:sts::MASKED_ACCOUNT_1:assumed-role/MASKED_NAME_")
    assert "kompass-audit-role" not in role and "alice-session" not in role
    user = masker.mask_text(f"arn:aws:iam::{ACCOUNT}:user/engineering/alice")
    assert "engineering" not in user and "alice" not in user


def test_aws_defined_path_segments_are_kept() -> None:
    masker = Masker.for_values([])
    arn = (
        f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/ap-northeast-2/"
        "AWSReservedSSO_Admin_0123456789abcdef"
    )
    masked = masker.mask_text(arn)
    assert "role/aws-reserved/sso.amazonaws.com/ap-northeast-2/MASKED_NAME_" in masked
    assert "AWSReservedSSO_Admin" not in masked


def test_s3_object_arn_masks_bucket() -> None:
    masker = Masker.for_values([])
    masked = masker.mask_text("arn:aws:s3:::my-secret-bucket/path/key.txt")
    assert "my-secret-bucket" not in masked and "path" not in masked


def test_iam_unique_ids_and_access_keys_are_masked() -> None:
    masker = Masker.for_values([])
    text = "requester AIDAEXAMPLEUSERID0001, key AKIAIOSFODNN7EXAMPLE, role AROAEXAMPLEROLEID0001"
    masked = masker.mask_text(text)
    for raw in ("AIDAEXAMPLEUSERID0001", "AKIAIOSFODNN7EXAMPLE", "AROAEXAMPLEROLEID0001"):
        assert raw not in masked
    assert masker.unmask_text(masked) == text


def test_inline_policy_names_are_masked() -> None:
    data = {"evidence": {"policy": "inline:kompass-lab-notaction"}}
    masker = Masker.for_values([data])
    assert "kompass-lab-notaction" not in json.dumps(masker.mask(data))


def test_aws_default_names_are_kept() -> None:
    masker = Masker.for_values([{"group_name": "default"}])
    assert masker.mask_text("default 보안그룹") == "default 보안그룹"


def test_partial_masking_is_detected() -> None:
    masker = Masker.for_values([])
    assert masker.partially_masked("kompass-MASKED_ACL_1 그리고 user/MASKED_NAME_2")
    assert not masker.partially_masked("user/MASKED_NAME_2, SG-001:ap:MASKED_SG_1의 규칙")


def test_name_only_in_arn_and_message_is_masked() -> None:
    # 증적에 사용자 이름 키가 없어도 ARN에서 이름을 모아 메시지 속 이름까지 바꾼다
    data = {
        "resource": f"arn:aws:iam::{ACCOUNT}:user/bob-ops",
        "message": "관리자 권한이 직접 연결되어 있음: bob-ops",
    }
    masker = Masker.for_values([data])
    masked = masker.mask(data)
    assert "bob-ops" not in json.dumps(masked, ensure_ascii=False)
    token = masked["resource"].rpartition("/")[2]
    assert token in masked["message"]


def test_two_digit_token_numbers_are_not_partial() -> None:
    # 회귀: 같은 종류 자리표시자가 10개를 넘으면 모든 요청이 차단되던 버그 (평가셋이 발견)
    masker = Masker.for_values([])
    assert not masker.partially_masked("user/MASKED_NAME_10, MASKED_SG_123")
    assert masker.partially_masked("MASKED_NAME_10-prod")
