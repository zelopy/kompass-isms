"""마스킹: LLM에 보내기 전 식별정보 치환, 응답 복원 (원칙 5, ADR-007)."""

import json
from pathlib import Path
from typing import Any

import pytest

from kompass.interpreter.masking import Masker, MaskingError, load_terms

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


def test_ids_followed_by_korean_particles_are_masked() -> None:
    # 회귀: 파이썬 \w가 한글도 단어 문자로 봐서 "vpc-…의"의 ID를 가리지 못했다
    # (LLM이 쓴 해설 요약을 종합 평가에 다시 넣을 때 드러남, 전송 직전 검사가 차단)
    masker = Masker.for_values([])
    text = (
        "VPC vpc-0a1b2c3d4e5f60718의 리소스, 인터페이스 eni-0f1e2d3c4b5a69788에 공인 IP, "
        "사용자 AIDAEXAMPLEUSERID0001는"
    )
    masked = masker.mask_text(text)
    for raw in ("vpc-0a1b2c3d4e5f60718", "eni-0f1e2d3c4b5a69788", "AIDAEXAMPLEUSERID0001"):
        assert raw not in masked
    assert "MASKED_VPC_1의" in masked and masker.unmask_text(masked) == text


def test_add_names_extends_vocabulary_and_keeps_tokens() -> None:
    masker = Masker.for_values([{"user": "alice"}])
    first = masker.mask_text("alice")
    masker.add_names(["platform-admins", "sg-0123456789abcdef0", "ab", "default", "alice"])
    assert "platform-admins" in masker.names
    assert "sg-0123456789abcdef0" not in masker.names  # ID는 정규식 단계가 맡는다
    assert "ab" not in masker.names and "default" not in masker.names
    assert masker.mask_text("alice in platform-admins").startswith(first)
    assert "platform-admins" not in masker.mask_text("alice in platform-admins")


def test_root_principal_is_kept() -> None:
    # 루트 사용자는 AWS가 정한 고정 주체라 식별정보가 아니다. 가리면 루트 사용 여부를 알 수 없다
    data = {
        "username": "root",
        "user_arn": "arn:aws:iam::123456789012:root",
        "other": "arn:aws:iam::123456789012:user/alice",
    }
    masker = Masker.for_values([data])
    masker.add_names(["root", "alice"])
    masked = masker.mask(data)
    assert masked["username"] == "root"
    assert masked["user_arn"] == "arn:aws:iam::MASKED_ACCOUNT_1:root"
    assert "alice" not in masked["other"] and "123456789012" not in json.dumps(masked)


def test_rds_identifiers_and_endpoint_are_masked() -> None:
    finding = {
        "resource": "cluster:ledger",
        "evidence": {
            "db_identifier": "ledger",
            "db_cluster": "ledger",
            "endpoint": "orders-db.abc123xyz.ap-northeast-2.rds.amazonaws.com",
            "subnet_group": "prod-db-subnets",
        },
    }
    masker = Masker.for_values([finding])
    text = json.dumps(masker.mask(finding))
    for raw in ("ledger", "orders-db", "abc123xyz", "prod-db-subnets"):
        assert raw not in text, raw


# --- 증적 문서의 개인정보 (ADR-049) ---


def test_personal_patterns_are_off_by_default() -> None:
    # 해설·조사 프롬프트는 평가셋 기준선에 묶여 있어 기존 동작을 바꾸지 않는다 (ADR-033)
    text = "담당 alice@example.com, 010-1234-5678"
    assert Masker().mask_text(text) == text


def test_emails_phones_and_resident_numbers_are_masked() -> None:
    masker = Masker(personal=True)
    text = (
        "alice.kim+ops@corp.example.co.kr / 010-1234-5678 / 01098765432 / 02-123-4567 / "
        "+82-10-2222-3333 / 900101-1234567 / 9001012345678"
    )
    masked = masker.mask_text(text)
    assert masked == (
        "MASKED_EMAIL_1 / MASKED_PHONE_1 / MASKED_PHONE_2 / MASKED_PHONE_3 / "
        "MASKED_PHONE_4 / MASKED_RRN_1 / MASKED_RRN_2"
    )
    assert masker.unmask_text(masked) == text


def test_dates_times_and_aws_numbers_are_not_personal() -> None:
    masker = Masker(personal=True)
    text = "2026-10-17 08:38:24, 보존 365일, 포트 3306, 계정 123456789012, 규칙 1-65535"
    assert masker.mask_text(text) == text.replace("123456789012", "MASKED_ACCOUNT_1")


def test_email_is_masked_before_names_inside_it() -> None:
    # IAM 사용자 이름이 메일 주소의 일부여도 주소 전체가 하나의 자리표시자가 된다
    masker = Masker(["alice"], personal=True)
    assert masker.mask_text("alice / alice@corp.example") == "MASKED_NAME_1 / MASKED_EMAIL_1"


def test_dictionary_terms_include_two_letter_korean_names() -> None:
    masker = Masker(terms=["홍길동", "이산", "보안운영팀", "x"], personal=True)
    masked = masker.mask_text("홍길동님(보안운영팀), 이산: 퇴사")
    # 긴 것부터 바꾸므로 번호는 길이 순이다
    assert masked == "MASKED_TERM_2님(MASKED_TERM_1), MASKED_TERM_3: 퇴사"
    assert masker.mask_text("x") == "x"  # 한 글자는 사전에 넣어도 바꾸지 않는다


def test_korean_terms_are_masked_inside_file_names() -> None:
    masker = Masker(terms=["홍길동", "ops"])
    # 길이가 같으면 문자 순으로 바꾼다 ("ops" < "홍길동"). 집합 순서에 따라 번호가 바뀌지 않는다
    assert (
        masker.mask_text("홍길동_권한.xlsx, ops_team, ops")
        == "MASKED_TERM_2_권한.xlsx, ops_team, MASKED_TERM_1"
    )


def test_longer_terms_are_replaced_first() -> None:
    masker = Masker(terms=["김철", "김철수"])
    assert masker.mask_text("김철수, 김철") == "MASKED_TERM_1, MASKED_TERM_2"
    assert masker.unmask_text("MASKED_TERM_1") == "김철수"


def test_require_clean_rejects_remaining_terms() -> None:
    masker = Masker(terms=["홍길동"])
    with pytest.raises(MaskingError, match="가리지 못한 이름"):
        masker.require_clean("홍길동", ())
    masker.require_clean(masker.mask_text("홍길동"), ())


def test_token_counts_summarise_what_was_masked() -> None:
    masker = Masker(terms=["홍길동"], personal=True)
    masker.mask_text("홍길동 a@b.example 010-1111-2222 c@d.example a@b.example")
    assert masker.token_counts() == {"EMAIL": 2, "PHONE": 1, "TERM": 1}


def test_load_terms_reads_one_term_per_line(tmp_path: Path) -> None:
    path = tmp_path / "terms.txt"
    path.write_text("﻿# 직원 명단\n홍길동\n\n  이산  \n홍길동\n", encoding="utf-8")
    assert load_terms(path) == ("홍길동", "이산")


def test_load_terms_reports_unreadable_file(tmp_path: Path) -> None:
    with pytest.raises(MaskingError, match="마스킹 사전"):
        load_terms(tmp_path / "missing.txt")
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"\xff\xfe\x81")
    with pytest.raises(MaskingError, match="UTF-8"):
        load_terms(bad)


def test_json_escapes_before_placeholders_are_not_partial_masks() -> None:
    masker = Masker(["prod-web"])
    masked = masker.mask({"message": "규칙 목록:\nprod-web\t22/tcp\r\nprod-web"})
    text = json.dumps(masked, ensure_ascii=False)
    assert "\\nMASKED_NAME_1" in text and "\\tMASKED_NAME_1" not in text
    masker.require_clean(text, [])  # 이스케이프는 이름 문자가 아니다
    assert masker.partially_masked("xMASKED_NAME_1")  # 실제로 붙은 글자는 계속 잡는다
    assert masker.partially_masked("prod-MASKED_NAME_1")
