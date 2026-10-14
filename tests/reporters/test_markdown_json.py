"""JSON·Markdown 리포터."""

from kompass.models import AuditReport
from kompass.reporters.json_reporter import render_json
from kompass.reporters.markdown_reporter import render_markdown
from tests.reporters.sample import DEFAULT, EXPLAINED, sample_report

MD = render_markdown(DEFAULT)


# --- JSON ---


def test_json_round_trips() -> None:
    assert AuditReport.model_validate_json(render_json(DEFAULT)) == DEFAULT


def test_json_keeps_korean_readable() -> None:
    assert "관리 포트가 전체 개방" in render_json(DEFAULT)


# --- Markdown: 머리말과 점검 정보 ---


def test_disclaimers() -> None:
    assert "인증 심사 결과를 보장하지 않는다" in MD
    assert "ISMS-P 매핑은 원문 검증 전 초안" in MD


def test_scan_information_in_kst() -> None:
    assert "123456789012" in MD
    assert "arn:aws:iam::123456789012:user/security_manager" in MD
    assert "2026-10-14 08:07:54 KST" in MD
    assert DEFAULT.mapping_digest[:12] in MD
    assert "admin_ports: [22, 3389]" in MD


# --- KISA 항목 ---


def test_all_kisa_items_listed_with_korean_outcomes() -> None:
    for code in ("CA-01", "CA-09", "CA-13", "CA-19"):
        assert f"| {code} |" in MD
    assert "| CA-09 | 접근 제어 설정 관리 | 상 | partial | 취약 |" in MD
    assert "| CA-13 | 클라우드 서비스 사용자 계정 로깅 설정 | 상 | full | 양호 |" in MD
    assert "| CA-05 | 인스턴스 서비스 정책 관리 | 상 | partial | 수동 점검 (미구현) |" in MD
    assert "| CA-03 | MFA(Multi-Factor Authentication) 설정 | 상 | full | 점검하지 않음 |" in MD


def test_summary_counts() -> None:
    assert "취약 1" in MD  # CA-09
    assert "수동 점검 (미구현) 9" in MD
    assert "finding: 취약 2, 확인 불가 0, 검토 필요 1, 양호 4, 해당 없음 0" in MD


# --- 조치가 필요한 결과 ---


def test_action_findings_with_escaped_evidence() -> None:
    assert "관리 포트가 전체 개방: sg-1" in MD
    assert "open\\|ssh" in MD  # 표 구분자 이스케이프
    assert "루트 비밀번호 사용 이력을 확인할 수 없다" in MD


def test_pass_findings_not_listed_in_action_section() -> None:
    action = MD.split("## 조치가 필요한 결과", 1)[1].split("\n## ", 1)[0]
    assert "sg-2" not in action


def test_rules_without_kisa_section() -> None:
    section = MD.split("## KISA 대응 항목이 없는 룰", 1)[1].split("\n## ", 1)[0]
    assert "S3-004" in section
    assert "기본 암호화가 없다" in section


# --- ISMS-P ---


def test_isms_p_only_related_controls_listed() -> None:
    section = MD.split("## ISMS-P 통제항목", 1)[1].split("\n## ", 1)[0]
    assert "| 2.6.1 | 네트워크 접근 |" in section
    assert "| 1.1.1 |" not in section
    assert "자동 점검 범위 밖" in section


# --- 건너뛴 룰 ---


def test_skipped_rules() -> None:
    assert "IAM-001, IAM-002" in MD


def test_empty_report_renders() -> None:
    text = render_markdown(sample_report())
    assert "조치가 필요한 결과가 없다" in text


def test_excluded_regions_are_shown_as_out_of_scope() -> None:
    from kompass.models import AuditReport

    scan = DEFAULT.scan.model_validate(
        {**DEFAULT.scan.model_dump(), "excluded_regions": {"eu-west-1": "AccessDenied: scp|deny"}}
    )
    report = AuditReport.model_validate({**DEFAULT.model_dump(), "scan": scan})
    text = render_markdown(report)
    assert "| 점검 제외 리전 (접근 거부) | eu-west-1 |" in text
    assert "점검 범위 밖 리전 1개" in text
    assert "양호가 아니라 확인하지 않은 것" in text
    assert r"scp\|deny" in text  # 표 구분자 이스케이프


def test_no_excluded_regions() -> None:
    assert "| 점검 제외 리전 (접근 거부) | 없음 |" in MD
    assert "점검 범위 밖 리전" not in MD


# --- AI 해설 ---

EXPLAINED_MD = render_markdown(EXPLAINED)


def test_no_explanation_section_without_explanations() -> None:
    assert "## AI 해설" not in MD
    assert "| AI 해설 | 없음 |" in MD


def test_explanation_section_states_it_does_not_change_judgment() -> None:
    assert "## AI 해설 (참고)" in EXPLAINED_MD
    assert "판정과 심각도는 룰이 정했고" in EXPLAINED_MD
    assert "| AI 해설 | claude-opus-5-5 (effort high)" in EXPLAINED_MD


def test_explanation_per_rule_with_verification_label() -> None:
    assert "### SG-001 " in EXPLAINED_MD and "원문 인용 검증됨" in EXPLAINED_MD
    assert "### S3-004 " in EXPLAINED_MD and "검증되지 않음" in EXPLAINED_MD
    assert '원문에 없는 구절: kisa CA-10 "지어낸 문장"' in EXPLAINED_MD
    assert '- KISA CA-09: "불필요한 포트를 차단해야 함"' in EXPLAINED_MD
    assert "`SG-001:ap-northeast-2:sg-1`: bastion 용도 확인" in EXPLAINED_MD


def test_explanation_failures_are_listed() -> None:
    assert "IAM-008: 거부됨" in EXPLAINED_MD


def test_llm_text_cannot_inject_markdown() -> None:
    # 줄바꿈을 접어 제목을 만들 수 없고, HTML은 이스케이프한다
    assert "\n# 제목 아님" not in EXPLAINED_MD
    assert "<b>" not in EXPLAINED_MD and "&lt;b&gt;굵게" in EXPLAINED_MD


def test_code_fence_longer_than_backticks_in_command() -> None:
    assert "````bash\n=cmd|' /C calc'!A0\naws ec2 revoke-security-group-ingress" in EXPLAINED_MD
    assert "--group-id sg-1 ```\n````\n" in EXPLAINED_MD


def test_json_includes_explanations() -> None:
    assert AuditReport.model_validate_json(render_json(EXPLAINED)) == EXPLAINED
