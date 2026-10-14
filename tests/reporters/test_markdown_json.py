"""JSON·Markdown 리포터."""

from kompass.models import AuditReport
from kompass.reporters.json_reporter import render_json
from kompass.reporters.markdown_reporter import render_markdown
from tests.reporters.sample import DEFAULT, sample_report

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
