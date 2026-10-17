"""평가 채점기: CLI 검사, 원문 구간, 정답 데이터, 오라클·널 점검 (ADR-033)."""

from pathlib import Path

import pytest

from kompass.evals.cases import EVAL_TIME, case_report, load_cases
from kompass.evals.grader import (
    METRICS,
    CaseOutcome,
    _iam_action_to_botocore,
    check_command,
    grade,
    kisa_sections,
    load_golden,
    parse_cli,
    split_commands,
    style_violations,
)
from kompass.evals.providers import NullProvider, OracleProvider, RecordingProvider
from kompass.interpreter.explainer import explain_report
from kompass.interpreter.llm import LLMProvider
from kompass.interpreter.sources import SourceIndexError, SourceLookup, load_index
from kompass.models import EvalCase, Remediation, RuleExplanationDraft
from kompass.rules.registry import RULES

EVAL_DIR = Path(__file__).parents[2] / "evals" / "explain"
GOLDEN = load_golden(EVAL_DIR / "golden.yaml")


# --- CLI 분리·검사 ---


def test_split_commands_handles_chains_subshells_and_quotes() -> None:
    text = (
        "aws s3control put-public-access-block --account-id $(aws sts get-caller-identity "
        "--query Account --output text) && aws iam list-roles --query \"Roles[?contains(a, 'b')]\" "
        "| jq . ; echo done"
    )
    commands = split_commands(text)
    assert [c[:3] for c in commands] == [
        ["aws", "s3control", "put-public-access-block"],
        ["aws", "sts", "get-caller-identity"],
        ["aws", "iam", "list-roles"],
    ]


def test_placeholders_are_not_separators() -> None:
    [command] = split_commands(
        "aws ec2 authorize-security-group-ingress --cidr <관리자_IP>/32 --port 22"
    )
    assert command[-2:] == ["--port", "22"]


def test_valid_and_invalid_commands() -> None:
    revoke = "aws ec2 revoke-security-group-ingress --group-id sg-1"
    ok = parse_cli([f"{revoke} --protocol tcp --port 22 --cidr 0.0.0.0/0"])
    assert [c.status for c in ok] == ["valid"] and ok[0].action == "ec2:RevokeSecurityGroupIngress"
    bad_op = parse_cli(["aws ec2 remove-all-rules --group-id sg-1"])
    assert bad_op[0].status == "invalid" and "작업" in (bad_op[0].problem or "")
    bad_opt = parse_cli(["aws iam delete-login-profile --user alice"])
    assert bad_opt[0].status == "invalid" and "--user" in (bad_opt[0].problem or "")
    assert parse_cli(["aws s3 ls s3://bucket"])[0].status == "unverifiable"
    assert parse_cli(["aws --region us-east-1 iam list-users"])[0].status == "valid"
    assert parse_cli(["aws iam list-users --query 'Users[0"])[0].status == "invalid"  # 따옴표


def test_cli_customized_and_boolean_options() -> None:
    assert check_command(
        ["aws", "iam", "create-virtual-mfa-device", "--virtual-mfa-device-name", "x",
         "--outfile", "qr.png", "--bootstrap-method", "QRCodePNG"], ""
    ).status == "valid"  # fmt: skip
    assert (
        parse_cli(["aws s3api put-bucket-versioning --bucket b --no-cli-pager"])[0].status
        == "valid"
    )
    assert (
        parse_cli(
            ["aws cloudtrail create-trail --name t --s3-bucket-name b --is-multi-region-trail"]
        )[0].status
        == "valid"
    )
    assert (
        parse_cli(
            ["aws cloudtrail create-trail --name t --s3-bucket-name b --no-is-multi-region-trail"]
        )[0].status
        == "valid"
    )


def test_write_detection() -> None:
    [write, read] = parse_cli(["aws iam delete-login-profile --user-name a", "aws iam list-users"])
    assert write.is_write and not read.is_write


# --- 원문 구간·문체 ---

KISA_TEXT = """CA-01
(상)
사용자 계정 관리
개요
점검 내용 불필요한 계정 존재 여부 점검
판단 기준
양호 : 불필요한 계정이 없는 경우
취약 : 불필요한 계정이 존재하며 활성화 된 경우
조치 방법 불필요한 계정 삭제 또는 비활성화
조치 시 영향 일반적인 경우 영향 없음
점검 및 조치 사례
§ 퇴사자 계정은 삭제해야 함"""


def test_kisa_sections() -> None:
    sections = kisa_sections(KISA_TEXT)
    assert "취약 : 불필요한 계정이 존재하며" in sections["판단 기준"]
    assert sections["조치 방법"].strip() == "불필요한 계정 삭제 또는 비활성화"
    assert "퇴사자" in sections["점검 및 조치 사례"]
    assert "영향 없음" in sections["조치 시 영향"]


def test_style_violations() -> None:
    draft = RuleExplanationDraft(
        summary="설정되지 않음. 위험이 있습니다.",
        risk="노출 위험이 있음",
        priority="high",
        priority_reason="즉시 조치 필요",
        citations=[],
        remediation=Remediation(
            steps=["규칙 삭제한다.", "확인 (콘솔)"], aws_cli=[], terraform=None
        ),
        resource_notes=[],
    )
    assert style_violations(draft) == ["위험이 있습니다.", "규칙 삭제한다."]


# --- 정답 데이터 ---


def test_golden_covers_every_rule() -> None:
    assert set(GOLDEN.rules) == {rule.id for rule in RULES}


def test_golden_actions_exist_in_botocore() -> None:
    actions = set(GOLDEN.error_actions)
    for rule in GOLDEN.rules.values():
        actions |= set(rule.fail) | set(rule.review)
    missing = sorted(a for a in actions if _iam_action_to_botocore(a) is None)
    assert missing == []


def test_golden_examples_are_valid_and_match_actions() -> None:
    for rule_id, rule in GOLDEN.rules.items():
        [command] = parse_cli([rule.example.replace("{resource}", "res-1")])
        assert command.status == "valid", (rule_id, command.problem)
        assert command.action in set(rule.fail) | set(rule.review), rule_id
    [error] = parse_cli([GOLDEN.error_example])
    assert error.status == "valid" and error.action in GOLDEN.error_actions


# --- 오라클·널 (실제 해설 흐름을 거친다) ---


def _lookup() -> SourceLookup:
    try:
        return SourceLookup(load_index())
    except SourceIndexError:
        pytest.skip("원문 색인이 없음 (knowledge/SOURCES.md 참고)")


def _run(case: EvalCase, provider: LLMProvider, lookup: SourceLookup) -> dict[str, float | None]:
    recorder = RecordingProvider(provider)
    result = explain_report(case_report(case), recorder, lookup, effort="high", assess=False)
    assert result.failures == (), result.failures
    [explanation] = result.explanations
    outcome = CaseOutcome(
        case=case,
        explanation=explanation,
        first_draft=recorder.attempts[0].parsed,  # type: ignore[arg-type]
        prompts=[a.prompt for a in recorder.attempts],
    )
    return grade(outcome, GOLDEN, lookup).scores


def test_oracle_scores_full_marks_on_every_case() -> None:
    lookup = _lookup()
    for case in load_cases(EVAL_DIR / "cases"):
        scores = _run(case, OracleProvider(GOLDEN), lookup)
        assert set(scores) == set(METRICS)
        low = {k: v for k, v in scores.items() if v is not None and v < 1.0}
        assert low == {}, (case.id, low)


def test_null_scores_zero_on_quality_metrics() -> None:
    lookup = _lookup()
    for case in load_cases(EVAL_DIR / "cases"):
        scores = _run(case, NullProvider(), lookup)
        for metric in ("verified", "first_try", "cite_precision", "core_basis", "cli_valid",
                       "action_cover", "style_ok"):  # fmt: skip
            assert scores[metric] in (0.0, None), (case.id, metric, scores[metric])
        assert scores["leak_free"] == 1.0  # 마스킹은 공급자와 무관하다


def test_boolean_value_structures_are_flags() -> None:
    # 파일럿에서 발견: CLI는 {Value: boolean} 구조체를 --x / --no-x 플래그로 받는다
    for flag in ("--no-map-public-ip-on-launch", "--map-public-ip-on-launch"):
        [command] = parse_cli([f"aws ec2 modify-subnet-attribute --subnet-id subnet-1 {flag}"])
        assert command.status == "valid", flag


def test_core_quote_may_include_section_label() -> None:
    # 기준선에서 발견: 모델이 "조치 방법 …"처럼 구간 이름까지 인용한다
    from kompass.evals.grader import is_core_quote
    from kompass.models import SourceEntry, SourceIndex

    index = SourceIndex(
        built_at=EVAL_TIME,
        documents={},
        kisa={"CA-01": SourceEntry(title="t", page=1, text=KISA_TEXT)},
        isms_p={},
    )
    lookup = SourceLookup(index)
    assert is_core_quote(lookup, "CA-01", "조치 방법 불필요한 계정 삭제 또는 비활성화")
    assert is_core_quote(lookup, "CA-01", "불필요한 계정 삭제 또는 비활성화")
    assert not is_core_quote(lookup, "CA-01", "조치 시 영향 일반적인 경우 영향 없음")


def test_account_scoped_writes_are_not_target_judged() -> None:
    from kompass.evals.grader import _PLACEHOLDER  # noqa: F401  (형식 확인용)

    [command] = parse_cli(
        ["aws s3control put-public-access-block --account-id 123456789012 "
         "--public-access-block-configuration BlockPublicAcls=true"]
    )  # fmt: skip
    assert command.is_write and "--account-id" in command.text


def test_rds_targets_include_cluster_identifier_and_custom_parameter_group() -> None:
    # RDS-005 실제 실행에서 발견: 클러스터 finding의 리소스는 "cluster:<식별자>"이고,
    # SSL 강제 조치는 증적의 파라미터 그룹을 바꾼다. 기본 그룹(default.*)은 AWS가 수정을 막으므로
    # 대상이 아니다 (수정 명령은 대상 불일치로 남는다)
    from kompass.evals.grader import _targets

    cases = {c.id: c for c in load_cases(EVAL_DIR / "cases")}
    targets = _targets(cases["syn-rds-005-engine-default"].findings)
    assert {"acme-shop-db", "acme-analytics", "acme-analytics-cluster-params"} <= targets
    assert "default.mysql8.0" not in targets
    assert "acme-orders-db" not in targets  # PASS finding


def test_elb_targets_include_classic_load_balancer_name() -> None:
    # ELB 실제 실행에서 발견: Classic finding의 리소스는 "classic:<이름>"이고, 명령은
    # --load-balancer-name <이름>으로 가리킨다
    from kompass.evals.grader import _targets

    cases = {c.id: c for c in load_cases(EVAL_DIR / "cases")}
    targets = _targets(cases["syn-elb-001-classic-nlb"].findings)
    assert {"acme-legacy-web", "acme-api-nlb"} <= targets
    assert "acme-shop-alb" not in targets  # PASS finding


def test_error_actions_include_denied_lookups_nested_in_listeners() -> None:
    # ELB는 리스너별 수집 오류를 evidence.listeners[].errors에 남긴다.
    # 거부된 조회의 재실행도 정답이다
    from kompass.evals.grader import _required_actions, load_golden

    cases = {c.id: c for c in load_cases(EVAL_DIR / "cases")}
    golden = load_golden(EVAL_DIR / "golden.yaml")
    case = cases["syn-elb-002-classic-error"]
    assert (
        "elbv2:DescribeSSLPolicies"
        in _required_actions(case.findings, golden, case.rule_id)["ERROR"]
    )
    case = cases["syn-elb-001-error"]
    required = _required_actions(case.findings, golden, case.rule_id)["ERROR"]
    assert {"elbv2:DescribeRules", "elbv2:DescribeListeners"} <= required
