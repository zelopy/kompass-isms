"""추가 조사 흐름: 대상 선정, 마스킹, 도구 조사, 사실·호출 검증, 판정 불변 (ADR-035)."""

import json
from typing import Any

import pytest
from pydantic import ValidationError

from kompass.agent import tools as agent_tools
from kompass.agent.investigator import investigate_report, investigation_groups
from kompass.agent.llm import AgentTool
from kompass.agent.tools import Tool, ToolContext, ToolResult
from kompass.aws.guard import ReadOnlyViolation
from kompass.interpreter.llm import LLMError
from kompass.models import (
    Investigation,
    InvestigationDraft,
    InvestigationFact,
    InvestigationNote,
    InvestigationReport,
    Status,
)
from tests.agent.conftest import REGION, admin
from tests.agent.fakes import ScriptedAgent
from tests.reporters.sample import ACCOUNT, finding, sample_report

BUCKET = "acme-public-assets"


def _report() -> Any:
    return sample_report(
        finding(
            "S3-003",
            Status.FAIL,
            BUCKET,
            REGION,
            f"버킷 정책이 퍼블릭 접근을 허용함: {BUCKET}",
            {"bucket": BUCKET},
        ),
        finding("S3-003", Status.PASS, "acme-private-data", REGION),
        finding("IAM-008", Status.REVIEW, message="루트 비밀번호 사용 이력을 확인할 수 없음"),
        finding("CT-001", Status.ERROR, message="CloudTrail 추적 목록을 수집하지 못함"),
    )


def _bucket() -> None:
    s3 = admin("s3")
    s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PartnerRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{BUCKET}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(policy))


def _good(payload: dict[str, Any], tools: dict[str, AgentTool]) -> InvestigationDraft:
    first = payload["findings"][0]
    if payload["rule"]["id"] == "S3-003":
        result = json.loads(tools["s3_bucket_access"].call({"bucket": first["resource"]}))
        statement = f"{first['resource']} 정책 공개 여부 {result['policy_is_public']}"
    else:
        result = json.loads(tools["s3_account_public_access_block"].call({}))
        statement = "계정 수준 차단 조회"
    return InvestigationDraft(
        summary="추가 조사 결과",
        facts=[InvestigationFact(statement=statement, call_ids=[result["call_id"]])],
        finding_notes=[InvestigationNote(finding_key=first["key"], note="확인 필요")],
        open_questions=["정책 공개가 업무상 필요한지 담당자 확인 필요"],
    )


def _run(context: ToolContext, script: Any) -> tuple[InvestigationReport, ScriptedAgent]:
    agent = ScriptedAgent(script)
    return investigate_report(_report(), agent, context, effort="high"), agent


# --- 대상 선정 ---


def test_investigates_fail_and_review_only() -> None:
    groups = investigation_groups(_report())
    assert [g.rule_id for g in groups] == ["IAM-008", "S3-003"]
    assert all(f.status in (Status.FAIL, Status.REVIEW) for g in groups for f in g.findings)


# --- 조사·복원 ---


def test_verified_investigation_with_tool_log(context: ToolContext) -> None:
    _bucket()
    report, _ = _run(context, _good)
    s3 = next(i for i in report.investigations if i.rule_id == "S3-003")
    assert s3.verified and s3.problems == ()
    assert s3.investigation.facts[0].statement == f"{BUCKET} 정책 공개 여부 True"  # 복원됨
    [call] = s3.tool_calls
    assert call.call_id == "T1" and call.input_raw == {"bucket": BUCKET}
    assert BUCKET not in call.output_masked and "PartnerRead" not in call.output_masked
    assert s3.investigation.finding_notes[0].finding_key == f"S3-003:{REGION}:{BUCKET}"


def test_task_contains_no_raw_identifiers(context: ToolContext) -> None:
    _bucket()
    _, agent = _run(context, _good)
    sent = "\n".join(task for _, task in agent.tasks)
    for raw in (ACCOUNT, BUCKET):
        assert raw not in sent
    assert "hint" in sent and "버킷 정책 전문" in sent  # 룰별 조사 힌트


# --- 검증 ---


def test_fact_must_cite_real_tool_calls(context: ToolContext) -> None:
    def script(payload: dict[str, Any], tools: dict[str, AgentTool]) -> InvestigationDraft:
        return InvestigationDraft(
            summary="s",
            facts=[
                InvestigationFact(statement="호출 없이 단정", call_ids=[]),
                InvestigationFact(statement="없는 호출", call_ids=["T9"]),
            ],
            finding_notes=[InvestigationNote(finding_key="X:-:y", note="n")],
            open_questions=["MASKED_NAME_99 확인"],
        )

    report, _ = _run(context, script)
    problems = " / ".join(p for i in report.investigations for p in i.problems)
    assert all(not i.verified for i in report.investigations)
    assert "근거 호출이 없는 사실" in problems and "T9" in problems
    assert "X:-:y" in problems and "MASKED_NAME_99" in problems


def test_no_result_and_llm_errors_are_failures(context: ToolContext) -> None:
    def script(payload: dict[str, Any], tools: dict[str, AgentTool]) -> Any:
        return None if payload["rule"]["id"] == "S3-003" else LLMError("거부됨")

    report, _ = _run(context, script)
    assert report.investigations == ()
    errors = {f.rule_id: f.error for f in report.failures}
    assert "max_iterations" in errors["S3-003"] and errors["IAM-008"] == "거부됨"


def test_guard_violation_stops_everything(
    context: ToolContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bad(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
        ctx.client("s3").create_bucket(Bucket="x")
        return ToolResult({})

    monkeypatch.setitem(
        agent_tools.TOOLS_BY_NAME,
        "s3_account_public_access_block",
        Tool("s3_account_public_access_block", "d", {"type": "object"}, bad),
    )
    with pytest.raises(ReadOnlyViolation):
        _run(context, _good)


def test_usage_and_metadata(context: ToolContext) -> None:
    _bucket()
    report, _ = _run(context, _good)
    assert report.usage.input_tokens == 2000 and report.model == "fake-agent"
    assert report.estimated_cost_usd is None  # 단가를 모르는 모델
    assert report.findings_evaluated_at == _report().evaluation.evaluated_at


# --- 판정 불변 (원칙 1, PLAN 4단계 항목) ---


def _property_names(schema: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(schema, dict):
        names |= set(schema.get("properties", {}))
        for value in schema.values():
            names |= _property_names(value)
    elif isinstance(schema, list):
        for value in schema:
            names |= _property_names(value)
    return names


def test_agent_output_schema_has_no_status() -> None:
    # 에이전트가 판정을 바꿀 수 있는 통로(응답 필드)가 없다
    for model in (InvestigationDraft, Investigation):
        names = _property_names(model.model_json_schema())
        assert "status" not in names and "severity" not in names


def test_investigation_does_not_modify_findings(context: ToolContext) -> None:
    _bucket()
    report = _report()
    before = report.model_dump()
    investigate_report(report, ScriptedAgent(_good), context, effort="high")
    assert report.model_dump() == before
    with pytest.raises(ValidationError):  # Finding은 동결 모델이다
        report.findings[0].status = Status.PASS  # type: ignore[misc]
