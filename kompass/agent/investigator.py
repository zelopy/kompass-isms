"""추가 조사: 1차 판정의 FAIL·REVIEW finding을 룰 단위로 에이전트가 더 조사한다 (ADR-035).

흐름 (룰 하나마다):
1. FAIL·REVIEW finding을 모은다 (ERROR는 같은 권한 거부가 되풀이될 뿐이라 조사하지 않는다).
2. finding을 마스킹하고 룰별 조사 힌트를 붙여 과제를 만든다. 전송 직전 검사를 거친다.
3. 에이전트가 읽기 전용 도구(마스킹 다리·예산·호출 기록)로 조사하고 구조화된 결과를 낸다.
4. 결과를 검증한다: 사실마다 실제 도구 호출 ID를 근거로 가리키는가, 모르는 finding 키나
   지어낸 자리표시자가 없는가. 에이전트를 다시 돌리면 도구 호출까지 되풀이되므로 재시도하지
   않고 "검증되지 않음"으로 남긴다.
5. 마스킹을 복원해 저장한다. 판정(status)은 바꾸지 않는다 (원칙 1).

읽기 전용 가드 위반은 도구의 버그이므로 조사 전체를 멈춘다.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any

from kompass.agent.llm import AgentProvider
from kompass.agent.toolbox import DEFAULT_MAX_CALLS, InvestigationToolbox
from kompass.agent.tools import ToolContext
from kompass.interpreter.explainer import RuleGroup, report_names, select_groups
from kompass.interpreter.llm import LLMError, Usage, estimate_cost
from kompass.interpreter.masking import Masker, MaskingError
from kompass.models import (
    AuditReport,
    Finding,
    Investigation,
    InvestigationDraft,
    InvestigationFailure,
    InvestigationReport,
    Status,
    TokenUsage,
)
from kompass.rules.base import ACCOUNT_RESOURCE
from kompass.rules.registry import RULES

SYSTEM_PROMPT = (
    files("kompass.agent").joinpath("investigate_system.txt").read_text(encoding="utf-8").strip()
)
INVESTIGATE = frozenset({Status.FAIL, Status.REVIEW})
MAX_FINDINGS_PER_TASK = 20
DEFAULT_MAX_ITERATIONS = 12
DEFAULT_MAX_TOTAL_TOKENS = 200_000
_TITLES = {rule.id: rule.title for rule in RULES}

# 룰별 조사 힌트: 판정을 넘어 사람이 판단할 근거가 되는 조회
RULE_HINTS: dict[str, str] = {
    "CT-001": "추적 목록과 기록 범위, 최근 StopLogging·DeleteTrail·UpdateTrail 이벤트",
    "IAM-001": "루트 계정 최근 사용 이벤트(us-east-1, Username=root)",
    "IAM-002": "루트 계정 최근 사용 이벤트(us-east-1, Username=root)",
    "IAM-003": "사용자의 콘솔 비밀번호·MFA·최근 사용, 연결된 권한(관리자 여부)",
    "IAM-004": "비밀번호 정책은 계정 단위라 추가 조회가 적음. 콘솔 사용자 현황 확인",
    "IAM-005": "사용자의 액세스 키·비밀번호 마지막 사용, 연결된 권한",
    "IAM-006": "액세스 키의 마지막 사용 시각·서비스, 사용자 권한",
    "IAM-007": "사용자 정책·그룹 정책·인라인 정책 문서, "
    "정책 평가 시뮬레이션으로 실제 관리자 권한 여부",
    "IAM-008": "루트 계정 최근 사용 이벤트(us-east-1, Username=root)",
    "IAM-009": "외부 자격증명 공급자로 들어오는 역할의 권한, 관련 AssumeRoleWith* 이벤트",
    "S3-001": "계정 수준 차단 상태와 퍼블릭 정책·ACL이 있는 버킷",
    "S3-002": "버킷 정책·ACL이 실제로 공개하는지, 버킷 차단 설정",
    "S3-003": "버킷 정책 전문과 공개 조건, 차단 설정, 데이터 이벤트 기록 여부, 정책 변경 이력"
    "(ResourceName=버킷)",
    "S3-004": "버킷 접근 설정(공개 여부와 함께 위험도 판단)",
    "S3-005": "버킷 공개 여부, CloudTrail 데이터 이벤트로 대체 기록되는지",
    "S3-006": "ACL 부여 내역과 객체 소유권, 차단 설정, ACL 변경 이력(ResourceName=버킷)",
    "SG-001": "보안그룹이 연결된 인터페이스·인스턴스와 공인 IP, 서브넷의 인터넷 게이트웨이 경로",
    "SG-002": "보안그룹이 연결된 인터페이스·인스턴스와 공인 IP, 서브넷의 인터넷 게이트웨이 경로",
    "SG-003": "보안그룹이 연결된 인터페이스(데이터베이스 등)와 공인 IP, 서브넷 경로",
    "SG-004": "기본 보안그룹 규칙과 연결된 인터페이스·인스턴스",
    "VPC-001": "서브넷 라우팅(인터넷 게이트웨이·NAT), 인터페이스의 공인 IP·보안그룹",
    "VPC-002": "인터페이스의 인스턴스·보안그룹 규칙·서브넷 경로",
    "VPC-003": "VPC의 인터페이스·서브넷 구성, 흐름 로그 변경 이력(DeleteFlowLogs·CreateFlowLogs)",
    "S3-007": "버킷 정책 문서(HTTPS 강제 문장 유무), 정책 변경 이력(PutBucketPolicy 이벤트)",
    "CT-002": "추적 버킷의 수명주기 변경 이력(PutBucketLifecycle 이벤트), 로그 백업 여부",
    "LOG-001": "로그 그룹 보존 기간 변경 이력(PutRetentionPolicy·DeleteRetentionPolicy 이벤트)",
    "GD-001": "탐지기 생성·삭제·변경 이력(CreateDetector·DeleteDetector·UpdateDetector 이벤트)",
    "GD-002": "EventBridge 규칙 변경 이력(PutRule·DeleteRule·RemoveTargets 이벤트)",
    "IAM-010": "정책 평가 시뮬레이션으로 인스턴스 생성·접속 작업의 실제 허용 여부, 권한 부여 이력",
    "IAM-011": "정책 평가 시뮬레이션으로 보안그룹·라우팅 변경의 실제 허용 여부, 권한 부여 이력",
    "RDS-001": "데이터베이스 생성·수정 이력(CreateDBInstance·ModifyDBInstance 이벤트)",
    "RDS-002": "연결된 보안그룹 규칙과 서브넷 경로(인터넷 게이트웨이 여부), 공개 설정 변경 이력",
    "RDS-003": "데이터베이스 설정 변경 이력(ModifyDBInstance·ModifyDBCluster 이벤트)",
    "RDS-004": "백업 설정 변경 이력(ModifyDBInstance·ModifyDBCluster 이벤트)",
    "RDS-005": "파라미터 그룹 변경 이력(ModifyDBParameterGroup·ModifyDBClusterParameterGroup "
    "이벤트), 데이터베이스에 연결된 파라미터 그룹 변경(ModifyDBInstance·ModifyDBCluster)",
    "ELB-001": "리스너·규칙 변경 이력(CreateListener·ModifyListener·CreateRule·ModifyRule 이벤트), "
    "TCP 리스너의 대상 그룹 프로토콜·포트",
    "ELB-002": "리스너 보안 정책 변경 이력(ModifyListener·"
    "SetLoadBalancerPoliciesOfListener 이벤트)",
}


@dataclass(frozen=True)
class PreparedInvestigation:
    masker: Masker
    task: str
    finding_keys: frozenset[str]  # 마스킹된 키
    resources: tuple[str, ...]  # 원본 리소스 값 (결과에 그대로 남으면 안 된다)


def investigation_groups(report: AuditReport) -> list[RuleGroup]:
    groups = []
    for group in select_groups(report):
        findings = tuple(f for f in group.findings if f.status in INVESTIGATE)
        if findings:
            groups.append(RuleGroup(group.rule_id, findings))
    return groups


def prepare_investigation(group: RuleGroup, names: tuple[str, ...]) -> PreparedInvestigation:
    shown = group.findings[:MAX_FINDINGS_PER_TASK]
    masker = Masker(names)
    masked: list[dict[str, Any]] = masker.mask([_raw(f) for f in shown])
    payload = {
        "rule": {"id": group.rule_id, "title": _TITLES.get(group.rule_id, group.rule_id)},
        "hint": RULE_HINTS.get(group.rule_id, ""),
        "findings": masked,
        "omitted_findings": len(group.findings) - len(shown),
    }
    body = json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True)
    resources = tuple(f.resource for f in group.findings if f.resource != ACCOUNT_RESOURCE)
    masker.require_clean(body, resources)
    return PreparedInvestigation(
        masker=masker,
        task=f"다음 룰의 finding을 도구로 추가 조사한다.\n\n```json\n{body}\n```",
        finding_keys=frozenset(item["key"] for item in masked),
        resources=resources,
    )


def check_investigation(
    draft: InvestigationDraft, prepared: PreparedInvestigation, call_ids: set[str]
) -> list[str]:
    problems: list[str] = []
    if not draft.facts and not draft.open_questions:
        problems.append("확인한 사실도 사람이 확인할 질문도 없음")
    for fact in draft.facts:
        if not fact.call_ids:
            problems.append(f"근거 호출이 없는 사실: {fact.statement}")
        unknown = [c for c in fact.call_ids if c not in call_ids]
        if unknown:
            problems.append(f"없는 도구 호출을 근거로 든 사실: {', '.join(unknown)}")
    for note in draft.finding_notes:
        if note.finding_key not in prepared.finding_keys:
            problems.append(f"findings에 없는 finding_key: {note.finding_key}")
    invented = prepared.masker.unknown_tokens(draft.model_dump_json())
    if invented:
        problems.append(f"주어지지 않은 자리표시자: {', '.join(sorted(invented))}")
    return problems


def investigate_report(
    report: AuditReport,
    provider: AgentProvider,
    context: ToolContext,
    *,
    effort: str,
    max_calls: int = DEFAULT_MAX_CALLS,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS,
    on_progress: Callable[[str], None] | None = None,
) -> InvestigationReport:
    names = report_names(report)
    investigations: list[Investigation] = []
    failures: list[InvestigationFailure] = []
    total = Usage(0, 0, 0, 0)
    cost: float | None = 0.0
    for group in investigation_groups(report):
        if on_progress:
            on_progress(group.rule_id)
        keys = tuple(f.key for f in group.findings)
        try:
            prepared = prepare_investigation(group, names)
            toolbox = InvestigationToolbox(
                context, prepared.masker, prepared.resources, max_calls=max_calls
            )
            run = provider.run(
                SYSTEM_PROMPT,
                prepared.task,
                toolbox.agent_tools(),
                InvestigationDraft,
                max_iterations=max_iterations,
                max_total_tokens=max_total_tokens,
            )
        except (LLMError, MaskingError) as exc:
            failures.append(
                InvestigationFailure(rule_id=group.rule_id, finding_keys=keys, error=str(exc))
            )
            continue
        if toolbox.violation is not None:
            raise toolbox.violation  # 도구의 버그. 조사 전체를 멈춘다
        total = total + run.usage
        call_cost = estimate_cost(run.model, run.usage)
        cost = None if cost is None or call_cost is None else cost + call_cost
        if run.parsed is None:
            failures.append(
                InvestigationFailure(
                    rule_id=group.rule_id,
                    finding_keys=keys,
                    error=f"조사 결과 없음 (종료 사유: {run.stop})",
                )
            )
            continue
        problems = check_investigation(run.parsed, prepared, {c.call_id for c in toolbox.calls})
        masker = prepared.masker
        investigations.append(
            Investigation(
                rule_id=group.rule_id,
                finding_keys=keys,
                investigation=InvestigationDraft.model_validate(
                    masker.unmask(run.parsed.model_dump(mode="json"))
                ),
                verified=not problems,
                problems=tuple(masker.unmask_text(p) for p in problems),
                tool_calls=tuple(toolbox.calls),
                model=run.model,
                iterations=run.iterations,
                stop=run.stop,
                usage=_token_usage(run.usage),
            )
        )
    return InvestigationReport(
        scan_id=report.scan.scan_id,
        account_id=report.scan.account_id,
        findings_evaluated_at=report.evaluation.evaluated_at,
        generated_at=datetime.now(UTC),
        model=provider.model,
        effort=effort,
        investigations=tuple(investigations),
        failures=tuple(failures),
        usage=_token_usage(total),
        estimated_cost_usd=cost,
    )


def _raw(finding: Finding) -> dict[str, Any]:
    return {
        "key": finding.key,
        "resource": finding.resource,
        "region": finding.region,
        "status": finding.status.value,
        "message": finding.message,
        "evidence": finding.evidence,
    }


def _token_usage(usage: Usage) -> TokenUsage:
    return TokenUsage(
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        cache_read_input_tokens=usage.cache_read_input_tokens,
        cache_write_input_tokens=usage.cache_write_input_tokens,
    )
