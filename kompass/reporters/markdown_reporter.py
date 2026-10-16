"""Markdown 보고서. 사람이 읽는 점검 결과 요약이며, 전체 증적은 JSON 보고서에 있다."""

import re
from collections import Counter

import yaml

from kompass.models import AuditReport, Finding, Investigation, ItemOutcome, RuleExplanation
from kompass.reporters._format import (
    ACTION_STATUSES,
    DISCLAIMER,
    EXPLANATION_NOTICE,
    INVESTIGATION_NOTICE,
    OUTCOME_LABELS,
    PRIORITY_LABELS,
    RULE_TITLES,
    SCHEME_LABELS,
    STATUS_LABELS,
    STATUS_ORDER,
    compact_json,
    explanation_summary,
    investigation_summary,
    kst,
)


def _cell(value: object) -> str:
    """표 칸 안에서 Markdown 표를 깨뜨리는 문자를 이스케이프한다."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _row(*cells: object) -> str:
    return "| " + " | ".join(_cell(c) for c in cells) + " |"


def _finding_rows(findings: list[Finding]) -> list[str]:
    rows = [_row("룰", "결과", "리소스", "리전", "내용", "핵심 증적"), "|---|---|---|---|---|---|"]
    rows += [
        _row(
            f.rule_id,
            STATUS_LABELS[f.status],
            f.resource,
            f.region or "-",
            f.message,
            compact_json(f.evidence),
        )
        for f in findings
    ]
    return rows


def _excluded_notice(report: AuditReport) -> list[str]:
    excluded = report.scan.excluded_regions
    if not excluded:
        return []
    lines = [
        f"> **점검 범위 밖 리전 {len(excluded)}개**: 리전 전체가 접근 거부되어(SCP 리전 제한 등) "
        "EC2·VPC를 점검하지 않음. 이 리전의 리소스는 양호가 아니라 확인하지 않은 것임. "
        "예외 권한으로 만든 리소스가 있을 수 있으므로 필요 시 해당 리전 권한으로 재점검 필요.",
        "",
    ]
    lines += [f"- {_cell(region)}: {_cell(reason)}" for region, reason in excluded.items()]
    return [*lines, ""]


def _text(value: str) -> str:
    """LLM이 쓴 문장을 본문에 넣는다. 줄바꿈을 접어 제목·목록을 만들지 못하게 하고 HTML은 막는다."""
    collapsed = " ".join(value.split())
    return collapsed.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _labeled(label: str, value: str) -> list[str]:
    """LLM이 여러 줄(개조식 목록)로 쓴 값은 하위 목록으로, 한 줄이면 그대로 붙인다."""
    items = [line.strip().lstrip("-•·*").strip() for line in value.splitlines()]
    items = [item for item in items if item]
    if len(items) <= 1:
        return [f"- {label}: {_text(items[0] if items else '')}"]
    return [f"- {label}:", *(f"  - {_list_item(item)}" for item in items)]


def _list_item(value: str) -> str:
    text = _text(value)
    # 목록 항목 맨 앞의 "#"은 제목으로 렌더링되므로 이스케이프한다
    return "\\" + text if text.startswith("#") else text


def _code_block(language: str, body: str) -> list[str]:
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}{language}", body, fence]


def _explanation_rule(item: RuleExplanation) -> list[str]:
    draft = item.explanation
    rule = RULE_TITLES.get(item.rule_id, "")
    label = "원문 인용 검증됨" if item.verified else "검증되지 않음"
    lines = [
        f"### {item.rule_id} {_text(rule)} — 우선순위 {PRIORITY_LABELS[draft.priority]} · {label}",
        "",
        f"대상 finding {len(item.finding_keys)}건, 모델 {item.model}"
        + (" (거부되어 대체 모델이 답함)" if item.fallback_used else ""),
        "",
        *_labeled("요약", draft.summary),
        *_labeled("위험", draft.risk),
        *_labeled("우선순위 근거", draft.priority_reason),
        "",
        "근거 인용:",
        "",
    ]
    lines += [
        f'- {SCHEME_LABELS[c.scheme]} {_text(c.code)}: "{_text(c.quote)}"' for c in draft.citations
    ] or ["- 없음"]
    if item.problems:
        lines += ["", "검증 문제 (인용을 그대로 믿지 않음):", ""]
        lines += [f"- {_text(p)}" for p in item.problems]
    lines += ["", "조치 절차:", ""]
    lines += [f"{n}. {_text(step)}" for n, step in enumerate(draft.remediation.steps, start=1)]
    if draft.remediation.aws_cli:
        lines += [
            "",
            "AWS CLI (실행 전 검토):",
            "",
            *_code_block("bash", "\n".join(draft.remediation.aws_cli)),
        ]
    if draft.remediation.terraform:
        lines += ["", "Terraform:", "", *_code_block("hcl", draft.remediation.terraform)]
    if draft.resource_notes:
        lines += ["", "리소스별 메모:", ""]
        lines += [
            f"- `{n.finding_key.replace('`', '')}`: {_text(n.note)}" for n in draft.resource_notes
        ]
    return [*lines, ""]


def _assessment_section(report: AuditReport) -> list[str]:
    explained = report.explanations
    if explained is None:
        return []
    if explained.assessment is None:
        if explained.assessment_failure:
            return [
                "### 종합 위험 평가",
                "",
                f"- 만들지 못함: {_text(explained.assessment_failure)}",
                "",
            ]
        return []
    item = explained.assessment
    draft = item.assessment
    label = "참조 검증됨" if item.verified else "검증되지 않음"
    lines = [
        "### 종합 위험 평가 — " + label,
        "",
        *_labeled("요약", draft.summary),
        "",
        "위험 시나리오:",
        "",
    ]
    for scenario in draft.scenarios:
        keys = ", ".join(f"`{k.replace('`', '')}`" for k in scenario.finding_keys)
        heading = f"- **{_text(scenario.title)}** (영향 {PRIORITY_LABELS[scenario.impact]})"
        # 여러 줄(개조식 목록) 설명은 하위 목록으로, 한 줄이면 제목 뒤에 붙인다
        [first, *rest] = _labeled("", scenario.description)
        if rest:
            lines += [f"{heading}:", *rest]
        else:
            lines.append(f"{heading}: {first.removeprefix('- : ')}")
        lines.append(f"  - 관련 finding: {keys}")
    lines += ["", "조치 순서:", ""]
    for n, step in enumerate(draft.action_order, start=1):
        title = _text(RULE_TITLES.get(step.rule_id, ""))
        lines.append(f"{n}. {_text(step.rule_id)} {title} — {_text(step.reason)}")
    if item.problems:
        lines += ["", "검증 문제:", ""] + [f"- {_text(p)}" for p in item.problems]
    return [*lines, ""]


def _explanation_section(report: AuditReport) -> list[str]:
    explained = report.explanations
    if explained is None:
        return []
    cost = (
        f", 예상 비용 약 ${explained.estimated_cost_usd:.2f}"
        if explained.estimated_cost_usd is not None
        else ""
    )
    lines = [
        "",
        "## AI 해설 (참고)",
        "",
        f"> {EXPLANATION_NOTICE}",
        "",
        f"생성 {kst(explained.generated_at)}, 모델 {explained.model} (effort {explained.effort}), "
        f"토큰 입력 {explained.usage.input_tokens:,} · "
        f"출력 {explained.usage.output_tokens:,}{cost}",
        "",
    ]
    lines += _assessment_section(report)
    for item in explained.explanations:
        lines += _explanation_rule(item)
    if explained.failures:
        lines += ["### 해설하지 못한 룰", ""]
        lines += [f"- {f.rule_id}: {_text(f.error)}" for f in explained.failures]
    return lines


def _investigation_rule(item: Investigation) -> list[str]:
    draft = item.investigation
    rule = RULE_TITLES.get(item.rule_id, "")
    label = "근거 검증됨" if item.verified else "검증되지 않음"
    lines = [
        f"### {item.rule_id} {_text(rule)} — {label}",
        "",
        f"대상 finding {len(item.finding_keys)}건, 도구 호출 {len(item.tool_calls)}회, "
        f"모델 {item.model}, 종료 {item.stop}",
        "",
        *_labeled("요약", draft.summary),
        "",
        "확인된 사실:",
        "",
    ]
    lines += [
        f"- {_text(fact.statement)} (근거: {', '.join(_text(c) for c in fact.call_ids) or '없음'})"
        for fact in draft.facts
    ] or ["- 없음"]
    if draft.open_questions:
        lines += ["", "사람이 확인할 질문:", ""]
        lines += [f"- {_list_item(q)}" for q in draft.open_questions]
    if draft.finding_notes:
        lines += ["", "finding별 메모:", ""]
        lines += [
            f"- `{n.finding_key.replace('`', '')}`: {_text(n.note)}" for n in draft.finding_notes
        ]
    if item.problems:
        lines += ["", "검증 문제:", ""] + [f"- {_text(p)}" for p in item.problems]
    if item.tool_calls:
        lines += ["", "도구 호출:", "", _row("호출", "도구", "입력", "결과"), "|---|---|---|---|"]
        lines += [
            _row(
                c.call_id,
                c.tool,
                compact_json(c.input_raw),
                f"오류: {c.error}" if c.error else "정상",
            )
            for c in item.tool_calls
        ]
    return [*lines, ""]


def _investigation_section(report: AuditReport) -> list[str]:
    investigated = report.investigations
    if investigated is None:
        return []
    cost = (
        f", 예상 비용 약 ${investigated.estimated_cost_usd:.2f}"
        if investigated.estimated_cost_usd is not None
        else ""
    )
    lines = [
        "",
        "## 추가 조사 (참고)",
        "",
        f"> {INVESTIGATION_NOTICE}",
        "",
        f"생성 {kst(investigated.generated_at)}, 모델 {investigated.model} "
        f"(effort {investigated.effort}), 토큰 입력 {investigated.usage.input_tokens:,} · "
        f"출력 {investigated.usage.output_tokens:,}{cost}",
        "",
    ]
    for item in investigated.investigations:
        lines += _investigation_rule(item)
    if investigated.failures:
        lines += ["### 조사하지 못한 룰", ""]
        lines += [f"- {f.rule_id}: {_text(f.error)}" for f in investigated.failures]
    return lines


def render_markdown(report: AuditReport) -> str:
    scan, evaluation = report.scan, report.evaluation
    lines: list[str] = [
        f"# kompass 점검 보고서 — {scan.account_id}",
        "",
        f"> {DISCLAIMER}",
        "",
        "## 점검 정보",
        "",
        "| 항목 | 값 |",
        "|---|---|",
        _row("계정", f"{scan.account_id} ({scan.partition})"),
        _row("점검 수행 주체", scan.caller_arn),
        _row("점검 리전 (EC2·VPC)", ", ".join(scan.regions)),
        _row(
            "점검 제외 리전 (접근 거부)",
            ", ".join(scan.excluded_regions) or "없음",
        ),
        _row("점검 ID", scan.scan_id),
        _row("수집 시각", f"{kst(scan.started_at)} ~ {kst(scan.finished_at)}"),
        _row("판정 시각", kst(evaluation.evaluated_at)),
        _row("보고서 생성", kst(report.generated_at)),
        _row("kompass 버전", evaluation.kompass_version),
        _row("매핑 데이터", report.mapping_digest[:12]),
        _row("AI 해설", explanation_summary(report)),
        _row("추가 조사", investigation_summary(report)),
        "",
        *_excluded_notice(report),
        "판정 기준값 (kompass.yaml 형식):",
        "",
        "```yaml",
        yaml.safe_dump(
            evaluation.settings, allow_unicode=True, sort_keys=False, default_flow_style=None
        ).rstrip(),
        "```",
        "",
    ]

    item_counts = Counter(i.outcome for i in report.kisa_items)
    finding_counts = Counter(f.status for f in report.findings)
    lines += [
        "## 요약",
        "",
        "KISA 항목 (19개): "
        + ", ".join(f"{OUTCOME_LABELS[o]} {item_counts.get(o, 0)}" for o in ItemOutcome),
        "",
        "finding: "
        + ", ".join(f"{STATUS_LABELS[s]} {finding_counts.get(s, 0)}" for s in STATUS_ORDER),
        "",
        "## KISA 항목별 결과",
        "",
        "2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 XII. 클라우드 기준. "
        "partial 항목은 자동 점검만으로 양호가 되지 않음.",
        "",
        "| 코드 | 항목 | 중요도 | 분류 | 결과 | 룰 | finding |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in report.kisa_items:
        counts = ", ".join(f"{k} {v}" for k, v in sorted(item.status_counts.items()))
        lines.append(
            _row(
                item.code,
                item.title,
                item.importance,
                item.automation.value,
                OUTCOME_LABELS[item.outcome],
                ", ".join(item.rule_ids) or "-",
                counts or "-",
            )
        )

    lines += ["", "## 조치가 필요한 결과", ""]
    actionable = [
        f for f in report.findings if f.status in ACTION_STATUSES and f.mappings and f.mappings.kisa
    ]
    if not actionable:
        lines.append("조치가 필요한 결과가 없음.")
    for item in report.kisa_items:
        selected = [f for f in actionable if f.mappings and item.code in f.mappings.kisa]
        if selected:
            lines += ["", f"### {item.code} {item.title} ({item.importance})", ""]
            lines += _finding_rows(selected)

    unmapped = [f for f in report.findings if not (f.mappings and f.mappings.kisa)]
    lines += ["", "## KISA 대응 항목이 없는 룰", ""]
    if unmapped:
        unmapped_counts = Counter((f.rule_id, f.status) for f in unmapped)
        lines.append(
            "결과 개수: "
            + ", ".join(
                f"{rule} {STATUS_LABELS[st]} {n}"
                for (rule, st), n in sorted(unmapped_counts.items())
            )
        )
        flagged = [f for f in unmapped if f.status in ACTION_STATUSES]
        if flagged:
            lines += ["", *_finding_rows(flagged)]
    else:
        lines.append("결과가 없음.")

    lines += _explanation_section(report)
    lines += _investigation_section(report)

    related = [c for c in report.isms_p_controls if c.outcome != ItemOutcome.NOT_IMPLEMENTED]
    out_of_scope = len(report.isms_p_controls) - len(related)
    lines += [
        "",
        "## ISMS-P 통제항목 (초안)",
        "",
        "자동 점검 결과는 통제항목 충족 여부의 참고 증적임. 관리 절차를 포함하므로 자동으로 "
        "양호가 되지 않음. 매핑은 원문 검증 전 초안임.",
        "",
        "| 번호 | 통제항목 | 결과 | KISA 항목 | 룰 |",
        "|---|---|---|---|---|",
    ]
    lines += [
        _row(
            c.code,
            c.name,
            OUTCOME_LABELS[c.outcome],
            ", ".join(c.kisa_items) or "-",
            ", ".join(c.rule_ids),
        )
        for c in related
    ]
    lines += ["", f"자동 점검 범위 밖: {out_of_scope}개 (관리 절차·물리 보안·개인정보 처리 등)"]

    lines += ["", "## 건너뛴 룰", ""]
    lines.append(
        "스냅샷이 없어 실행하지 않은 룰 (양호가 아님): " + ", ".join(evaluation.skipped_rules)
        if evaluation.skipped_rules
        else "없음."
    )
    return "\n".join(lines) + "\n"
