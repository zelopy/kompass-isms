"""Markdown 보고서. 사람이 읽는 점검 결과 요약이며, 전체 증적은 JSON 보고서에 있다."""

from collections import Counter

import yaml

from kompass.models import AuditReport, Finding, ItemOutcome
from kompass.reporters._format import (
    ACTION_STATUSES,
    DISCLAIMER,
    OUTCOME_LABELS,
    STATUS_LABELS,
    STATUS_ORDER,
    compact_json,
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
        _row("점검 ID", scan.scan_id),
        _row("수집 시각", f"{kst(scan.started_at)} ~ {kst(scan.finished_at)}"),
        _row("판정 시각", kst(evaluation.evaluated_at)),
        _row("보고서 생성", kst(report.generated_at)),
        _row("kompass 버전", evaluation.kompass_version),
        _row("매핑 데이터", report.mapping_digest[:12]),
        "",
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
        "partial 항목은 자동 점검만으로 양호가 되지 않는다.",
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
        lines.append("조치가 필요한 결과가 없다.")
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
        lines.append("결과가 없다.")

    related = [c for c in report.isms_p_controls if c.outcome != ItemOutcome.NOT_IMPLEMENTED]
    out_of_scope = len(report.isms_p_controls) - len(related)
    lines += [
        "",
        "## ISMS-P 통제항목 (초안)",
        "",
        "자동 점검 결과는 통제항목 충족 여부의 참고 증적이다. 관리 절차를 포함하므로 자동으로 "
        "양호가 되지 않는다. 매핑은 원문 검증 전 초안이다.",
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
        "스냅샷이 없어 실행하지 않은 룰 (양호가 아니다): " + ", ".join(evaluation.skipped_rules)
        if evaluation.skipped_rules
        else "없다."
    )
    return "\n".join(lines) + "\n"
