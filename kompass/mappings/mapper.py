"""매퍼: 판정 결과에 매핑을 붙이고 KISA 항목·ISMS-P 통제항목 단위로 집계한다 (ADR-025).

status는 바꾸지 않는다 (ADR-001). 집계 규칙:
- KISA 항목: 담당 룰이 없으면 NOT_IMPLEMENTED(수동 점검). 담당 룰 중 건너뛴 것이 있으면
  확정된 FAIL이 있을 때만 FAIL, 아니면 NOT_EVALUATED. 그 밖에는 `aggregate_status`로 집계하며
  partial 항목은 자동으로 양호가 되지 않는다 (ADR-009, ADR-013).
- ISMS-P 통제항목: 관련 룰이 없으면 NOT_IMPLEMENTED(자동 점검 범위 밖). 있으면 항상 partial로
  집계한다. ISMS-P 통제는 관리 절차까지 포함하므로 자동 점검 결과는 참고 증적이다.
"""

from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime

from kompass.mappings.data import MappingData
from kompass.models import (
    AuditReport,
    Automation,
    EvaluationReport,
    Finding,
    IsmsPControlResult,
    ItemOutcome,
    KisaItemResult,
    Mappings,
    ScanManifest,
    Status,
    aggregate_status,
)


def _sort_key(code: str) -> list[int]:
    return [int(part) for part in code.replace("CA-", "").split(".")]


def _outcome(
    rule_ids: Iterable[str],
    findings_by_rule: dict[str, list[Finding]],
    skipped: set[str],
    automation: Automation,
) -> ItemOutcome:
    rules = list(rule_ids)
    if not rules:
        return ItemOutcome.NOT_IMPLEMENTED
    statuses = [f.status for rule in rules for f in findings_by_rule.get(rule, [])]
    if skipped & set(rules) or not statuses:
        return ItemOutcome.FAIL if Status.FAIL in statuses else ItemOutcome.NOT_EVALUATED
    return ItemOutcome(aggregate_status(statuses, automation).value)


def build_report(
    manifest: ScanManifest, evaluation: EvaluationReport, mappings: MappingData
) -> AuditReport:
    findings = tuple(
        f.with_mappings(
            Mappings(
                kisa=mappings.rules[f.rule_id].kisa,
                isms_p=mappings.rules[f.rule_id].isms_p,
                kisa_verified=mappings.rules[f.rule_id].kisa_verified,
                isms_p_verified=mappings.rules[f.rule_id].isms_p_verified,
            )
        )
        for f in evaluation.findings
    )
    by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)
    skipped = set(evaluation.skipped_rules)

    items: list[KisaItemResult] = []
    for code in sorted(mappings.kisa_items, key=_sort_key):
        item = mappings.kisa_items[code]
        rule_ids = tuple(mappings.rules_for_item(code))
        counts = Counter(f.status.value for r in rule_ids for f in by_rule.get(r, []))
        items.append(
            KisaItemResult(
                code=code,
                title=item.title,
                importance=item.importance,
                page=item.page,
                automation=item.automation,
                outcome=_outcome(rule_ids, by_rule, skipped, item.automation),
                rule_ids=rule_ids,
                status_counts=dict(counts),
                isms_p=item.isms_p,
            )
        )

    controls: list[IsmsPControlResult] = []
    for code in sorted(mappings.isms_p_controls, key=_sort_key):
        rule_ids = tuple(r for r, m in mappings.rules.items() if code in m.isms_p)
        kisa = tuple(c for c, i in mappings.kisa_items.items() if code in i.isms_p)
        controls.append(
            IsmsPControlResult(
                code=code,
                name=mappings.isms_p_controls[code],
                outcome=_outcome(rule_ids, by_rule, skipped, Automation.PARTIAL),
                kisa_items=kisa,
                rule_ids=rule_ids,
            )
        )

    return AuditReport(
        scan=manifest,
        evaluation=evaluation,
        mapping_digest=mappings.digest,
        generated_at=datetime.now(UTC),
        kisa_items=tuple(items),
        isms_p_controls=tuple(controls),
        findings=findings,
    )
