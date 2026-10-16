"""매퍼: 판정 결과에 매핑을 붙이고 KISA 항목·ISMS-P 통제항목 단위로 집계한다 (ADR-025).

status는 바꾸지 않는다 (ADR-001). 집계 규칙:
- KISA 항목: 담당 룰이 없으면 NOT_IMPLEMENTED(수동 점검). 담당 룰 중 건너뛴 것이 있으면
  확정된 FAIL이 있을 때만 FAIL, 아니면 NOT_EVALUATED. 그 밖에는 `aggregate_status`로 집계하며
  partial 항목은 자동으로 양호가 되지 않는다 (ADR-009, ADR-013).
- ISMS-P 통제항목: 관련 룰이 없으면 NOT_IMPLEMENTED(자동 점검 범위 밖). 있으면 항상 partial로
  집계한다. ISMS-P 통제는 관리 절차까지 포함하므로 자동 점검 결과는 참고 증적이다.
- 증적 요청 목록 (ADR-037): partial·manual 항목은 항상, full 항목은 결과가 자동으로 확정되지
  않았거나 검토 필요·확인 불가 finding이 있을 때만 넣는다. 그 finding을 확인 대상으로 붙인다.
"""

from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime

from kompass.mappings.data import MappingData
from kompass.models import (
    AuditReport,
    Automation,
    EvaluationReport,
    EvidenceRequestGroup,
    EvidenceTarget,
    Finding,
    IsmsPControlResult,
    ItemOutcome,
    KisaItemResult,
    Mappings,
    ScanManifest,
    Status,
    aggregate_status,
)

# full 항목이라도 이 결과면 자동 판정이 확정되지 않아 사람의 확인이 필요하다
_UNSETTLED = frozenset(
    {
        ItemOutcome.REVIEW,
        ItemOutcome.ERROR,
        ItemOutcome.NOT_EVALUATED,
        ItemOutcome.NOT_IMPLEMENTED,
    }
)
_TARGET_STATUSES = frozenset({Status.REVIEW, Status.ERROR})


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


def _evidence_reason(item: KisaItemResult, has_targets: bool) -> str:
    if item.outcome == ItemOutcome.NOT_IMPLEMENTED:
        return "자동 점검 룰 없음. 판단 기준 전체를 담당자 확인으로 판단해야 함"
    if item.outcome in (ItemOutcome.ERROR, ItemOutcome.NOT_EVALUATED):
        return "수집 실패 또는 미점검으로 자동 판정이 확정되지 않음. 담당자 확인 필요"
    if item.automation == Automation.FULL and item.outcome == ItemOutcome.FAIL and has_targets:
        return "취약 판정과 별도로 검토 필요·확인 불가 결과 있음. 해당 리소스 담당자 확인 필요"
    if item.automation == Automation.FULL:
        return "자동 점검 결과에 검토 필요 항목 있음. 담당자 확인 필요"
    return "자동 점검은 명백한 취약만 판정함. 판단 기준의 나머지 조건은 담당자 확인 필요"


def _evidence_requests(
    items: Iterable[KisaItemResult], by_rule: dict[str, list[Finding]], mappings: MappingData
) -> tuple[EvidenceRequestGroup, ...]:
    groups: list[EvidenceRequestGroup] = []
    for item in items:
        targets = tuple(
            EvidenceTarget(
                finding_key=f.key,
                rule_id=f.rule_id,
                resource=f.resource,
                region=f.region,
                status=f.status,
                message=f.message,
            )
            for rule_id in item.rule_ids
            for f in by_rule.get(rule_id, [])
            if f.status in _TARGET_STATUSES
        )
        # full 항목은 결과가 확정됐고 사람이 확인할 finding도 없으면 증적이 필요 없다
        if item.automation == Automation.FULL and item.outcome not in _UNSETTLED and not targets:
            continue
        catalog = mappings.evidence[item.code]
        groups.append(
            EvidenceRequestGroup(
                code=item.code,
                title=item.title,
                importance=item.importance,
                page=item.page,
                automation=item.automation,
                outcome=item.outcome,
                reason=_evidence_reason(item, bool(targets)),
                verified=catalog.verified,
                requests=catalog.requests,
                targets=targets,
            )
        )
    return tuple(groups)


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
                area=mappings.isms_p_areas[code.split(".")[0]],
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
        evidence_requests=_evidence_requests(items, by_rule, mappings),
    )
