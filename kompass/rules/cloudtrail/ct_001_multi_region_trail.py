"""CT-001 멀티 리전 관리 이벤트 추적 미설정 (KISA CA-13, docs/RULES.md).

조건을 모두 만족하는 추적이 하나 이상 있으면 PASS:
- 멀티 리전 추적이다
- 로깅 중이다
- 관리 이벤트를 쓰기(와 `require_read_events`면 읽기까지) 기록한다

PASS가 없을 때, 판정에 영향을 줄 수 있는 멀티 리전 추적의 상태나 선택기를 수집하지 못했으면
FAIL로 단정하지 않고 ERROR다 (ADR-005). 단일 리전 추적은 상태를 몰라도 조건을 만족할 수
없으므로 판정에 영향이 없다.

`ExcludeManagementEventSources`(KMS, RDS Data API)로 일부 관리 이벤트를 제외한 추적은
PASS로 보고 제외 목록을 evidence에 남긴다 (사용자 결정, 2026-10-13).
"""

from dataclasses import dataclass, field
from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import CollectError, Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence, errors_for

# 고급 선택기에서 "전체 관리 이벤트"를 좁히지 않는 필드. 그 외 조건이 있으면 일부 이벤트만 기록한다
_ADVANCED_NEUTRAL_FIELDS = frozenset({"eventCategory", "readOnly"})


@dataclass
class _Coverage:
    read: bool = False
    write: bool = False
    excluded: list[str] = field(default_factory=list)


class Ct001MultiRegionTrail(BaseRule):
    id: ClassVar[str] = "CT-001"
    service: ClassVar[str] = "cloudtrail"
    title: ClassVar[str] = "멀티 리전 관리 이벤트 추적 미설정"
    severity: ClassVar[Severity] = Severity.HIGH

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        data = snapshot.data
        if "trails" not in data:
            return [
                self._account_finding(
                    snapshot,
                    Status.ERROR,
                    "CloudTrail 추적 목록을 수집하지 못했다",
                    {"errors": errors_evidence(errors_for(snapshot, "cloudtrail:DescribeTrails"))},
                )
            ]

        require_read = settings.cloudtrail.require_read_events
        assessed = [_assess(trail, data, require_read) for trail in data["trails"]]
        passing = [t["arn"] for t in assessed if t["result"] == "pass"]
        unknown = [t["arn"] for t in assessed if t["result"] == "unknown"]
        evidence: dict[str, Any] = {
            "require_read_events": require_read,
            "trails": assessed,
            "passing_trails": passing,
        }

        if passing:
            return [
                self._account_finding(
                    snapshot,
                    Status.PASS,
                    f"조건을 만족하는 멀티 리전 추적이 있다: {', '.join(passing)}",
                    evidence,
                )
            ]
        if unknown:
            unknown_errors = [e for arn in unknown for e in _errors_for_trail(snapshot, arn)]
            evidence["errors"] = errors_evidence(unknown_errors)
            return [
                self._account_finding(
                    snapshot,
                    Status.ERROR,
                    f"멀티 리전 추적의 상태를 확인하지 못했다: {', '.join(unknown)}",
                    evidence,
                )
            ]
        message = (
            "CloudTrail 추적이 없다"
            if not assessed
            else "조건(멀티 리전, 로깅 중, 관리 이벤트 기록)을 만족하는 추적이 없다"
        )
        return [self._account_finding(snapshot, Status.FAIL, message, evidence)]

    def _account_finding(
        self, snapshot: Snapshot, status: Status, message: str, evidence: dict[str, Any]
    ) -> Finding:
        return self.finding(
            snapshot,
            resource=ACCOUNT_RESOURCE,
            region=None,
            status=status,
            message=message,
            evidence=evidence,
        )


def _errors_for_trail(snapshot: Snapshot, arn: str) -> list[CollectError]:
    return errors_for(snapshot, "cloudtrail:GetTrailStatus", arn) + errors_for(
        snapshot, "cloudtrail:GetEventSelectors", arn
    )


def _assess(trail: dict[str, Any], data: dict[str, Any], require_read: bool) -> dict[str, Any]:
    arn: str = trail["TrailARN"]
    multi = trail.get("IsMultiRegionTrail") is True
    status = data["status"].get(arn)
    selectors = data["event_selectors"].get(arn)
    coverage = _coverage(selectors) if selectors is not None else None

    reasons: list[str] = []
    if not multi:
        reasons.append("멀티 리전 추적이 아니다")
    if status is None:
        reasons.append("로깅 상태를 수집하지 못했다")
    elif status.get("IsLogging") is not True:
        reasons.append("로깅이 중지되어 있다")
    if coverage is None:
        reasons.append("이벤트 선택기를 수집하지 못했다")
    else:
        if not coverage.write:
            reasons.append("관리 이벤트(쓰기)를 기록하지 않는다")
        if require_read and not coverage.read:
            reasons.append("관리 이벤트(읽기)를 기록하지 않는다")

    if not reasons:
        result = "pass"
    elif multi and (status is None or coverage is None):
        result = "unknown"
    else:
        result = "fail"

    return {
        "arn": arn,
        "name": trail.get("Name"),
        "home_region": trail.get("HomeRegion"),
        "is_multi_region": multi,
        "is_organization_trail": trail.get("IsOrganizationTrail") is True,
        "is_logging": None if status is None else status.get("IsLogging") is True,
        "latest_delivery_error": None if status is None else status.get("LatestDeliveryError"),
        "latest_delivery_time": None if status is None else status.get("LatestDeliveryTime"),
        "management_events": (
            None if coverage is None else {"read": coverage.read, "write": coverage.write}
        ),
        "excluded_event_sources": None if coverage is None else coverage.excluded,
        "result": result,
        "reasons": reasons,
    }


def _coverage(selectors: dict[str, Any]) -> _Coverage:
    """기본·고급 이벤트 선택기가 기록하는 관리 이벤트 범위를 합집합으로 계산한다."""
    coverage = _Coverage()
    for selector in selectors.get("EventSelectors") or []:
        if selector.get("IncludeManagementEvents") is not True:
            continue
        read_write = selector.get("ReadWriteType", "All")
        coverage.read |= read_write in ("All", "ReadOnly")
        coverage.write |= read_write in ("All", "WriteOnly")
        coverage.excluded.extend(selector.get("ExcludeManagementEventSources") or [])

    for selector in selectors.get("AdvancedEventSelectors") or []:
        fields = {f["Field"]: f for f in selector.get("FieldSelectors", [])}
        category = fields.get("eventCategory")
        if category is None or "Management" not in category.get("Equals", []):
            continue
        source = fields.get("eventSource")
        narrowing = set(fields) - _ADVANCED_NEUTRAL_FIELDS - {"eventSource"}
        if narrowing or (source is not None and set(source) - {"Field", "NotEquals"}):
            continue  # 일부 이벤트만 기록하는 선택기
        if source is not None:
            coverage.excluded.extend(source.get("NotEquals", []))
        read_only = fields.get("readOnly")
        if read_only is None:
            coverage.read = coverage.write = True
            continue
        if "Equals" in read_only:
            coverage.read |= "true" in read_only["Equals"]
            coverage.write |= "false" in read_only["Equals"]
        elif "NotEquals" in read_only:
            coverage.read |= "true" not in read_only["NotEquals"]
            coverage.write |= "false" not in read_only["NotEquals"]
    coverage.excluded = sorted(set(coverage.excluded))
    return coverage
