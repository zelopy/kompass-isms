"""CT-001 멀티 리전 관리 이벤트 추적 미설정.

데이터 형태는 실습 계정에서 확인한 실제 응답을 따른다 (RULES.md CT-001 "확인됨").
- `LatestDeliveryError`는 오류가 없으면 키가 없다
- 이벤트 선택기는 `EventSelectors`와 `AdvancedEventSelectors` 중 하나만 온다
"""

from datetime import UTC, datetime
from typing import Any

from kompass.config import CloudTrailSettings, Settings
from kompass.models import CollectError, Severity, Snapshot, Status
from kompass.rules.cloudtrail.ct_001_multi_region_trail import Ct001MultiRegionTrail

T0 = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
RULE = Ct001MultiRegionTrail()
DEFAULT = Settings()
WRITE_ONLY_OK = Settings(cloudtrail=CloudTrailSettings(require_read_events=False))


def _arn(name: str, region: str = "ap-northeast-2") -> str:
    return f"arn:aws:cloudtrail:{region}:{ACCOUNT}:trail/{name}"


def _trail(name: str, *, multi: bool = True, region: str = "ap-northeast-2") -> dict[str, Any]:
    return {
        "Name": name,
        "TrailARN": _arn(name, region),
        "HomeRegion": region,
        "IsMultiRegionTrail": multi,
        "IsOrganizationTrail": False,
        "S3BucketName": "logs",
    }


def _status(logging: bool = True, **extra: Any) -> dict[str, Any]:
    return {"IsLogging": logging, "LatestDeliveryTime": "2026-10-13T11:00:00Z", **extra}


def _basic(
    read_write: str = "All", management: bool = True, excluded: list[str] | None = None
) -> dict[str, Any]:
    return {
        "EventSelectors": [
            {
                "ReadWriteType": read_write,
                "IncludeManagementEvents": management,
                "DataResources": [],
                "ExcludeManagementEventSources": excluded or [],
            }
        ]
    }


def _advanced(*selectors: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "AdvancedEventSelectors": [
            {"Name": f"s{i}", "FieldSelectors": fields} for i, fields in enumerate(selectors)
        ]
    }


MANAGEMENT = {"Field": "eventCategory", "Equals": ["Management"]}


def _snapshot(
    trails: list[dict[str, Any]] | None,
    status: dict[str, Any] | None = None,
    selectors: dict[str, Any] | None = None,
    errors: tuple[CollectError, ...] = (),
) -> Snapshot:
    data: dict[str, Any] = {}
    if trails is not None:
        data = {"trails": trails, "status": status or {}, "event_selectors": selectors or {}}
    return Snapshot(
        service="cloudtrail",
        account_id=ACCOUNT,
        regions=("ap-northeast-2",),
        collected_at=T0,
        data=data,
        errors=errors,
    )


def _one(snapshot: Snapshot, settings: Settings = DEFAULT) -> Any:
    [finding] = RULE.evaluate(snapshot, settings)
    return finding


def _single_trail(status: dict[str, Any], selectors: dict[str, Any], **kw: Any) -> Snapshot:
    arn = _arn("main")
    return _snapshot([_trail("main", **kw)], {arn: status}, {arn: selectors})


# --- PASS ---


def test_pass_multi_region_logging_all_events() -> None:
    finding = _one(_single_trail(_status(), _basic("All")))
    assert finding.status == Status.PASS
    assert finding.rule_id == "CT-001"
    assert finding.resource == "account"
    assert finding.region is None
    assert finding.severity == Severity.HIGH
    assert finding.collected_at == T0
    assert finding.evidence["passing_trails"] == [_arn("main")]


def test_pass_advanced_selector_without_read_only_filter() -> None:
    finding = _one(_single_trail(_status(), _advanced([MANAGEMENT])))
    assert finding.status == Status.PASS


def test_pass_advanced_read_and_write_split_across_selectors() -> None:
    selectors = _advanced(
        [MANAGEMENT, {"Field": "readOnly", "Equals": ["true"]}],
        [MANAGEMENT, {"Field": "readOnly", "Equals": ["false"]}],
    )
    assert _one(_single_trail(_status(), selectors)).status == Status.PASS


def test_pass_write_only_when_read_events_not_required() -> None:
    finding = _one(_single_trail(_status(), _basic("WriteOnly")), WRITE_ONLY_OK)
    assert finding.status == Status.PASS
    assert finding.evidence["require_read_events"] is False


def test_pass_with_excluded_sources_records_them() -> None:
    # 사용자 결정 (2026-10-13): KMS·RDS Data API 관리 이벤트 제외는 PASS로 보고 증적에 남긴다
    selectors = _basic("All", excluded=["kms.amazonaws.com"])
    finding = _one(_single_trail(_status(), selectors))
    assert finding.status == Status.PASS
    [trail] = finding.evidence["trails"]
    assert trail["excluded_event_sources"] == ["kms.amazonaws.com"]


def test_pass_shadow_trail_from_other_region() -> None:
    arn = _arn("org", "us-east-1")
    snapshot = _snapshot(
        [_trail("org", region="us-east-1")], {arn: _status()}, {arn: _basic("All")}
    )
    assert _one(snapshot).status == Status.PASS


def test_pass_when_another_trail_is_unknown() -> None:
    # 확인하지 못한 추적이 있어도 조건을 만족하는 추적이 하나 있으면 PASS다
    good, unknown = _arn("good"), _arn("unknown")
    snapshot = _snapshot(
        [_trail("good"), _trail("unknown")],
        {good: _status()},
        {good: _basic("All"), unknown: _basic("All")},
    )
    assert _one(snapshot).status == Status.PASS


# --- FAIL ---


def test_fail_no_trails() -> None:
    finding = _one(_snapshot([]))
    assert finding.status == Status.FAIL
    assert finding.evidence["trails"] == []


def test_fail_single_region_trail_only() -> None:
    finding = _one(_single_trail(_status(), _basic("All"), multi=False))
    assert finding.status == Status.FAIL
    assert "멀티 리전" in finding.evidence["trails"][0]["reasons"][0]


def test_fail_logging_stopped() -> None:
    assert _one(_single_trail(_status(logging=False), _basic("All"))).status == Status.FAIL


def test_fail_management_events_not_included() -> None:
    # 데이터 이벤트만 기록하는 추적
    assert _one(_single_trail(_status(), _basic("All", management=False))).status == Status.FAIL


def test_fail_write_only_when_read_events_required() -> None:
    finding = _one(_single_trail(_status(), _basic("WriteOnly")))
    assert finding.status == Status.FAIL
    assert finding.evidence["trails"][0]["management_events"] == {"read": False, "write": True}


def test_fail_advanced_selector_limited_to_some_sources() -> None:
    # 특정 서비스의 이벤트만 기록하는 선택기는 사용자 계정 로깅 전체로 보지 않는다
    selectors = _advanced([MANAGEMENT, {"Field": "eventSource", "Equals": ["s3.amazonaws.com"]}])
    assert _one(_single_trail(_status(), selectors)).status == Status.FAIL


def test_fail_advanced_data_events_only() -> None:
    selectors = _advanced([{"Field": "eventCategory", "Equals": ["Data"]}])
    assert _one(_single_trail(_status(), selectors)).status == Status.FAIL


def test_unknown_single_region_trail_does_not_turn_fail_into_error() -> None:
    # 단일 리전 추적은 상태를 몰라도 조건을 만족할 수 없으므로 판정에 영향이 없다
    snapshot = _snapshot([_trail("single", multi=False)])
    assert _one(snapshot).status == Status.FAIL


# --- ERROR ---


def test_error_when_trail_list_not_collected() -> None:
    error = CollectError(
        operation="cloudtrail:DescribeTrails",
        region="ap-northeast-2",
        error_code="AccessDeniedException",
        message="denied",
    )
    finding = _one(_snapshot(None, errors=(error,)))
    assert finding.status == Status.ERROR
    assert finding.evidence["errors"][0]["error_code"] == "AccessDeniedException"


def test_error_when_only_multi_region_trail_status_unknown() -> None:
    arn = _arn("org")
    error = CollectError(
        operation="cloudtrail:GetTrailStatus",
        region="ap-northeast-2",
        error_code="TrailNotFoundException",
        message="not found",
        resource=arn,
    )
    snapshot = _snapshot([_trail("org")], {}, {arn: _basic("All")}, errors=(error,))
    finding = _one(snapshot)
    assert finding.status == Status.ERROR
    assert finding.evidence["trails"][0]["result"] == "unknown"
    assert finding.evidence["errors"][0]["resource"] == arn


# --- 증적 ---


def test_evidence_includes_delivery_error() -> None:
    finding = _one(_single_trail(_status(LatestDeliveryError="AccessDenied"), _basic("All")))
    [trail] = finding.evidence["trails"]
    assert trail["latest_delivery_error"] == "AccessDenied"
    assert trail["latest_delivery_time"] == "2026-10-13T11:00:00Z"


def test_evidence_delivery_error_absent_is_none() -> None:
    [trail] = _one(_single_trail(_status(), _basic("All"))).evidence["trails"]
    assert trail["latest_delivery_error"] is None
