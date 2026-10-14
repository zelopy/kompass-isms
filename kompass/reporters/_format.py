"""리포터 공용 표기: 한글 라벨, KST 시각, 증적 요약.

시각은 UTC로 저장되어 있으므로 표시할 때만 KST로 바꾼다 (ADR-019). 한국은 서머타임이 없어
고정 오프셋(+09:00)을 쓴다. 시간대 데이터 패키지가 없는 Windows에서도 동작한다.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from kompass.models import ItemOutcome, Status

KST = timezone(timedelta(hours=9), "KST")

OUTCOME_LABELS = {
    ItemOutcome.FAIL: "취약",
    ItemOutcome.ERROR: "확인 불가",
    ItemOutcome.REVIEW: "검토 필요",
    ItemOutcome.PASS: "양호",
    ItemOutcome.NOT_APPLICABLE: "해당 없음",
    ItemOutcome.NOT_EVALUATED: "점검하지 않음",
    ItemOutcome.NOT_IMPLEMENTED: "수동 점검 (미구현)",
}
STATUS_LABELS = {
    Status.FAIL: "취약",
    Status.ERROR: "확인 불가",
    Status.REVIEW: "검토 필요",
    Status.PASS: "양호",
    Status.NOT_APPLICABLE: "해당 없음",
}
ACTION_STATUSES = (Status.FAIL, Status.ERROR, Status.REVIEW)
STATUS_ORDER = (*ACTION_STATUSES, Status.PASS, Status.NOT_APPLICABLE)
DISCLAIMER = (
    "이 보고서는 점검 보조 자료이며 ISMS-P 인증 심사 결과를 보장하지 않는다. "
    "ISMS-P 매핑은 원문 검증 전 초안이다."
)


def kst(value: datetime) -> str:
    return value.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S KST")


def compact_json(value: Any, limit: int = 300) -> str:
    """증적을 한 줄 JSON으로 줄인다. 전체 증적은 JSON 보고서에 있다."""
    text = json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
    return text if len(text) <= limit else text[: limit - 1] + "…"
