"""리포터 공용 표기: 한글 라벨, KST 시각, 증적 요약.

시각은 UTC로 저장되어 있으므로 표시할 때만 KST로 바꾼다 (ADR-019). 한국은 서머타임이 없어
고정 오프셋(+09:00)을 쓴다. 시간대 데이터 패키지가 없는 Windows에서도 동작한다.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from kompass.models import AuditReport, ItemOutcome, Status
from kompass.rules.registry import RULES

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
    "이 보고서는 점검 보조 자료이며 ISMS-P 인증 심사 결과를 보장하지 않음. "
    "ISMS-P 매핑은 원문 검증 전 초안임."
)


def kst(value: datetime) -> str:
    return value.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S KST")


def compact_json(value: Any, limit: int = 300) -> str:
    """증적을 한 줄 JSON으로 줄인다. 전체 증적은 JSON 보고서에 있다."""
    text = json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --- AI 해설 ---

RULE_TITLES = {rule.id: rule.title for rule in RULES}
PRIORITY_LABELS = {"critical": "긴급", "high": "높음", "medium": "보통", "low": "낮음"}
SCHEME_LABELS = {"kisa": "KISA", "isms_p": "ISMS-P"}
EXPLANATION_NOTICE = (
    "LLM이 판정 결과를 설명한 참고 자료임. 판정과 심각도는 룰이 정했고 해설은 이를 바꾸지 않음. "
    '"검증됨"은 인용 구절이 KISA·ISMS-P 원문에 있음을 확인했다는 뜻이며 설명이나 조치 명령의 '
    "정확성을 보장하지 않음. 명령은 실행 전 검토 필요."
)


def explanation_summary(report: AuditReport) -> str:
    explained = report.explanations
    if explained is None:
        return "없음"
    verified = sum(1 for e in explained.explanations if e.verified)
    unverified = len(explained.explanations) - verified
    return (
        f"{explained.model} (effort {explained.effort}), {kst(explained.generated_at)}, "
        f"검증됨 {verified} · 검증되지 않음 {unverified} · 실패 {len(explained.failures)}, "
        f"종합 평가 {assessment_label(report)}"
    )


def assessment_label(report: AuditReport) -> str:
    explained = report.explanations
    if explained is None or (explained.assessment is None and not explained.assessment_failure):
        return "없음"
    if explained.assessment is None:
        return "실패"
    return "검증됨" if explained.assessment.verified else "검증되지 않음"


# --- 추가 조사 ---

INVESTIGATION_NOTICE = (
    "에이전트가 읽기 전용 도구로 추가 확인한 사실임. 판정과 심각도는 바꾸지 않음. "
    '사실마다 근거가 된 도구 호출(T1, T2 …)을 표시함. "근거 검증됨"은 사실이 실제 도구 호출을 '
    "가리킨다는 뜻이며 해석의 정확성을 보장하지 않음."
)


def investigation_summary(report: AuditReport) -> str:
    investigated = report.investigations
    if investigated is None:
        return "없음"
    verified = sum(1 for i in investigated.investigations if i.verified)
    unverified = len(investigated.investigations) - verified
    return (
        f"{investigated.model} (effort {investigated.effort}), {kst(investigated.generated_at)}, "
        f"근거 검증됨 {verified} · 검증되지 않음 {unverified} · 실패 {len(investigated.failures)}"
    )


# --- 증적 요청 ---

EVIDENCE_NOTICE = (
    "자동 점검만으로 확인할 수 없는 판단 기준에 대해 담당자에게 요청할 증적임. 판정은 바꾸지 않음. "
    "요청 문구는 KISA 원문 구절(원문 근거)을 바탕으로 작성한 것이며 원문이 아님."
)
EVIDENCE_UNVERIFIED = "요청 문구는 원문 대조 확인 전 초안임."


def evidence_summary(report: AuditReport) -> str:
    groups = report.evidence_requests
    if not groups:
        return "없음"
    requests = sum(len(g.requests) for g in groups)
    targets = sum(len(g.targets) for g in groups)
    return f"KISA 항목 {len(groups)}개, 요청 {requests}건, 확인 대상 리소스 {targets}건"
