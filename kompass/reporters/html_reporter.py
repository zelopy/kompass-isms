"""HTML 보고서: 브라우저로 여는 파일 하나짜리 결과 뷰어 (ADR-055).

`AuditReport` JSON과 화면 표기용 라벨을 데이터 블록에 넣고, 화면은 `html/viewer.js`가 그린다.
리소스 이름·메시지·증적·LLM 해설은 신뢰할 수 없는 문자열이므로 다음을 지킨다.

- 데이터 블록은 `type="application/json"`이라 실행되지 않는다. `<`·`>`·`&`·U+2028·U+2029를
  `\\uXXXX`로 바꿔 `</script>`로 태그를 빠져나오지 못하게 한다.
- 인라인 스크립트·스타일은 CSP 해시로만 허용한다. 외부 연결은 막는다.
- 뷰어는 `textContent`로만 값을 넣는다 (`innerHTML` 금지, 테스트로 검사).
"""

import base64
import hashlib
import json
import re
from importlib.resources import files
from typing import Any

from kompass.models import AuditReport
from kompass.reporters._format import (
    DISCLAIMER,
    EVIDENCE_NOTICE,
    EVIDENCE_REVIEW_NOTICE,
    EVIDENCE_UNVERIFIED,
    EXPLANATION_NOTICE,
    INVESTIGATION_NOTICE,
    OUTCOME_LABELS,
    PRIORITY_LABELS,
    RULE_TITLES,
    SCHEME_LABELS,
    STATUS_LABELS,
    kst,
)
from kompass.reporters.json_reporter import render_json

DATA_ELEMENT_ID = "kompass-data"
_ESCAPES = {
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    " ": "\\u2028",
    " ": "\\u2029",
}
_DATA_PATTERN = re.compile(
    rf'<script type="application/json" id="{DATA_ELEMENT_ID}">(.*?)</script>', re.S
)


def _asset(name: str) -> str:
    # 체크아웃 설정과 관계없이 같은 출력이 나오도록 줄바꿈을 LF로 맞춘다
    text = (files("kompass.reporters") / "html" / name).read_text(encoding="utf-8")
    return text.replace("\r\n", "\n")


def _sha256(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def build_payload(report: AuditReport) -> dict[str, Any]:
    """뷰어가 읽는 데이터. `report`는 JSON 보고서와 같고, 라벨은 다른 리포터와 공유한다."""
    display: dict[str, str] = {
        "started_at": kst(report.scan.started_at),
        "finished_at": kst(report.scan.finished_at),
        "generated_at": kst(report.generated_at),
        "evaluated_at": kst(report.evaluation.evaluated_at),
    }
    if report.explanations is not None:
        display["explanations_at"] = kst(report.explanations.generated_at)
    if report.investigations is not None:
        display["investigations_at"] = kst(report.investigations.generated_at)
    if report.evidence_reviews is not None:
        display["evidence_reviews_at"] = kst(report.evidence_reviews.generated_at)
    return {
        "report": json.loads(render_json(report)),
        "labels": {
            "outcome": {k.value: v for k, v in OUTCOME_LABELS.items()},
            "status": {k.value: v for k, v in STATUS_LABELS.items()},
            "priority": PRIORITY_LABELS,
            "scheme": SCHEME_LABELS,
            "notices": {
                "disclaimer": DISCLAIMER,
                "explanation": EXPLANATION_NOTICE,
                "investigation": INVESTIGATION_NOTICE,
                "evidence_review": EVIDENCE_REVIEW_NOTICE,
                "evidence": EVIDENCE_NOTICE,
                "evidence_unverified": EVIDENCE_UNVERIFIED,
            },
        },
        "rules": RULE_TITLES,
        "display": display,
    }


def _escape_json(payload: dict[str, Any]) -> str:
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    for char, escaped in _ESCAPES.items():
        text = text.replace(char, escaped)
    return text


def render_html(report: AuditReport) -> str:
    script = _asset("viewer.js")
    style = _asset("viewer.css")
    csp = "; ".join(
        (
            "default-src 'none'",
            f"script-src {_sha256(script)}",
            f"style-src {_sha256(style)}",
            "img-src data:",
            "base-uri 'none'",
            "form-action 'none'",
        )
    )
    # 데이터는 마지막에 채워 데이터 안의 자리표시자 문자열이 치환되지 않게 한다
    return (
        _asset("template.html")
        .replace("{{CSP}}", csp)
        .replace("{{STYLE}}", style)
        .replace("{{SCRIPT}}", script)
        .replace("{{DATA}}", _escape_json(build_payload(report)))
    )


def extract_payload(html: str) -> dict[str, Any]:
    """HTML에서 데이터 블록을 꺼낸다 (테스트·데모 검사용)."""
    found = _DATA_PATTERN.search(html)
    if found is None:
        raise ValueError("데이터 블록이 없다")
    payload: dict[str, Any] = json.loads(found.group(1))
    return payload
