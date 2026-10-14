"""JSON 보고서: `AuditReport` 전체 (매핑을 붙인 finding과 전체 증적 포함)."""

from kompass.models import AuditReport


def render_json(report: AuditReport) -> str:
    return report.model_dump_json(indent=2)
