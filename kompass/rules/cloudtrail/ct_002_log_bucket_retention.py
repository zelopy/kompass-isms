"""CT-002 CloudTrail 로그 버킷 보존 기간 부족 (KISA CA-17, docs/RULES.md).

추적 S3 버킷마다, 추적 로그 경로(`<S3KeyPrefix>/AWSLogs/`)와 겹치는 활성 수명주기 규칙이
`logs.min_retention_days`보다 일찍 객체를 삭제하면 FAIL. 삭제 규칙이 없으면 PASS.
날짜를 지정해 삭제하는 규칙은 보존 일수를 알 수 없으므로 FAIL로 본다.
버킷이 없으면(`NoSuchBucket`) 로그를 보존할 곳이 없으므로 FAIL, 그 밖의 수집 실패는 ERROR (ADR-056).
증적에 버킷을 쓰는 추적과 로깅 상태를 남기고, 로깅 중지된 추적만 쓰는 버킷은 메시지에 표시한다.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence

_LIFECYCLE_OPERATIONS = frozenset({"s3:GetBucketLocation", "s3:GetBucketLifecycleConfiguration"})
_NO_SUCH_BUCKET = "NoSuchBucket"
_STOPPED_NOTE = " (로깅 중지된 추적만 사용)"


def _log_path(trail: dict[str, Any]) -> str:
    prefix = (trail.get("S3KeyPrefix") or "").strip("/")
    return f"{prefix}/AWSLogs/" if prefix else "AWSLogs/"


def _rule_prefix(rule: dict[str, Any]) -> str:
    """규칙이 적용되는 키 접두사. 필터가 없으면 버킷 전체("")."""
    rule_filter = rule.get("Filter") or {}
    if "Prefix" in rule_filter:
        return str(rule_filter["Prefix"])
    if "And" in rule_filter:
        return str(rule_filter["And"].get("Prefix", ""))
    return str(rule.get("Prefix", ""))


def _overlaps(rule_prefix: str, paths: set[str]) -> bool:
    return any(path.startswith(rule_prefix) or rule_prefix.startswith(path) for path in paths)


def _trail_state(trail: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    """추적 이름과 로깅 상태. 상태를 수집하지 못했으면 `is_logging`은 None."""
    trail_status = status.get(trail.get("TrailARN", ""))
    is_logging = trail_status.get("IsLogging") if isinstance(trail_status, dict) else None
    return {"trail": trail.get("Name"), "is_logging": is_logging}


class Ct002LogBucketRetention(BaseRule):
    id: ClassVar[str] = "CT-002"
    service: ClassVar[str] = "cloudtrail"
    title: ClassVar[str] = "CloudTrail 로그 버킷 보존 기간 부족"
    severity: ClassVar[Severity] = Severity.MEDIUM

    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]:
        trails = snapshot.data.get("trails")
        if trails is None:
            errors = [e for e in snapshot.errors if e.operation == "cloudtrail:DescribeTrails"]
            return [
                self._account(
                    snapshot,
                    Status.ERROR,
                    "CloudTrail 추적 목록을 수집하지 못함",
                    {"errors": errors_evidence(errors)},
                )
            ]
        paths: dict[str, set[str]] = {}
        users: dict[str, list[dict[str, Any]]] = {}
        status = snapshot.data.get("status", {})
        for trail in trails:
            if trail.get("S3BucketName"):
                bucket = trail["S3BucketName"]
                paths.setdefault(bucket, set()).add(_log_path(trail))
                users.setdefault(bucket, []).append(_trail_state(trail, status))
        if not paths:
            return [
                self._account(snapshot, Status.NOT_APPLICABLE, "S3로 로그를 보내는 추적이 없음", {})
            ]
        lifecycles = snapshot.data.get("bucket_lifecycles", {})
        minimum = settings.logs.min_retention_days
        findings = []
        for bucket in sorted(paths):
            verdict, message, evidence = self._judge(
                snapshot, bucket, paths[bucket], lifecycles, minimum
            )
            evidence["trails"] = users[bucket]
            # 상태를 모르는 추적(None)이 섞이면 중지되었다고 단정하지 않는다
            if all(state["is_logging"] is False for state in users[bucket]):
                message += _STOPPED_NOTE
            findings.append(self._bucket(snapshot, bucket, verdict, message, evidence))
        return findings

    def _judge(
        self,
        snapshot: Snapshot,
        bucket: str,
        paths: set[str],
        lifecycles: dict[str, Any],
        minimum: int,
    ) -> tuple[Status, str, dict[str, Any]]:
        """버킷 하나의 판정 (상태, 메시지, 증적)."""
        evidence: dict[str, Any] = {
            "log_paths": sorted(paths),
            "min_retention_days": minimum,
        }
        if bucket not in lifecycles:
            errors = [
                e
                for e in snapshot.errors
                if e.resource == bucket and e.operation in _LIFECYCLE_OPERATIONS
            ]
            evidence["errors"] = errors_evidence(errors)
            codes = list(dict.fromkeys(e.error_code for e in errors))
            if _NO_SUCH_BUCKET in codes:
                # 권한 문제와 달리 버킷이 없다는 확정된 사실이다. 로그를 보존할 곳이 없음 (ADR-056)
                return Status.FAIL, f"추적 로그 버킷이 존재하지 않음: {bucket}", evidence
            cause = f" ({', '.join(codes)})" if codes else ""
            message = f"추적 버킷의 수명주기 설정을 수집하지 못함{cause}: {bucket}"
            return Status.ERROR, message, evidence
        rules = lifecycles[bucket] or []
        short = []
        for rule in rules:
            expiration = rule.get("Expiration") or {}
            if rule.get("Status") != "Enabled" or not _overlaps(_rule_prefix(rule), paths):
                continue
            days = expiration.get("Days")
            if (isinstance(days, int) and days < minimum) or "Date" in expiration:
                short.append(
                    {
                        "id": rule.get("ID"),
                        "prefix": _rule_prefix(rule),
                        "expiration_days": days,
                        "expiration_date": expiration.get("Date"),
                    }
                )
        evidence["lifecycle_rules"] = len(rules)
        evidence["short_rules"] = short
        if short:
            message = f"추적 로그가 {minimum}일 전에 삭제되는 수명주기 규칙 있음: {bucket}"
            return Status.FAIL, message, evidence
        return Status.PASS, f"추적 로그를 {minimum}일 전에 삭제하는 규칙 없음: {bucket}", evidence

    def _bucket(
        self,
        snapshot: Snapshot,
        bucket: str,
        status: Status,
        message: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return self.finding(
            snapshot,
            resource=bucket,
            region=None,
            status=status,
            message=message,
            evidence=evidence,
        )

    def _account(
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
