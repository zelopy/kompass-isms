"""CT-002 CloudTrail 로그 버킷 보존 기간 부족 (KISA CA-17, docs/RULES.md).

추적 S3 버킷마다, 추적 로그 경로(`<S3KeyPrefix>/AWSLogs/`)와 겹치는 활성 수명주기 규칙이
`logs.min_retention_days`보다 일찍 객체를 삭제하면 FAIL. 삭제 규칙이 없으면 PASS.
날짜를 지정해 삭제하는 규칙은 보존 일수를 알 수 없으므로 FAIL로 본다.
"""

from typing import Any, ClassVar

from kompass.config import Settings
from kompass.models import Finding, Severity, Snapshot, Status
from kompass.rules.base import ACCOUNT_RESOURCE, BaseRule, errors_evidence

_LIFECYCLE_OPERATIONS = frozenset({"s3:GetBucketLocation", "s3:GetBucketLifecycleConfiguration"})


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
        for trail in trails:
            if trail.get("S3BucketName"):
                paths.setdefault(trail["S3BucketName"], set()).add(_log_path(trail))
        if not paths:
            return [
                self._account(snapshot, Status.NOT_APPLICABLE, "S3로 로그를 보내는 추적이 없음", {})
            ]
        lifecycles = snapshot.data.get("bucket_lifecycles", {})
        minimum = settings.logs.min_retention_days
        return [
            self._judge(snapshot, bucket, paths[bucket], lifecycles, minimum)
            for bucket in sorted(paths)
        ]

    def _judge(
        self,
        snapshot: Snapshot,
        bucket: str,
        paths: set[str],
        lifecycles: dict[str, Any],
        minimum: int,
    ) -> Finding:
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
            message = f"추적 버킷의 수명주기 설정을 수집하지 못함: {bucket}"
            return self._bucket(snapshot, bucket, Status.ERROR, message, evidence)
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
            return self._bucket(snapshot, bucket, Status.FAIL, message, evidence)
        message = f"추적 로그를 {minimum}일 전에 삭제하는 규칙 없음: {bucket}"
        return self._bucket(snapshot, bucket, Status.PASS, message, evidence)

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
