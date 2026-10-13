"""S3-004 기본 암호화, S3-005 서버 액세스 로깅."""

from kompass.config import S3Settings, Settings
from kompass.models import Severity, Status
from kompass.rules.s3.s3_004_default_encryption import S3004DefaultEncryption
from kompass.rules.s3.s3_005_access_logging import S3005AccessLogging
from tests.rules.s3.data import collect_error, details, encryption, snapshot

S3004 = S3004DefaultEncryption()
S3005 = S3005AccessLogging()
REQUIRE_KMS = Settings(s3=S3Settings(require_kms=True))
EXCLUDE_TARGETS = Settings(s3=S3Settings(exclude_log_target_buckets=True))


# --- S3-004 ---


def test_s3004_pass_sse_s3_by_default() -> None:
    [finding] = S3004.evaluate(snapshot({"b": details()}), Settings())
    assert finding.status == Status.PASS
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["algorithms"] == ["AES256"]


def test_s3004_fail_no_encryption() -> None:
    [finding] = S3004.evaluate(snapshot({"b": details(encryption_config=None)}), Settings())
    assert finding.status == Status.FAIL


def test_s3004_require_kms() -> None:
    [sse_s3] = S3004.evaluate(snapshot({"b": details()}), REQUIRE_KMS)
    [kms] = S3004.evaluate(
        snapshot({"b": details(encryption_config=encryption("aws:kms"))}), REQUIRE_KMS
    )
    [dsse] = S3004.evaluate(
        snapshot({"b": details(encryption_config=encryption("aws:kms:dsse"))}), REQUIRE_KMS
    )
    assert (sse_s3.status, kms.status, dsse.status) == (Status.FAIL, Status.PASS, Status.PASS)
    assert sse_s3.evidence["require_kms"] is True


def test_s3004_error() -> None:
    data = snapshot(
        {"b": details(missing=("encryption",))},
        errors=(collect_error("s3:GetBucketEncryption", "b"),),
    )
    [finding] = S3004.evaluate(data, Settings())
    assert finding.status == Status.ERROR


# --- S3-005 ---


def _logged(target: str) -> dict[str, str]:
    return {"TargetBucket": target, "TargetPrefix": "s3-access/"}


def test_s3005_pass_logging_enabled() -> None:
    [finding] = S3005.evaluate(snapshot({"b": details(logging=_logged("logs"))}), Settings())
    assert finding.status == Status.PASS
    assert finding.severity == Severity.LOW
    assert finding.evidence["target_bucket"] == "logs"


def test_s3005_fail_logging_disabled() -> None:
    [finding] = S3005.evaluate(snapshot({"b": details()}), Settings())
    assert finding.status == Status.FAIL


def test_s3005_log_target_fails_by_default() -> None:
    data = snapshot({"app": details(logging=_logged("logs")), "logs": details()})
    statuses = {f.resource: f.status for f in S3005.evaluate(data, Settings())}
    assert statuses == {"app": Status.PASS, "logs": Status.FAIL}


def test_s3005_log_target_excluded_when_configured() -> None:
    data = snapshot({"app": details(logging=_logged("logs")), "logs": details()})
    findings = {f.resource: f for f in S3005.evaluate(data, EXCLUDE_TARGETS)}
    assert findings["logs"].status == Status.NOT_APPLICABLE
    assert findings["logs"].evidence["log_target_for"] == ["app"]


def test_s3005_error() -> None:
    data = snapshot(
        {"b": details(missing=("logging",))}, errors=(collect_error("s3:GetBucketLogging", "b"),)
    )
    [finding] = S3005.evaluate(data, Settings())
    assert finding.status == Status.ERROR
