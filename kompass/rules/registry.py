"""룰 레지스트리와 실행기."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from kompass.config import Settings
from kompass.models import Finding, Snapshot
from kompass.rules.base import BaseRule
from kompass.rules.cloudtrail.ct_001_multi_region_trail import Ct001MultiRegionTrail
from kompass.rules.cloudtrail.ct_002_log_bucket_retention import Ct002LogBucketRetention
from kompass.rules.ec2.sg_001_admin_port_open import Sg001AdminPortOpen
from kompass.rules.ec2.sg_002_all_ports_open import Sg002AllPortsOpen
from kompass.rules.ec2.sg_003_db_port_open import Sg003DbPortOpen
from kompass.rules.ec2.sg_004_default_group_in_use import Sg004DefaultGroupInUse
from kompass.rules.ec2.vpc_001_subnet_separation import Vpc001SubnetSeparation
from kompass.rules.ec2.vpc_002_public_ip_interface import Vpc002PublicIpInterface
from kompass.rules.ec2.vpc_003_flow_logs import Vpc003FlowLogs
from kompass.rules.guardduty.gd_001_detector_enabled import Gd001DetectorEnabled
from kompass.rules.guardduty.gd_002_finding_alerts import Gd002FindingAlerts
from kompass.rules.iam.iam_001_root_mfa import Iam001RootMfa
from kompass.rules.iam.iam_002_root_access_key import Iam002RootAccessKey
from kompass.rules.iam.iam_003_console_user_mfa import Iam003ConsoleUserMfa
from kompass.rules.iam.iam_004_password_policy import Iam004PasswordPolicy
from kompass.rules.iam.iam_005_unused_credentials import Iam005UnusedCredentials
from kompass.rules.iam.iam_006_access_key_rotation import Iam006AccessKeyRotation
from kompass.rules.iam.iam_007_admin_users import Iam007AdminUsers
from kompass.rules.iam.iam_008_root_recent_use import Iam008RootRecentUse
from kompass.rules.iam.iam_009_external_identity import Iam009ExternalIdentity
from kompass.rules.iam.iam_010_instance_permissions import Iam010InstancePermissions
from kompass.rules.iam.iam_011_network_permissions import Iam011NetworkPermissions
from kompass.rules.logs.log_001_security_log_retention import Log001SecurityLogRetention
from kompass.rules.rds.rds_001_storage_encryption import Rds001StorageEncryption
from kompass.rules.rds.rds_002_public_access import Rds002PublicAccess
from kompass.rules.rds.rds_003_log_exports import Rds003LogExports
from kompass.rules.rds.rds_004_backup_retention import Rds004BackupRetention
from kompass.rules.s3.s3_001_account_public_access_block import S3001AccountPublicAccessBlock
from kompass.rules.s3.s3_002_bucket_public_access_block import S3002BucketPublicAccessBlock
from kompass.rules.s3.s3_003_public_bucket_policy import S3003PublicBucketPolicy
from kompass.rules.s3.s3_004_default_encryption import S3004DefaultEncryption
from kompass.rules.s3.s3_005_access_logging import S3005AccessLogging
from kompass.rules.s3.s3_006_public_bucket_acl import S3006PublicBucketAcl
from kompass.rules.s3.s3_007_secure_transport import S3007SecureTransport

RULES: tuple[BaseRule, ...] = (
    Ct001MultiRegionTrail(),
    Ct002LogBucketRetention(),
    Sg001AdminPortOpen(),
    Sg002AllPortsOpen(),
    Sg003DbPortOpen(),
    Sg004DefaultGroupInUse(),
    Vpc001SubnetSeparation(),
    Vpc002PublicIpInterface(),
    Vpc003FlowLogs(),
    S3001AccountPublicAccessBlock(),
    S3002BucketPublicAccessBlock(),
    S3003PublicBucketPolicy(),
    S3004DefaultEncryption(),
    S3005AccessLogging(),
    S3006PublicBucketAcl(),
    S3007SecureTransport(),
    Iam001RootMfa(),
    Iam002RootAccessKey(),
    Iam003ConsoleUserMfa(),
    Iam004PasswordPolicy(),
    Iam005UnusedCredentials(),
    Iam006AccessKeyRotation(),
    Iam007AdminUsers(),
    Iam008RootRecentUse(),
    Iam009ExternalIdentity(),
    Iam010InstancePermissions(),
    Iam011NetworkPermissions(),
    Rds001StorageEncryption(),
    Rds002PublicAccess(),
    Rds003LogExports(),
    Rds004BackupRetention(),
    Gd001DetectorEnabled(),
    Gd002FindingAlerts(),
    Log001SecurityLogRetention(),
)


@dataclass(frozen=True)
class Evaluation:
    findings: tuple[Finding, ...]
    # 스냅샷이 없어서 실행하지 않은 룰. PASS가 아니며, 해당 항목은 "점검하지 않음"이다
    skipped: tuple[str, ...]


def evaluate(
    snapshots: Mapping[str, Snapshot],
    settings: Settings,
    rules: Sequence[BaseRule] = RULES,
) -> Evaluation:
    """룰을 실행한다. 룰 코드의 예외는 잡지 않는다 (버그를 ERROR로 숨기지 않는다)."""
    _require_unique_ids(rules)
    findings: list[Finding] = []
    skipped: list[str] = []
    for rule in rules:
        snapshot = snapshots.get(rule.service)
        if snapshot is None:
            skipped.append(rule.id)
            continue
        produced = rule.evaluate(snapshot, settings)
        if not produced:
            raise RuntimeError(f"{rule.id}가 finding을 내지 않았다. 룰은 항상 하나 이상 내야 한다")
        foreign = {f.rule_id for f in produced} - {rule.id}
        if foreign:
            raise RuntimeError(f"{rule.id}가 다른 룰 ID의 finding을 냈다: {sorted(foreign)}")
        findings.extend(produced)
    _require_unique_keys(findings)
    return Evaluation(findings=tuple(findings), skipped=tuple(skipped))


def _require_unique_ids(rules: Sequence[BaseRule]) -> None:
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise ValueError(f"룰 ID가 중복된다: {rule.id}")
        seen.add(rule.id)


def _require_unique_keys(findings: Sequence[Finding]) -> None:
    """finding 식별자(`Finding.key`)는 점검 안에서 유일해야 한다. 해설을 붙일 때 기준이 된다."""
    seen: set[str] = set()
    for finding in findings:
        if finding.key in seen:
            raise RuntimeError(f"finding 식별자가 중복된다: {finding.key}")
        seen.add(finding.key)
