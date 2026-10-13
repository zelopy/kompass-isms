"""판정 기준값 설정 (`kompass.yaml`).

기본값은 일반적인 권고 수준이다. 조직 기준이 다르면 `kompass.yaml`로 바꾼다 (ADR-017).
보고서에는 적용한 기준값을 함께 표시한다. 항목은 그 값을 쓰는 룰을 구현할 때 추가한다.
"""

from pydantic import BaseModel, ConfigDict


class _Section(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CloudTrailSettings(_Section):
    # true면 관리 이벤트를 읽기·쓰기 모두 기록해야 CT-001 PASS
    require_read_events: bool = True


class Ec2Settings(_Section):
    # SG-001: 전체 개방되면 안 되는 관리 포트
    admin_ports: tuple[int, ...] = (22, 3389)
    # SG-003: 전체 개방되면 안 되는 데이터베이스 포트
    db_ports: tuple[int, ...] = (3306, 5432, 1433, 1521, 27017, 6379)


class S3Settings(_Section):
    # S3-004: true면 SSE-KMS(aws:kms, aws:kms:dsse)일 때만 PASS
    require_kms: bool = False
    # S3-005: true면 다른 버킷의 서버 액세스 로그를 받는 버킷은 판정에서 제외(N/A)
    exclude_log_target_buckets: bool = False


class PasswordPolicySettings(_Section):
    # IAM-004 (KISA CA-04, ADR-014): 영문자·숫자·특수문자 중 2종이면 10자, 3종이면 8자 이상
    min_length_two_types: int = 10
    min_length_three_types: int = 8


class IamSettings(_Section):
    unused_credential_days: int = 90  # IAM-005
    access_key_rotation_days: int = 90  # IAM-006
    root_recent_use_days: int = 90  # IAM-008
    password_policy: PasswordPolicySettings = PasswordPolicySettings()


class Settings(_Section):
    cloudtrail: CloudTrailSettings = CloudTrailSettings()
    ec2: Ec2Settings = Ec2Settings()
    s3: S3Settings = S3Settings()
    iam: IamSettings = IamSettings()
