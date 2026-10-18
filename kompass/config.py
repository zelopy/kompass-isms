"""판정 기준값 설정 (`kompass.yaml`).

기본값은 일반적인 권고 수준이다. 조직 기준이 다르면 `kompass.yaml`로 바꾼다 (ADR-017).
보고서에는 적용한 기준값을 함께 표시한다. 항목은 그 값을 쓰는 룰을 구현할 때 추가한다.
"""

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


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
    # IAM-010 (KISA CA-05): 인스턴스 생성·삭제·수정·접속 작업. 와일드카드(*, ?) 허용
    instance_actions: tuple[str, ...] = (
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:ModifyInstanceAttribute",
        "ssm:StartSession",
        "ssm:SendCommand",
        "ec2-instance-connect:SendSSHPublicKey",
        "ec2-instance-connect:SendSerialConsoleSSHPublicKey",
    )
    # IAM-011 (KISA CA-06): 방화벽·라우팅·로드 밸런서·DNS 등 네트워크 리소스 생성·삭제·수정 작업
    network_actions: tuple[str, ...] = (
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:ModifySecurityGroupRules",
        "ec2:CreateNetworkAclEntry",
        "ec2:ReplaceNetworkAclEntry",
        "ec2:CreateVpc",
        "ec2:DeleteVpc",
        "ec2:CreateSubnet",
        "ec2:ModifySubnetAttribute",
        "ec2:CreateRoute",
        "ec2:ReplaceRoute",
        "ec2:CreateRouteTable",
        "ec2:AssociateRouteTable",
        "ec2:CreateInternetGateway",
        "ec2:AttachInternetGateway",
        "ec2:CreateNatGateway",
        "ec2:CreateVpcPeeringConnection",
        "ec2:AssociateAddress",
        "elasticloadbalancing:CreateLoadBalancer",
        "elasticloadbalancing:DeleteLoadBalancer",
        "elasticloadbalancing:CreateListener",
        "elasticloadbalancing:ModifyListener",
        "route53:CreateHostedZone",
        "route53:ChangeResourceRecordSets",
    )


class RdsSettings(_Section):
    # RDS-004 (KISA CA-18): 자동 백업 보존 기간 최소 일수. 0이면 자동 백업 꺼짐
    min_backup_retention_days: int = Field(default=7, ge=1)


class BackupSettings(_Section):
    # BKP-002 (KISA CA-18): 백업 계획 규칙의 최소 보존 일수. RDS-004 기본값과 같다
    min_retention_days: int = Field(default=7, ge=1)
    # BKP-003 (KISA CA-18): 마지막 백업 뒤 허용하는 최대 경과 일수
    max_backup_age_days: int = Field(default=7, ge=1)


class ElbSettings(_Section):
    # ELB-002 (KISA CA-12): 리스너 보안 정책이 허용해도 되는 최소 TLS 버전
    min_tls_version: Literal["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"] = "TLSv1.2"


class LogsSettings(_Section):
    # LOG-001·CT-002 (KISA CA-17): 보안 로그 최소 보존 일수
    min_retention_days: int = Field(default=365, ge=1)
    # LOG-001: 보안 로그로 보는 CloudWatch 로그 그룹 이름 접두사 (추적·흐름 로그 대상 그룹 외)
    security_log_group_prefixes: tuple[str, ...] = ("/aws/rds/",)


class LlmSettings(_Section):
    """LLM 해설 설정 (3단계, ADR-029). 판정에는 쓰이지 않으므로 판정 결과 파일에 남기지 않는다."""

    model: str = "claude-opus-5-5"
    # 추론 깊이. 인용 정확도가 중요해 high를 기본으로 한다 (모델 기본값은 medium)
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    max_tokens: int = Field(default=16000, ge=1024)
    # 요청 하나의 시간 제한(초). SDK가 연결 오류·429·5xx를 최대 2회 재시도하므로 최악은 약 3배
    timeout_s: float = Field(default=300.0, gt=0)


class Settings(_Section):
    cloudtrail: CloudTrailSettings = CloudTrailSettings()
    ec2: Ec2Settings = Ec2Settings()
    s3: S3Settings = S3Settings()
    iam: IamSettings = IamSettings()
    rds: RdsSettings = RdsSettings()
    backup: BackupSettings = BackupSettings()
    elb: ElbSettings = ElbSettings()
    logs: LogsSettings = LogsSettings()
    llm: LlmSettings = LlmSettings()

    def judgment_criteria(self) -> dict[str, Any]:
        """판정 결과 파일에 남길 판정 기준값. LLM 설정은 판정과 무관하므로 뺀다."""
        return self.model_dump(mode="json", exclude={"llm"})


class ConfigError(Exception):
    """`kompass.yaml`을 읽을 수 없거나 형식이 틀리다. 판정 전에 중단한다."""


def load_settings(path: Path | None) -> Settings:
    """설정 파일을 읽는다. `path`가 None이면 기본값.

    정의되지 않은 키나 잘못된 값은 ConfigError다. 오타가 조용히 무시되어 기본값으로 판정되는
    것을 막는다 (ADR-023).
    """
    if path is None:
        return Settings()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"설정 파일을 읽을 수 없습니다: {path}: {exc}") from exc
    if raw is None:
        return Settings()
    if not isinstance(raw, dict):
        raise ConfigError(f"설정 파일의 최상위는 키-값 형식이어야 합니다: {path}")
    try:
        return Settings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"설정 파일 형식이 맞지 않습니다: {path}\n{exc}") from exc
