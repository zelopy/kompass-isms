variable "region" {
  description = "실습 리소스를 만들 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "aws_profile" {
  description = "배포에 쓸 AWS CLI 프로필 (관리자 권한). 점검용 SecurityAudit 프로필과 다르다."
  type        = string
  default     = null
}

# --- 계정 단위 설정 (계정 전체에 영향) ---

variable "password_policy" {
  description = "IAM 비밀번호 정책: weak(2종 8자, IAM-004 FAIL), kisa(3종 8자, PASS), none(정책 없음, FAIL)"
  type        = string
  default     = "weak"

  validation {
    condition     = contains(["weak", "kisa", "none"], var.password_policy)
    error_message = "password_policy는 weak, kisa, none 중 하나여야 한다."
  }
}

variable "account_block_public_access" {
  description = "계정 수준 S3 퍼블릭 액세스 차단. true면 S3-001 PASS지만 퍼블릭 버킷 케이스(정책·ACL)를 만들 수 없다."
  type        = bool
  default     = false
}

# --- CloudTrail ---

variable "cloudtrail_enabled" {
  description = "CloudTrail 로깅 활성화. false면 CT-001 FAIL."
  type        = bool
  default     = true
}

variable "cloudtrail_read_write_type" {
  description = "관리 이벤트 기록 범위: All(CT-001 PASS) 또는 WriteOnly(require_read_events=true일 때 FAIL)"
  type        = string
  default     = "All"

  validation {
    condition     = contains(["All", "WriteOnly"], var.cloudtrail_read_write_type)
    error_message = "cloudtrail_read_write_type은 All 또는 WriteOnly여야 한다."
  }
}

# --- 비용이 드는 선택 리소스 ---

variable "enable_public_rds" {
  description = "공개 RDS 인스턴스 생성 (VPC-002 제외 조건 확인용). 시간당 과금되므로 확인 후 바로 끈다."
  type        = bool
  default     = false
}
