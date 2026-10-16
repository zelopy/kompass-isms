# CT-001: 멀티 리전 관리 이벤트 추적.
# 계정의 첫 번째 관리 이벤트 추적은 CloudTrail 요금이 없고, S3 저장 비용만 든다.

locals {
  trail_name = "${local.name}-trail"
  trail_arn  = "arn:aws:cloudtrail:${var.region}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"
}

resource "aws_cloudtrail" "this" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_logging                = var.cloudtrail_enabled

  event_selector {
    read_write_type           = var.cloudtrail_read_write_type
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.logs]
}

# --- 로그 보관 기간: CT-002 FAIL, LOG-001 FAIL·PASS (ADR-043) ---

# 추적 로그를 30일 뒤 삭제 → CT-002 FAIL (기준 365일). 실습 저장 비용도 줄인다
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-cloudtrail-logs"
    status = "Enabled"
    filter {
      prefix = "cloudtrail/AWSLogs/"
    }
    expiration {
      days = 30
    }
  }
}

# /aws/rds/ 접두사는 기본 설정에서 보안 로그 그룹으로 본다. 데이터는 쌓이지 않는다
resource "aws_cloudwatch_log_group" "retention_short" {
  name              = "/aws/rds/instance/${local.name}-short/error"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "retention_long" {
  name              = "/aws/rds/instance/${local.name}-long/error"
  retention_in_days = 400
}
