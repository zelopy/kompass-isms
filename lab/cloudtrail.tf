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
