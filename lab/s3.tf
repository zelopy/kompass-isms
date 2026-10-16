# S3 실습 케이스. 버킷은 모두 비어 있다. 퍼블릭 버킷에도 객체를 올리지 않는다.

# --- S3-001 계정 수준 퍼블릭 액세스 차단 ---
# 기본값(manage_account_public_access_block = false)에서는 만들지 않는다. 기존 계정 설정이 없으면 S3-001 FAIL.
# 퍼블릭 버킷 케이스를 만들려면 계정 수준 차단이 꺼져 있거나 설정이 없어야 한다.

resource "aws_s3_account_public_access_block" "this" {
  count = var.manage_account_public_access_block ? 1 : 0

  block_public_acls       = var.account_block_public_access
  ignore_public_acls      = var.account_block_public_access
  block_public_policy     = var.account_block_public_access
  restrict_public_buckets = var.account_block_public_access
}

locals {
  public_cases = var.manage_account_public_access_block && var.account_block_public_access ? 0 : 1
}

# --- 로그 버킷: S3 서버 액세스 로그와 CloudTrail 로그 저장 ---

resource "aws_s3_bucket" "logs" {
  bucket        = "${local.name}-logs-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "S3ServerAccessLogs"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/s3-access/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.logs.arn
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
        }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
      {
        Sid       = "VpcFlowLogsAclCheck"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.logs.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        Sid       = "VpcFlowLogsWrite"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/vpc-flow/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# --- 비공개 + 로깅 버킷: S3-002, S3-003, S3-005, S3-006 PASS ---

resource "aws_s3_bucket" "private_logged" {
  bucket        = "${local.name}-private-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "private_logged" {
  bucket                  = aws_s3_bucket.private_logged.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "private_logged" {
  bucket        = aws_s3_bucket.private_logged.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/${aws_s3_bucket.private_logged.id}/"

  depends_on = [aws_s3_bucket_policy.logs]
}

# --- 버킷 정책 공개: S3-002 FAIL, S3-003 FAIL ---

resource "aws_s3_bucket" "public_policy" {
  count = local.public_cases

  bucket        = "${local.name}-public-policy-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "public_policy" {
  count = local.public_cases

  bucket                  = aws_s3_bucket.public_policy[0].id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false

  depends_on = [aws_s3_account_public_access_block.this]
}

resource "aws_s3_bucket_policy" "public_policy" {
  count = local.public_cases

  bucket = aws_s3_bucket.public_policy[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public_policy[0].arn}/*"
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.public_policy]
}

# --- 공개 정책 + RestrictPublicBuckets: S3-003 IsPublic 동작 확인용 ---
# 정책은 공개지만 RestrictPublicBuckets가 실제 공개를 막는다.
# RULES.md 공통 원칙상 기대값은 S3-003 FAIL(evidence에 차단 설정). IsPublic 실제 값을 이 버킷으로 확인한다.

resource "aws_s3_bucket" "restricted_policy" {
  count = local.public_cases

  bucket        = "${local.name}-restricted-policy-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "restricted_policy" {
  count = local.public_cases

  bucket                  = aws_s3_bucket.restricted_policy[0].id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = true

  depends_on = [aws_s3_account_public_access_block.this]
}

resource "aws_s3_bucket_policy" "restricted_policy" {
  count = local.public_cases

  bucket = aws_s3_bucket.restricted_policy[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.restricted_policy[0].arn}/*"
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.restricted_policy]
}

# --- ACL 공개: S3-002 FAIL, S3-006 FAIL ---

resource "aws_s3_bucket" "public_acl" {
  count = local.public_cases

  bucket        = "${local.name}-public-acl-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "public_acl" {
  count = local.public_cases

  bucket = aws_s3_bucket.public_acl[0].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "public_acl" {
  count = local.public_cases

  bucket                  = aws_s3_bucket.public_acl[0].id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = true
  restrict_public_buckets = true

  depends_on = [aws_s3_account_public_access_block.this]
}

resource "aws_s3_bucket_acl" "public_acl" {
  count = local.public_cases

  bucket = aws_s3_bucket.public_acl[0].id
  acl    = "public-read"

  depends_on = [
    aws_s3_bucket_ownership_controls.public_acl,
    aws_s3_bucket_public_access_block.public_acl,
  ]
}
