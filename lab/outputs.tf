output "account_id" {
  description = "실습 계정 ID (커밋하지 않는다)"
  value       = data.aws_caller_identity.current.account_id
  sensitive   = true
}

output "buckets" {
  description = "생성된 버킷 이름"
  value = {
    logs              = aws_s3_bucket.logs.id
    private_logged    = aws_s3_bucket.private_logged.id
    public_policy     = one(aws_s3_bucket.public_policy[*].id)
    restricted_policy = one(aws_s3_bucket.restricted_policy[*].id)
    public_acl        = one(aws_s3_bucket.public_acl[*].id)
  }
}

output "vpcs" {
  description = "생성된 VPC ID"
  value = {
    mixed       = aws_vpc.mixed.id
    public_only = aws_vpc.public_only.id
  }
}
