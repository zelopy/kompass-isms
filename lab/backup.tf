# 선택: AWS Backup 계획 2개와 백업 대상 DynamoDB 테이블 (BKP-001~003, ADR-054).
# - daily: 매시 정각 백업, 보존 35일, 테이블 선택 → BKP-001 PASS, BKP-002 PASS, BKP-003 PASS(첫 백업 뒤)
# - short: 보존 1일, 선택 없음 → BKP-002 FAIL (daily가 있어 BKP-001은 PASS)
# 첫 백업은 apply 뒤 다음 정각부터 시작 창(60분) 안에 돈다. 그 전에 점검하면 BKP-003이 리전 FAIL이다.
# 테이블은 비어 있어 백업 저장 비용은 사실상 0이다. destroy 때 저장소의 복구 지점도 함께 지운다.

resource "aws_dynamodb_table" "backup_target" {
  count = var.enable_backup ? 1 : 0

  name         = "${local.name}-backup"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_backup_vault" "this" {
  count = var.enable_backup ? 1 : 0

  name          = "${local.name}-vault"
  force_destroy = true
}

resource "aws_backup_plan" "daily" {
  count = var.enable_backup ? 1 : 0

  name = "${local.name}-daily"

  rule {
    rule_name         = "hourly-35d"
    target_vault_name = aws_backup_vault.this[0].name
    schedule          = "cron(0 * ? * * *)"
    start_window      = 60
    completion_window = 180

    lifecycle {
      delete_after = 35
    }
  }
}

resource "aws_backup_plan" "short" {
  count = var.enable_backup ? 1 : 0

  name = "${local.name}-short"

  rule {
    rule_name         = "daily-1d"
    target_vault_name = aws_backup_vault.this[0].name
    schedule          = "cron(0 5 ? * * *)"

    lifecycle {
      delete_after = 1
    }
  }
}

resource "aws_iam_role" "backup" {
  count = var.enable_backup ? 1 : 0

  name = "${local.name}-backup"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  count = var.enable_backup ? 1 : 0

  role       = aws_iam_role.backup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_selection" "daily" {
  count = var.enable_backup ? 1 : 0

  name         = "${local.name}-tables"
  plan_id      = aws_backup_plan.daily[0].id
  iam_role_arn = aws_iam_role.backup[0].arn
  resources    = [aws_dynamodb_table.backup_target[0].arn]
}
