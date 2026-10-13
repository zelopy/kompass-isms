# IAM 실습 케이스. 사용자는 모두 자격증명이 없거나(콘솔 비밀번호만 있음) 권한 확인용이다.
# 액세스 키는 만들지 않는다. 시크릿이 state에 남고, 시간 기반 케이스(IAM-005, IAM-006)는 어차피 재현할 수 없다.

# --- IAM-004 비밀번호 정책 ---

locals {
  password_policies = {
    # 영문자(대·소문자) + 숫자 = KISA 기준 2종, 8자 → 10자 미만이라 FAIL
    weak = {
      minimum_password_length      = 8
      require_uppercase_characters = true
      require_lowercase_characters = true
      require_numbers              = true
      require_symbols              = false
    }
    # 영문자 + 숫자 + 특수문자 = 3종, 8자 → PASS
    kisa = {
      minimum_password_length      = 8
      require_uppercase_characters = false
      require_lowercase_characters = true
      require_numbers              = true
      require_symbols              = true
    }
  }
}

resource "aws_iam_account_password_policy" "this" {
  count = var.password_policy == "none" ? 0 : 1

  minimum_password_length        = local.password_policies[var.password_policy].minimum_password_length
  require_uppercase_characters   = local.password_policies[var.password_policy].require_uppercase_characters
  require_lowercase_characters   = local.password_policies[var.password_policy].require_lowercase_characters
  require_numbers                = local.password_policies[var.password_policy].require_numbers
  require_symbols                = local.password_policies[var.password_policy].require_symbols
  allow_users_to_change_password = true
}

# --- IAM-003 콘솔 사용자 MFA 미설정 (FAIL) ---

resource "aws_iam_user" "console_no_mfa" {
  name          = "${local.name}-console-no-mfa"
  force_destroy = true
}

resource "aws_iam_user_login_profile" "console_no_mfa" {
  user                    = aws_iam_user.console_no_mfa.name
  password_length         = 24
  password_reset_required = true

  # 비밀번호는 쓰지 않는다. 콘솔 비밀번호가 "있다"는 상태만 필요하다.
  lifecycle {
    ignore_changes = [password_length, password_reset_required]
  }
}

# --- IAM-007 관리자 권한 ---

# 직접 연결된 AdministratorAccess → FAIL
resource "aws_iam_user" "direct_admin" {
  name          = "${local.name}-direct-admin"
  force_destroy = true
}

resource "aws_iam_user_policy_attachment" "direct_admin" {
  user       = aws_iam_user.direct_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# 그룹을 거친 AdministratorAccess → REVIEW
resource "aws_iam_group" "admins" {
  name = "${local.name}-admins"
}

resource "aws_iam_group_policy_attachment" "admins" {
  group      = aws_iam_group.admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "group_admin" {
  name          = "${local.name}-group-admin"
  force_destroy = true
}

resource "aws_iam_user_group_membership" "group_admin" {
  user   = aws_iam_user.group_admin.name
  groups = [aws_iam_group.admins.name]
}

# 고객 관리형 정책 본문의 Action "*" / Resource "*"를 직접 연결 → FAIL (정책 본문 분석 확인용)
resource "aws_iam_policy" "wildcard" {
  name        = "${local.name}-wildcard"
  description = "kompass 실습: Action/Resource 와일드카드 정책"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_user" "wildcard_admin" {
  name          = "${local.name}-wildcard-admin"
  force_destroy = true
}

resource "aws_iam_user_policy_attachment" "wildcard_admin" {
  user       = aws_iam_user.wildcard_admin.name
  policy_arn = aws_iam_policy.wildcard.arn
}

# Allow + NotAction (정적 분석으로 확정하기 어려움) → REVIEW
resource "aws_iam_user" "notaction" {
  name          = "${local.name}-notaction"
  force_destroy = true
}

resource "aws_iam_user_policy" "notaction" {
  name = "${local.name}-notaction"
  user = aws_iam_user.notaction.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      NotAction = ["iam:*", "organizations:*"]
      Resource  = "*"
    }]
  })
}

# 일반 권한 사용자 → finding 없음
resource "aws_iam_user" "readonly" {
  name          = "${local.name}-readonly"
  force_destroy = true
}

resource "aws_iam_user_policy_attachment" "readonly" {
  user       = aws_iam_user.readonly.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# --- IAM-009 외부 자격증명 공급자 (REVIEW) ---

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}
