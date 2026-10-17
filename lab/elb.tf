# 선택: ALB 2개 (ELB-001~002 확인용, ADR-052).
# 시간당 과금되므로 enable_elb = true로 확인한 뒤 바로 false로 되돌려 apply한다.
#
# - weak: HTTP:80 → 대상 그룹 전달, HTTPS:443 ELBSecurityPolicy-2016-08 (TLS 1.0·1.1 허용)
#   → ELB-001 FAIL, ELB-002 FAIL
# - strict: HTTP:80 → HTTPS 리디렉션, HTTPS:443 ELBSecurityPolicy-TLS13-1-2-2021-06
#   → ELB-001 PASS, ELB-002 PASS
# 두 ALB 모두 internal이라 공인 IP가 없다 (VPC-002 결과가 바뀌지 않음). 보안그룹은 인바운드 규칙이
# 없어 실제로는 접속할 수 없다. HTTPS 리스너용 인증서는 자체 서명 인증서를 ACM으로 가져온다.

resource "tls_private_key" "elb" {
  count = var.enable_elb ? 1 : 0

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "elb" {
  count = var.enable_elb ? 1 : 0

  private_key_pem       = tls_private_key.elb[0].private_key_pem
  validity_period_hours = 24 * 30
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]

  subject {
    common_name  = "kompass-lab.example.com"
    organization = "kompass lab"
  }
}

resource "aws_acm_certificate" "elb" {
  count = var.enable_elb ? 1 : 0

  private_key      = tls_private_key.elb[0].private_key_pem
  certificate_body = tls_self_signed_cert.elb[0].cert_pem
  tags             = { Name = "${local.name}-elb" }
}

resource "aws_security_group" "elb" {
  count = var.enable_elb ? 1 : 0

  name        = "${local.name}-elb"
  description = "kompass lab: load balancers, no inbound rules"
  vpc_id      = aws_vpc.public_only.id
}

resource "aws_lb_target_group" "elb" {
  count = var.enable_elb ? 1 : 0

  name     = "${local.name}-web"
  protocol = "HTTP"
  port     = 80
  vpc_id   = aws_vpc.public_only.id
}

locals {
  elb = {
    weak   = { ssl_policy = "ELBSecurityPolicy-2016-08", redirect = false }
    strict = { ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06", redirect = true }
  }
}

resource "aws_lb" "elb" {
  for_each = var.enable_elb ? local.elb : {}

  name               = "${local.name}-${each.key}"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.elb[0].id]
  subnets            = aws_subnet.public_only[*].id
}

resource "aws_lb_listener" "http" {
  for_each = aws_lb.elb

  load_balancer_arn = each.value.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = local.elb[each.key].redirect ? "redirect" : "forward"
    target_group_arn = local.elb[each.key].redirect ? null : aws_lb_target_group.elb[0].arn

    dynamic "redirect" {
      for_each = local.elb[each.key].redirect ? [1] : []
      content {
        protocol    = "HTTPS"
        port        = "443"
        status_code = "HTTP_301"
      }
    }
  }
}

resource "aws_lb_listener" "https" {
  for_each = aws_lb.elb

  load_balancer_arn = each.value.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = local.elb[each.key].ssl_policy
  certificate_arn   = aws_acm_certificate.elb[0].arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      status_code  = "404"
    }
  }
}
