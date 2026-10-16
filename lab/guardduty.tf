# 선택: GuardDuty 탐지기와 결과 알림 경로 (GD-001~002, ADR-041).
# 실습 리전에 이미 탐지기가 있으면 생성이 실패한다 (리전당 하나). 그때는 이 변수를 켜지 않는다.
# SNS 주제에는 구독을 만들지 않는다. GD-002는 알림 규칙과 대상만 보고, 실제 전달은 사람이 확인한다.

resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_sns_topic" "guardduty_alerts" {
  count = var.enable_guardduty ? 1 : 0

  name = "${local.name}-guardduty-alerts"
}

resource "aws_sns_topic_policy" "guardduty_alerts" {
  count = var.enable_guardduty ? 1 : 0

  arn = aws_sns_topic.guardduty_alerts[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts[0].arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count = var.enable_guardduty ? 1 : 0

  name = "${local.name}-guardduty-findings"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_findings" {
  count = var.enable_guardduty ? 1 : 0

  rule = aws_cloudwatch_event_rule.guardduty_findings[0].name
  arn  = aws_sns_topic.guardduty_alerts[0].arn
}
