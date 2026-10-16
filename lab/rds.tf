# 선택: RDS 인스턴스 2개 (RDS-001~004, VPC-002 확인용, ADR-039).
# 시간당 과금되므로 enable_public_rds = true로 확인한 뒤 바로 false로 되돌려 apply한다.
#
# - public: 공개, 암호화 없음, 로그 내보내기 없음, 자동 백업 꺼짐 → RDS-001~004 모두 FAIL, VPC-002 REVIEW
# - private: 비공개, 암호화, postgresql 로그 내보내기, 백업 7일 → RDS-001~004 모두 PASS
# 두 인스턴스 모두 public-only VPC의 서브넷 그룹(2개 AZ)을 쓴다. private은 PubliclyAccessible만 끈다.

resource "aws_db_subnet_group" "public" {
  count = var.enable_public_rds ? 1 : 0

  name       = "${local.name}-public"
  subnet_ids = aws_subnet.public_only[*].id
}

resource "aws_security_group" "rds" {
  count = var.enable_public_rds ? 1 : 0

  name        = "${local.name}-rds"
  description = "kompass lab: RDS without inbound rules"
  vpc_id      = aws_vpc.public_only.id
}

resource "aws_db_instance" "public" {
  count = var.enable_public_rds ? 1 : 0

  identifier                  = "${local.name}-public"
  engine                      = "postgres"
  instance_class              = "db.t4g.micro"
  allocated_storage           = 20
  storage_encrypted           = false
  username                    = "kompass"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.public[0].name
  vpc_security_group_ids      = [aws_security_group.rds[0].id]
  publicly_accessible         = true
  skip_final_snapshot         = true
  backup_retention_period     = 0
  apply_immediately           = true

  depends_on = [aws_route_table_association.public_only]
}

# 로그 내보내기가 만드는 로그 그룹을 Terraform이 먼저 만들어 destroy 때 함께 지운다
resource "aws_cloudwatch_log_group" "rds_private" {
  count = var.enable_public_rds ? 1 : 0

  name              = "/aws/rds/instance/${local.name}-private/postgresql"
  retention_in_days = 1
}

resource "aws_db_instance" "private" {
  count = var.enable_public_rds ? 1 : 0

  identifier                      = "${local.name}-private"
  engine                          = "postgres"
  instance_class                  = "db.t4g.micro"
  allocated_storage               = 20
  storage_encrypted               = true
  username                        = "kompass"
  manage_master_user_password     = true
  db_subnet_group_name            = aws_db_subnet_group.public[0].name
  vpc_security_group_ids          = [aws_security_group.rds[0].id]
  publicly_accessible             = false
  enabled_cloudwatch_logs_exports = ["postgresql"]
  backup_retention_period         = 7
  delete_automated_backups        = true
  skip_final_snapshot             = true
  apply_immediately               = true

  depends_on = [aws_cloudwatch_log_group.rds_private]
}
