# 선택: RDS 인스턴스 2개와 수동 스냅샷 2개 (RDS-001~006, VPC-002 확인용, ADR-039·051·053).
# 시간당 과금되므로 enable_public_rds = true로 확인한 뒤 바로 false로 되돌려 apply한다.
#
# - public: 공개, 암호화 없음, 로그 내보내기 없음, 자동 백업 꺼짐, rds.force_ssl=0 그룹
#   → RDS-001~005 모두 FAIL, VPC-002 REVIEW
# - private: 비공개, 암호화, postgresql 로그 내보내기, 백업 7일, 기본 파라미터 그룹
#   → RDS-001~005 모두 PASS (PostgreSQL 15 이상 기본 그룹은 rds.force_ssl=1)
# - 스냅샷: public 인스턴스의 스냅샷을 모든 AWS 계정에 공개 → RDS-006 FAIL,
#   private 인스턴스의 스냅샷은 공유하지 않음 → RDS-006 PASS (암호화된 스냅샷은 공개할 수 없다)
#   스냅샷 안에는 빈 데이터베이스뿐이다.
# 두 인스턴스 모두 public-only VPC의 서브넷 그룹(2개 AZ)을 쓴다. private은 PubliclyAccessible만 끈다.
# 파라미터 그룹 계열이 엔진 버전과 맞아야 하므로 두 인스턴스 모두 기본 버전을 명시한다.

data "aws_rds_engine_version" "postgres" {
  count = var.enable_public_rds ? 1 : 0

  engine       = "postgres"
  default_only = true
}

resource "aws_db_parameter_group" "no_ssl" {
  count = var.enable_public_rds ? 1 : 0

  name   = "${local.name}-no-ssl"
  family = data.aws_rds_engine_version.postgres[0].parameter_group_family

  parameter {
    name  = "rds.force_ssl"
    value = "0"
  }
}

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
  engine_version              = data.aws_rds_engine_version.postgres[0].version
  parameter_group_name        = aws_db_parameter_group.no_ssl[0].name
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
  engine_version                  = data.aws_rds_engine_version.postgres[0].version
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

resource "aws_db_snapshot" "public" {
  count = var.enable_public_rds ? 1 : 0

  db_instance_identifier = aws_db_instance.public[0].identifier
  db_snapshot_identifier = "${local.name}-public-snapshot"
  shared_accounts        = ["all"]
}

resource "aws_db_snapshot" "private" {
  count = var.enable_public_rds ? 1 : 0

  db_instance_identifier = aws_db_instance.private[0].identifier
  db_snapshot_identifier = "${local.name}-private-snapshot"
}
