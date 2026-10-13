# 선택: 공개 RDS. VPC-002가 RDS의 ENI(RequesterManaged)를 현황에 포함하는지 확인하는 용도다.
# 시간당 과금되므로 enable_public_rds = true로 확인한 뒤 바로 false로 되돌려 apply한다.

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
  storage_encrypted           = true
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
