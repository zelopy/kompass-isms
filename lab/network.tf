# EC2 네트워크 실습 케이스. EC2 인스턴스와 NAT 게이트웨이는 만들지 않는다 (비용).
# 리소스 존재는 독립 네트워크 인터페이스(ENI)로 흉내 낸다. 연결되지 않은 ENI는 과금되지 않는다.

# ===== VPC "mixed": 퍼블릭 + 프라이빗 서브넷 → VPC-001 PASS =====

resource "aws_vpc" "mixed" {
  cidr_block = "10.10.0.0/16"
  tags       = { Name = "${local.name}-mixed" }
}

resource "aws_internet_gateway" "mixed" {
  vpc_id = aws_vpc.mixed.id
  tags   = { Name = "${local.name}-mixed" }
}

resource "aws_subnet" "mixed_public" {
  vpc_id            = aws_vpc.mixed.id
  cidr_block        = "10.10.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "${local.name}-mixed-public" }
}

resource "aws_route_table" "mixed_public" {
  vpc_id = aws_vpc.mixed.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.mixed.id
  }
  tags = { Name = "${local.name}-mixed-public" }
}

resource "aws_route_table_association" "mixed_public" {
  subnet_id      = aws_subnet.mixed_public.id
  route_table_id = aws_route_table.mixed_public.id
}

# 명시적 연결이 없으므로 VPC 기본 라우팅 테이블(IGW 경로 없음)을 쓴다 → 프라이빗
resource "aws_subnet" "mixed_private" {
  vpc_id            = aws_vpc.mixed.id
  cidr_block        = "10.10.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "${local.name}-mixed-private" }
}

# --- 보안그룹 (mixed VPC) ---

# SG-001 FAIL: 22/tcp 0.0.0.0/0
resource "aws_security_group" "open_ssh" {
  name        = "${local.name}-open-ssh"
  description = "kompass lab: SSH open to the world"
  vpc_id      = aws_vpc.mixed.id
}

resource "aws_vpc_security_group_ingress_rule" "open_ssh" {
  security_group_id = aws_security_group.open_ssh.id
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}

# SG-001·SG-002·SG-003 FAIL: 모든 프로토콜 0.0.0.0/0
resource "aws_security_group" "open_all" {
  name        = "${local.name}-open-all"
  description = "kompass lab: all traffic open to the world"
  vpc_id      = aws_vpc.mixed.id
}

resource "aws_vpc_security_group_ingress_rule" "open_all" {
  security_group_id = aws_security_group.open_all.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# SG-003 FAIL: 3306/tcp ::/0 (IPv6 전체 개방 확인용)
resource "aws_security_group" "open_db" {
  name        = "${local.name}-open-db"
  description = "kompass lab: MySQL open to the IPv6 world"
  vpc_id      = aws_vpc.mixed.id
}

resource "aws_vpc_security_group_ingress_rule" "open_db" {
  security_group_id = aws_security_group.open_db.id
  ip_protocol       = "tcp"
  from_port         = 3306
  to_port           = 3306
  cidr_ipv6         = "::/0"
}

# SG-001~003 PASS: 사설 대역에서만 SSH
resource "aws_security_group" "restricted" {
  name        = "${local.name}-restricted"
  description = "kompass lab: SSH from private range only"
  vpc_id      = aws_vpc.mixed.id
}

resource "aws_vpc_security_group_ingress_rule" "restricted" {
  security_group_id = aws_security_group.restricted.id
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "10.0.0.0/8"
}

# 프라이빗 서브넷의 리소스. open_ssh(연결된 SG 예시)와 VPC 기본 SG를 붙인다.
# 기본 SG는 AWS 기본 규칙을 그대로 두므로 "사용 중인 기본 SG에 규칙 존재" → SG-004 FAIL
resource "aws_network_interface" "mixed_private" {
  subnet_id = aws_subnet.mixed_private.id
  security_groups = [
    aws_security_group.open_ssh.id,
    aws_vpc.mixed.default_security_group_id,
  ]
  description = "kompass lab: workload in private subnet"
  tags        = { Name = "${local.name}-mixed-private" }
}

# ===== VPC "public-only": 퍼블릭 서브넷만 → VPC-001 FAIL =====

resource "aws_vpc" "public_only" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_hostnames = true # 공개 RDS(선택)의 필수 조건
  tags                 = { Name = "${local.name}-public-only" }
}

resource "aws_internet_gateway" "public_only" {
  vpc_id = aws_vpc.public_only.id
  tags   = { Name = "${local.name}-public-only" }
}

# 기본 SG의 규칙을 모두 제거 → SG-004 PASS (사용 중이어도 규칙 없음)
resource "aws_default_security_group" "public_only" {
  vpc_id = aws_vpc.public_only.id
}

resource "aws_route_table" "public_only" {
  vpc_id = aws_vpc.public_only.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.public_only.id
  }
  tags = { Name = "${local.name}-public-only" }
}

# RDS 서브넷 그룹을 위해 AZ 두 곳에 퍼블릭 서브넷을 둔다
resource "aws_subnet" "public_only" {
  count = 2

  vpc_id            = aws_vpc.public_only.id
  cidr_block        = "10.20.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "${local.name}-public-only-${count.index}" }
}

resource "aws_route_table_association" "public_only" {
  count = 2

  subnet_id      = aws_subnet.public_only[count.index].id
  route_table_id = aws_route_table.public_only.id
}

resource "aws_security_group" "public_only_workload" {
  name        = "${local.name}-public-only-workload"
  description = "kompass lab: no inbound rules"
  vpc_id      = aws_vpc.public_only.id
}

resource "aws_network_interface" "public_only" {
  subnet_id       = aws_subnet.public_only[0].id
  security_groups = [aws_security_group.public_only_workload.id, aws_default_security_group.public_only.id]
  description     = "kompass lab: workload in public-only VPC"
  tags            = { Name = "${local.name}-public-only" }
}

# VPC-002 REVIEW: 공인 IP가 할당된 ENI. 퍼블릭 IPv4는 시간당 과금된다 (약 월 3.6달러).
resource "aws_eip" "public_only" {
  domain            = "vpc"
  network_interface = aws_network_interface.public_only.id
  tags              = { Name = "${local.name}-public-only" }

  depends_on = [aws_internet_gateway.public_only]
}
