# kompass 실습 환경

kompass 룰이 기대한 FAIL/PASS/REVIEW를 내는지 확인하기 위한 **의도적으로 취약한** AWS 환경이다. 통합 테스트는 아래 [기대 결과표](#기대-결과표)와 실제 결과를 비교한다.

> **경고**
> - 퍼블릭 버킷과 관리자 권한 IAM 사용자를 만든다. 가능하면 실습 전용 AWS 계정에 배포한다.
> - **다른 서비스와 같은 계정에 배포할 때는 계정 단위 변수를 기본값으로 둔다.** 기본값에서는 IAM 비밀번호 정책과 계정 수준 S3 퍼블릭 액세스 차단을 만들지 않으므로, 기존 사용자·버킷·서비스에 적용되는 설정이 바뀌지 않는다. 실습 리소스는 모두 별도 VPC와 `kompass-lab-` 접두사 이름으로 만들어져 기존 리소스와 겹치지 않는다 (아래 [다른 서비스와 같은 계정에 배포할 때](#다른-서비스와-같은-계정에-배포할-때) 참고).
> - `terraform apply`/`destroy`는 사용자가 직접 실행한다. Claude Code는 이 디렉터리의 코드를 작성·수정만 한다 (CLAUDE.md 원칙 6).
> - state 파일에는 IAM 사용자 초기 비밀번호 등 민감 정보가 들어간다. `*.tfstate`는 `.gitignore` 대상이며 커밋하지 않는다.

## 비용

| 리소스 | 비용 |
|---|---|
| 공인 IPv4 1개 (`aws_eip.public_only`) | 시간당 과금, 월 약 3.6달러 |
| CloudTrail 첫 관리 이벤트 추적 | 추적 요금 없음, S3 저장 비용만 발생 |
| S3 버킷, VPC, 서브넷, 보안그룹, 연결되지 않은 ENI, IAM | 무료 또는 사실상 0 |
| GuardDuty (`enable_guardduty = true`일 때만) | 30일 무료 체험 뒤 분석한 이벤트량에 따라 과금. 확인 후 끈다 |
| AWS Backup 계획 2개·저장소·빈 DynamoDB 테이블 (`enable_backup = true`일 때만) | 온디맨드 테이블과 빈 테이블 백업이라 사실상 0. 매시 백업이 쌓이므로 확인 후 끈다 |
| ALB 2개 (`enable_elb = true`일 때만) | ALB 2대 시간당 과금(LCU 포함). 확인 후 바로 끈다 |
| RDS 2개와 수동 스냅샷 2개 (`enable_public_rds = true`일 때만) | db.t4g.micro 2대 시간당 과금 + Secrets Manager 시크릿 2개 + 스냅샷 저장(빈 DB라 매우 적음). 확인 후 바로 끈다 |

EC2 인스턴스와 NAT 게이트웨이는 만들지 않는다. 리소스 존재는 연결되지 않은 네트워크 인터페이스로 흉내 낸다. 로드 밸런서·RDS·GuardDuty·AWS Backup은 해당 `enable_*` 변수를 켰을 때만 만든다.

## 사용법

```bash
cd lab
cp terraform.tfvars.example terraform.tfvars   # 프로필 이름 등 수정
terraform init
terraform plan
terraform apply
```

- 배포 프로필은 관리자 권한이 필요하다. kompass 점검은 별도의 `SecurityAudit` 전용 프로필로 실행한다.
- 다른 리전의 기본 VPC 결과가 섞이지 않도록 점검은 `--regions ap-northeast-2`로 한정한다.
- 정리: `terraform destroy`. 계정 단위 변수를 바꿔서 만든 비밀번호 정책·계정 수준 차단 설정은 함께 **삭제**된다 (원래 값으로 복구되지 않는다).

## 변수로 바꿀 수 있는 케이스

| 변수 | 기본값 | 바꾸면 |
|---|---|---|
| `password_policy` | `none` | `weak` → IAM-004 FAIL (2종 8자), `kisa` → IAM-004 PASS. **계정의 모든 IAM 사용자에게 적용** |
| `manage_account_public_access_block` | `false` | `true` → 계정 수준 차단을 Terraform이 관리. **계정의 모든 버킷에 적용** |
| `account_block_public_access` | `false` | 위 변수가 `true`일 때 `true` → S3-001 PASS. 대신 퍼블릭 버킷 3개가 생성되지 않는다 |
| `cloudtrail_enabled` | `true` | `false` → CT-001 FAIL (로깅 중지) |
| `cloudtrail_read_write_type` | `All` | `WriteOnly` → CT-001 FAIL (`require_read_events: true`일 때) |
| `enable_guardduty` | `false` | `true` → GuardDuty 탐지기 + 결과 알림 규칙(EventBridge → SNS) 생성: GD-001·GD-002 PASS |
| `enable_elb` | `false` | `true` → internal ALB 2개 생성 (`weak`: ELB-001·002 FAIL, `strict`: ELB-001·002 PASS). `tls` provider로 만든 자체 서명 인증서를 ACM으로 가져옴 |
| `enable_backup` | `false` | `true` → AWS Backup 계획 2개 생성 (`daily`: 매시 백업·보존 35일·테이블 선택, `short`: 보존 1일·선택 없음). BKP-001 PASS, BKP-002 `daily` PASS·`short` FAIL, 첫 백업 뒤 BKP-003 PASS |
| `enable_public_rds` | `false` | `true` → RDS 2개와 수동 스냅샷 2개 생성 (`public`: RDS-001~005 FAIL·VPC-002 REVIEW, 공개 스냅샷 RDS-006 FAIL, `private`: RDS-001~006 PASS) |

## 기대 결과표

룰별 기대 결과는 [expected.yaml](expected.yaml)에 있다. 통합 테스트(`uv run pytest -m lab`)가 이 파일을 기준으로 실제 스캔 결과를 대조하며, 결과가 그렇게 나오는 이유와 실습 계정에서 확인한 AWS 동작은 파일 안 주석에 적는다.

- 대조 대상은 이름이 `kompass-lab-`으로 시작하는 리소스와 계정 단위 룰이다. 리전 기본 VPC 같은 기존 리소스의 결과는 대조하지 않는다.
- 루트 계정 룰(IAM-001·002·008)은 Terraform으로 만들 수 없어 계정 상태에 따른다.
- 선택 변수(`enable_*`)에 따라 달라지는 기대값은 `when`으로 구분한다. 테스트는 `terraform.tfvars`의 값을 읽는다.
- KISA 항목 단위 결과는 대조하지 않는다. 항목 집계 규칙은 단위 테스트(`tests/mappings/`)가 검사한다.

## 다른 서비스와 같은 계정에 배포할 때

계정 단위 변수를 기본값으로 두면 기존 서비스에 적용되는 설정은 바뀌지 않는다. 남는 고려사항은 다음과 같다.

| 항목 | 내용 |
|---|---|
| 기존 리소스 | Terraform은 새 리소스만 만든다 (`plan`에서 change 0, destroy 0 확인). 실습 VPC는 기존 VPC와 분리되어 있어 실습 보안그룹을 기존 인스턴스에 붙일 수 없다 |
| CloudTrail | 계정에 추적이 없으면 이 추적이 첫 추적이 되어 기존 서비스의 활동도 기록된다. 추적 요금은 없다. destroy하면 함께 삭제된다 |
| 관리자 권한 실습 사용자 | 비밀번호·액세스 키가 없어 로그인할 수 없다. 콘솔 비밀번호가 있는 `console-no-mfa`는 권한이 없다 |
| 배포용 관리자 키 | `kompass-lab-admin` 액세스 키가 유출되면 기존 서비스까지 위험하다. apply/destroy할 때만 활성화하고 평소에는 비활성화한다 |
| 서비스 한도 | VPC 2개, EIP 1개를 추가로 쓴다 (리전 기본 한도: VPC 5개, EIP 5개) |
| 점검 결과 | kompass는 계정 전체를 점검하므로 기존 리소스의 결과도 나온다. 통합 테스트는 이름이 `kompass-lab-`으로 시작하는 리소스와 계정 단위 룰만 기대 결과표와 비교한다. 기존 리소스의 결과는 실계정 점검 결과로 따로 본다 |

## Terraform으로 재현하지 않는 케이스

| 케이스 | 이유 | 대신 |
|---|---|---|
| 루트 MFA·액세스 키·최근 사용 (IAM-001, 002, 008) | 루트 계정은 Terraform으로 관리할 수 없다 | 계정 상태를 그대로 점검하고, 단위 테스트에서 PASS/FAIL 모두 검증 |
| MFA가 설정된 콘솔 사용자 (IAM-003 PASS) | 가상 MFA 활성화에 OTP 코드 입력이 필요하다 | 필요하면 콘솔에서 수동 설정. 단위 테스트로 검증 |
| 90일 이상 미사용·미교체 자격증명 (IAM-005, 006 FAIL) | 시간이 지나야 생긴다 | 자격증명 보고서 픽스처로 단위 테스트 |
| 루트 자격증명이 삭제된 멤버 계정 (IAM-001 N/A) | Organizations 환경이 필요하다 | 단위 테스트 |
| 조직 추적 (CT-001 섀도 추적) | Organizations 환경이 필요하다 | 단위 테스트, 조직 환경에서 별도 확인 |
| SSE-KMS 버킷 (S3-004 `require_kms`) | KMS 키 월 요금 | 단위 테스트 |
