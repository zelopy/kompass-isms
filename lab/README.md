# kompass 실습 환경

kompass 룰이 기대한 FAIL/PASS/REVIEW를 내는지 확인하기 위한 **의도적으로 취약한** AWS 환경이다. 1단계 통합 테스트는 아래 [기대 결과표](#기대-결과표)와 실제 결과를 비교한다.

> **경고**
> - **실습 전용 AWS 계정**에서만 배포한다. 이 구성은 계정 전체 설정(IAM 비밀번호 정책, 계정 수준 S3 퍼블릭 액세스 차단)을 바꾸고, 퍼블릭 버킷과 관리자 권한 IAM 사용자를 만든다.
> - `terraform apply`/`destroy`는 사용자가 직접 실행한다. Claude Code는 이 디렉터리의 코드를 작성·수정만 한다 (CLAUDE.md 원칙 6).
> - state 파일에는 IAM 사용자 초기 비밀번호 등 민감 정보가 들어간다. `*.tfstate`는 `.gitignore` 대상이며 커밋하지 않는다.

## 비용

| 리소스 | 비용 |
|---|---|
| 공인 IPv4 1개 (`aws_eip.public_only`) | 시간당 과금, 월 약 3.6달러 |
| CloudTrail 첫 관리 이벤트 추적 | 추적 요금 없음, S3 저장 비용만 발생 |
| S3 버킷, VPC, 서브넷, 보안그룹, 연결되지 않은 ENI, IAM | 무료 또는 사실상 0 |
| 공개 RDS (`enable_public_rds = true`일 때만) | db.t4g.micro 시간당 과금 + Secrets Manager 시크릿. 확인 후 바로 끈다 |

EC2 인스턴스, NAT 게이트웨이, 로드 밸런서는 만들지 않는다. 리소스 존재는 연결되지 않은 네트워크 인터페이스로 흉내 낸다.

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
- 정리: `terraform destroy`. 계정 비밀번호 정책과 계정 수준 퍼블릭 액세스 차단 설정도 함께 삭제된다.

## 변수로 바꿀 수 있는 케이스

| 변수 | 기본값 | 바꾸면 |
|---|---|---|
| `password_policy` | `weak` | `kisa` → IAM-004 PASS, `none` → IAM-004 FAIL (정책 없음) |
| `account_block_public_access` | `false` | `true` → S3-001 PASS. 대신 퍼블릭 버킷 3개가 생성되지 않는다 |
| `cloudtrail_enabled` | `true` | `false` → CT-001 FAIL (로깅 중지) |
| `cloudtrail_read_write_type` | `All` | `WriteOnly` → CT-001 FAIL (`require_read_events: true`일 때) |
| `enable_public_rds` | `false` | `true` → VPC-002에 RDS 인터페이스 REVIEW 추가 |

## 기대 결과표

기본 변수값, 점검 리전 `ap-northeast-2` 기준. "계정 상태"는 Terraform이 만들지 않는 루트 계정 상태에 따라 달라진다.

### IAM

| 룰 | 대상 | 기대 결과 |
|---|---|---|
| IAM-001 | 루트 계정 | 계정 상태 (루트 MFA를 설정해 두면 PASS) |
| IAM-002 | 루트 계정 | 계정 상태 (루트 액세스 키가 없으면 PASS) |
| IAM-003 | `kompass-lab-console-no-mfa` | FAIL |
| IAM-004 | 계정 비밀번호 정책 (영문자+숫자 2종, 8자) | FAIL |
| IAM-005 | 콘솔 사용자 (최근 설정된 비밀번호) | PASS |
| IAM-006 | 액세스 키 없음 | N/A (실습 계정에 다른 키가 없다면) |
| IAM-007 | `kompass-lab-direct-admin` (AdministratorAccess 직접) | FAIL |
| IAM-007 | `kompass-lab-wildcard-admin` (`*`/`*` 고객 관리형 정책 직접) | FAIL |
| IAM-007 | `kompass-lab-group-admin` (그룹 경유) | REVIEW |
| IAM-007 | `kompass-lab-notaction` (Allow + NotAction) | REVIEW |
| IAM-007 | `kompass-lab-readonly` | finding 없음 |
| IAM-008 | 루트 계정 | 계정 상태 (계정 생성·설정에 최근 90일 안에 루트를 썼으면 REVIEW) |
| IAM-009 | GitHub Actions OIDC 공급자 | REVIEW |

### S3

| 룰 | 대상 | 기대 결과 |
|---|---|---|
| S3-001 | 계정 | FAIL |
| S3-002 | `logs`, `private` | PASS |
| S3-002 | `public-policy`, `restricted-policy`, `public-acl` | FAIL |
| S3-003 | `public-policy` | FAIL |
| S3-003 | `restricted-policy` | FAIL (evidence에 `RestrictPublicBuckets: true`). **`IsPublic` 실제 값 확인 대상** |
| S3-003 | 나머지 | PASS |
| S3-004 | 전체 | PASS (SSE-S3 기본 암호화) |
| S3-005 | `private` | PASS |
| S3-005 | `logs` | 제외 옵션을 켜면 제외, 아니면 FAIL |
| S3-005 | `public-policy`, `restricted-policy`, `public-acl` | FAIL |
| S3-006 | `public-acl` | FAIL |
| S3-006 | 나머지 | PASS (`BucketOwnerEnforced`) |

### EC2

| 룰 | 대상 | 기대 결과 |
|---|---|---|
| SG-001 | `open-ssh`, `open-all` | FAIL |
| SG-001 | `open-db`, `restricted`, `public-only-workload`, 기본 SG들 | PASS |
| SG-002 | `open-all` | FAIL |
| SG-003 | `open-db` (IPv6 ::/0), `open-all` | FAIL |
| SG-004 | `mixed` VPC 기본 SG (ENI 연결, 기본 규칙 유지) | FAIL |
| SG-004 | `public-only` VPC 기본 SG (규칙 제거) | PASS |
| SG-004 | 리전 기본 VPC의 기본 SG (연결 없음) | PASS |
| VPC-001 | `mixed` (프라이빗 서브넷에 ENI) | PASS |
| VPC-001 | `public-only` (퍼블릭 서브넷에만 ENI) | FAIL |
| VPC-001 | 리전 기본 VPC (ENI 없음) | N/A |
| VPC-002 | `public-only` ENI (EIP 연결) | REVIEW |
| VPC-002 | 공개 RDS ENI (`enable_public_rds = true`일 때) | REVIEW. **RDS ENI 필드값 확인 대상** |

### CloudTrail

| 룰 | 대상 | 기대 결과 |
|---|---|---|
| CT-001 | `kompass-lab-trail` | PASS |

### KISA 항목 단위 (집계 후)

| 항목 | 분류 | 기대 결과 | 이유 |
|---|---|---|---|
| CA-01 | partial | 검토 필요 | IAM-005 PASS → partial 상한 |
| CA-02 | partial | 취약 | IAM-007 FAIL |
| CA-03 | full | 취약 | IAM-003 FAIL |
| CA-04 | partial | 취약 | IAM-004 FAIL |
| CA-07 | partial | 취약 | VPC-001 FAIL |
| CA-08 | partial | 검토 필요 | VPC-002 REVIEW |
| CA-09 | partial | 취약 | SG-001~003 FAIL |
| CA-10 | partial | 취약 | S3-001~003, S3-006 FAIL |
| CA-13 | full | 양호 | CT-001 PASS |
| CA-16 | full | 취약 | S3-005 FAIL |

## Terraform으로 재현하지 않는 케이스

| 케이스 | 이유 | 대신 |
|---|---|---|
| 루트 MFA·액세스 키·최근 사용 (IAM-001, 002, 008) | 루트 계정은 Terraform으로 관리할 수 없다 | 계정 상태를 그대로 점검하고, 단위 테스트에서 PASS/FAIL 모두 검증 |
| MFA가 설정된 콘솔 사용자 (IAM-003 PASS) | 가상 MFA 활성화에 OTP 코드 입력이 필요하다 | 필요하면 콘솔에서 수동 설정. 단위 테스트로 검증 |
| 90일 이상 미사용·미교체 자격증명 (IAM-005, 006 FAIL) | 시간이 지나야 생긴다 | 자격증명 보고서 픽스처로 단위 테스트 |
| 루트 자격증명이 삭제된 멤버 계정 (IAM-001 N/A) | Organizations 환경이 필요하다 | 단위 테스트 |
| 조직 추적 (CT-001 섀도 추적) | Organizations 환경이 필요하다 | 단위 테스트, 조직 환경에서 별도 확인 |
| SSE-KMS 버킷 (S3-004 `require_kms`) | KMS 키 월 요금 | 단위 테스트 |
