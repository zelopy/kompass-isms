# kompass 실습 환경

kompass 룰이 기대한 FAIL/PASS/REVIEW를 내는지 확인하기 위한 **의도적으로 취약한** AWS 환경이다. 1단계 통합 테스트는 아래 [기대 결과표](#기대-결과표)와 실제 결과를 비교한다.

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
| RDS 2개 (`enable_public_rds = true`일 때만) | db.t4g.micro 2대 시간당 과금 + Secrets Manager 시크릿 2개. 확인 후 바로 끈다 |

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
| `enable_public_rds` | `false` | `true` → RDS 2개 생성 (`public`: RDS-001~004 FAIL·VPC-002 REVIEW, `private`: RDS-001~004 PASS) |

## 기대 결과표

통합 테스트(`uv run pytest -m lab`)는 이 표를 옮긴 [expected.yaml](expected.yaml)을 기준으로 실제 스캔 결과를 대조한다. 표를 바꾸면 `expected.yaml`도 함께 바꾼다.

기본 변수값, 점검 리전 `ap-northeast-2`, 계정에 비밀번호 정책과 계정 수준 S3 차단 설정이 원래 없는 상태 기준. "계정 상태"는 Terraform이 만들지 않는 루트 계정 상태에 따라 달라진다. 실습 리소스가 아닌 기존 리소스의 결과는 이 표의 비교 대상이 아니다.

### IAM

실습 계정에서 기대값과 일치 확인 (2026-10-14). 배포·점검용 사용자(`kompass-lab-admin`, `security_manager`)의 결과도 함께 적는다.

| 룰 | 대상 | 기대 결과 |
|---|---|---|
| IAM-001 | 루트 계정 | 계정 상태 (루트 MFA를 설정해 두면 PASS) |
| IAM-002 | 루트 계정 | 계정 상태 (루트 액세스 키가 없으면 PASS) |
| IAM-003 | `kompass-lab-console-no-mfa` | FAIL |
| IAM-004 | 계정 비밀번호 정책 (없음) | FAIL (`NoSuchEntity`) |
| IAM-005 | 콘솔 사용자 (최근 설정된 비밀번호) | PASS |
| IAM-006 | `kompass-lab-admin`, `security_manager`의 액세스 키 | PASS (90일 안에 생성) |
| IAM-007 | `kompass-lab-direct-admin` (AdministratorAccess 직접) | FAIL |
| IAM-007 | `kompass-lab-wildcard-admin` (`*`/`*` 고객 관리형 정책 직접) | FAIL |
| IAM-007 | `kompass-lab-group-admin` (그룹 경유) | REVIEW |
| IAM-007 | `kompass-lab-notaction` (Allow + NotAction) | REVIEW |
| IAM-007 | `kompass-lab-readonly` | finding 없음 |
| IAM-007 | `kompass-lab-admin` (배포용, `admin` 그룹 경유) | REVIEW |
| IAM-008 | 루트 계정 | REVIEW. 루트 `password_last_used`가 `no_information`이라 사용 이력 확인 불가 (최근 90일 안의 사용일이 보고서에 있어도 REVIEW) |
| IAM-009 | GitHub Actions OIDC 공급자 | REVIEW |

### S3

실습 계정에서 기대값과 일치 확인 (2026-10-14). S3-005의 `logs`는 제외 옵션을 켜면 N/A 확인.

| 룰 | 대상 | 기대 결과 |
|---|---|---|
| S3-001 | 계정 (계정 수준 차단 설정 없음) | FAIL |
| S3-002 | `logs`, `private` | PASS |
| S3-002 | `public-policy`, `restricted-policy`, `public-acl` | FAIL |
| S3-003 | `public-policy` | FAIL |
| S3-003 | `restricted-policy` | FAIL (evidence에 `RestrictPublicBuckets: true`). `IsPublic=true` 확인됨 |
| S3-003 | 나머지 | PASS |
| S3-004 | 전체 | PASS (SSE-S3 기본 암호화) |
| S3-005 | `private` | PASS |
| S3-005 | `logs` | 제외 옵션을 켜면 제외, 아니면 FAIL |
| S3-005 | `public-policy`, `restricted-policy`, `public-acl` | FAIL |
| S3-006 | `public-acl` | FAIL |
| S3-006 | 나머지 | PASS (`BucketOwnerEnforced`) |
| S3-007 | `private` (HTTP 요청 거부 문장) | PASS |
| S3-007 | 나머지 (정책 없음 또는 거부 문장 없음) | FAIL |

### EC2

실습 계정에서 기대값과 일치 확인 (2026-10-13, VPC-002의 RDS 케이스 제외).

| 룰 | 대상 | 기대 결과 |
|---|---|---|
| SG-001 | `open-ssh`, `open-all` | FAIL |
| SG-001 | `open-db`, `restricted`, `public-only-workload`, 기본 SG들 | PASS |
| SG-002 | `open-all` | FAIL |
| SG-003 | `open-db` (IPv6 ::/0), `open-all` | FAIL |
| SG-004 | `mixed` VPC 기본 SG (ENI 연결, 기본 규칙 유지) | FAIL |
| SG-004 | `public-only` VPC 기본 SG (규칙 제거) | PASS |
| SG-004 | 리전 기본 VPC의 기본 SG | 실습 비교 대상 아님 |
| VPC-001 | `mixed` (프라이빗 서브넷에 ENI) | PASS |
| VPC-001 | `public-only` (퍼블릭 서브넷에만 ENI) | FAIL |
| VPC-001 | 리전 기본 VPC | 실습 비교 대상 아님 (기존 리소스가 있으면 결과가 달라진다) |
| VPC-002 | `public-only` ENI (EIP 연결) | REVIEW |
| VPC-003 | `mixed` (VPC 흐름 로그, REJECT만 기록) | PASS |
| VPC-003 | `public-only` (흐름 로그 없음) | FAIL |
| VPC-002 | 공개 RDS ENI (`enable_public_rds = true`일 때) | REVIEW (2026-10-16 확인, `RequesterId: amazon-rds`) |

### GuardDuty

| 룰 | `enable_guardduty = false` (기본) | `enable_guardduty = true` |
|---|---|---|
| GD-001 | FAIL (탐지기 없음) | PASS |
| GD-002 | N/A (GuardDuty 꺼짐) | PASS (EventBridge 규칙 → SNS 주제) |

기본값 결과는 실습 계정에서 확인했다 (2026-10-16). 실습 리전에 다른 경로로 만든 탐지기가 있으면 기본값에서도 GD-001이 PASS가 된다.

### RDS

`enable_public_rds = false`(기본)이면 RDS 룰은 리전 단위 해당 없음(N/A)이다. 아래 표는 실습 계정에서 확인했다 (2026-10-16).

| 룰 | 대상 (`enable_public_rds = true`일 때) | 기대 결과 |
|---|---|---|
| RDS-001 | `kompass-lab-public` / `kompass-lab-private` | FAIL / PASS |
| RDS-002 | `kompass-lab-public` / `kompass-lab-private` | FAIL / PASS |
| RDS-003 | `kompass-lab-public` / `kompass-lab-private` | FAIL / PASS (로그 내보내기가 없으면 `EnabledCloudwatchLogsExports` 키가 생략됨) |
| RDS-004 | `kompass-lab-public` (백업 0일) / `kompass-lab-private` (7일) | FAIL / PASS |

### CloudTrail

| 룰 | 대상 | 기대 결과 |
|---|---|---|
| CT-001 | `kompass-lab-trail` | PASS |

### KISA 항목 단위 (집계 후)

실습 리소스와 계정 단위 룰만으로 집계한 값이다. 같은 계정의 기존 리소스까지 포함한 실제 항목 결과는 이보다 나쁠 수 있다 (FAIL이 하나라도 있으면 취약).

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
