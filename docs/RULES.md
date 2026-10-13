# 점검 룰 카탈로그

1단계에서 구현할 초기 룰 목록이다. **ISMS-P 매핑은 초안**이며, KISA 항목코드는 0단계에서 가이드 원문을 확인한 뒤 채운다. 원문 근거를 확인하기 전까지 모든 룰은 `verified: false`다.

판정 기준값(일수, 길이 등)은 `kompass.yaml` 설정을 따르며, 아래 값은 기본값이다.

## IAM

### IAM-001 루트 계정 MFA 미설정
- 심각도: critical
- API: `iam:GetAccountSummary`
- 판정: `SummaryMap.AccountMFAEnabled == 1`이면 PASS
- ISMS-P(초안): 2.5.3 사용자 인증, 2.5.5 특수 계정 및 권한 관리
- KISA: (미정)

### IAM-002 루트 계정 액세스 키 존재
- 심각도: critical
- API: `iam:GetAccountSummary`
- 판정: `SummaryMap.AccountAccessKeysPresent == 0`이면 PASS
- ISMS-P(초안): 2.5.5 특수 계정 및 권한 관리
- KISA: (미정)

### IAM-003 콘솔 사용자 MFA 미설정
- 심각도: high
- API: `iam:GenerateCredentialReport`, `iam:GetCredentialReport`
- 판정: `password_enabled == true`인 사용자 중 `mfa_active == false`인 사용자가 없으면 PASS. 사용자별 finding 생성.
- ISMS-P(초안): 2.5.3 사용자 인증
- KISA: (미정)

### IAM-004 비밀번호 정책 미흡
- 심각도: medium
- API: `iam:GetAccountPasswordPolicy`
- 판정: 정책이 없으면(NoSuchEntity) FAIL. 있으면 최소 길이와 문자 종류 수가 설정 기준 이상이면 PASS. 기본값은 3종류 8자 이상.
- 주의: `NoSuchEntity`는 ERROR가 아니라 FAIL이다. 정책 미설정이 곧 취약 상태다.
- ISMS-P(초안): 2.5.4 비밀번호 관리
- KISA: (미정)

### IAM-005 장기 미사용 자격증명
- 심각도: medium
- API: 자격증명 보고서
- 판정: 비밀번호 또는 활성 액세스 키의 마지막 사용일(사용 이력 없으면 생성일)이 90일을 초과하면 FAIL. 사용자별 finding.
- ISMS-P(초안): 2.5.1 사용자 계정 관리, 2.5.6 접근권한 검토
- KISA: (미정)

### IAM-006 액세스 키 교체 주기 초과
- 심각도: medium
- API: 자격증명 보고서
- 판정: 활성 액세스 키의 `last_rotated`가 90일을 초과하면 FAIL. 키별 finding.
- ISMS-P(초안): 2.5.3 사용자 인증
- KISA: (미정)

### IAM-007 관리자 권한 사용자 현황
- 심각도: high
- API: `iam:ListUsers`, `iam:ListAttachedUserPolicies`, `iam:ListGroupsForUser`, `iam:ListAttachedGroupPolicies`, `iam:ListUserPolicies`, `iam:GetUserPolicy`
- 판정: `AdministratorAccess` 또는 `Action: "*"`, `Resource: "*"` 정책을 직접·그룹 경유로 가진 사용자를 식별한다. 사용자에게 직접 연결된 경우 FAIL, 그룹 경유는 `REVIEW`로 현황 보고.
- 비고: 관리자 수의 적정성은 사람이 판단할 영역이므로, 현황 증적 제공이 주목적이다. (`automation: partial`)
- ISMS-P(초안): 2.5.5 특수 계정 및 권한 관리
- KISA: (미정)

## S3

### S3-001 계정 수준 퍼블릭 액세스 차단 미설정
- 심각도: high
- API: `s3control:GetPublicAccessBlock`
- 판정: 4개 설정(`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`)이 모두 true이면 PASS. 설정 없음(`NoSuchPublicAccessBlockConfiguration`)은 FAIL.
- ISMS-P(초안): 2.6.x (원문 확인 필요)
- KISA: (미정)

### S3-002 버킷 수준 퍼블릭 액세스 차단 미설정
- 심각도: high
- API: `s3:ListBuckets`, `s3:GetPublicAccessBlock`
- 판정: 버킷별로 4개 설정이 모두 true이면 PASS. 계정 수준이 모두 true이면 버킷 수준이 없어도 PASS로 보되, evidence에 계정 수준 설정을 함께 남긴다.
- ISMS-P(초안): 2.6.x (원문 확인 필요)
- KISA: (미정)

### S3-003 버킷 정책에 의한 퍼블릭 노출
- 심각도: critical
- API: `s3:GetBucketPolicyStatus`
- 판정: `PolicyStatus.IsPublic == false`이거나 정책이 없으면 PASS
- ISMS-P(초안): 2.6.x (원문 확인 필요)
- KISA: (미정)

### S3-004 기본 암호화 설정
- 심각도: medium
- API: `s3:GetBucketEncryption`
- 판정: 기본 암호화 설정이 있으면 PASS. 설정에 `require_kms: true`이면 SSE-KMS일 때만 PASS.
- 비고: 2023년 1월 이후 생성 버킷은 SSE-S3가 기본 적용되므로, 기본 설정에서는 대부분 PASS가 나온다. 조직 기준이 KMS 사용이라면 설정으로 강화한다.
- ISMS-P(초안): 2.7.1 암호정책 적용
- KISA: (미정)

### S3-005 서버 액세스 로깅 미설정
- 심각도: low
- API: `s3:GetBucketLogging`
- 판정: `LoggingEnabled`가 있으면 PASS. 로그 저장 버킷 자신은 제외 옵션 제공.
- ISMS-P(초안): 2.9.4 로그 및 접속기록 관리
- KISA: (미정)

## EC2 보안그룹

모든 SG 룰은 활성 리전 전체를 대상으로 하며, 리전별 finding을 낸다. 인바운드 규칙의 `IpRanges`(0.0.0.0/0)와 `Ipv6Ranges`(::/0)를 모두 확인한다.

### SG-001 관리 포트 전체 개방
- 심각도: critical
- API: `ec2:DescribeSecurityGroups`
- 판정: 22 또는 3389 포트를 포함하는 인바운드 규칙이 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL. 포트 범위(`FromPort`~`ToPort`)에 포함되는 경우도 FAIL.
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.6.6 원격접근 통제
- KISA: (미정)

### SG-002 전체 포트·프로토콜 개방
- 심각도: critical
- API: `ec2:DescribeSecurityGroups`
- 판정: `IpProtocol == "-1"` 또는 0~65535 범위 인바운드 규칙이 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL
- ISMS-P(초안): 2.6.1 네트워크 접근
- KISA: (미정)

### SG-003 데이터베이스 포트 전체 개방
- 심각도: high
- API: `ec2:DescribeSecurityGroups`
- 판정: 설정의 `db_ports` 중 하나라도 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.6.4 데이터베이스 접근
- KISA: (미정)

### SG-004 기본 보안그룹 규칙 존재
- 심각도: low
- API: `ec2:DescribeSecurityGroups`
- 판정: 이름이 `default`인 SG에 인바운드 또는 아웃바운드 규칙이 있으면 FAIL
- ISMS-P(초안): 2.6.1 네트워크 접근
- KISA: (미정)

## 룰 추가 절차

1. 이 문서에 룰 항목을 먼저 추가한다 (ID, 심각도, API, 판정 기준, 매핑).
2. `tests/rules/`에 PASS/FAIL/ERROR 테스트를 작성한다.
3. `kompass/rules/<service>/`에 룰을 구현하고 레지스트리에 등록한다.
4. `kompass/mappings/rules.yaml`에 매핑을 추가한다.
5. 필요한 API가 collector에 없으면 collector를 먼저 확장한다.
