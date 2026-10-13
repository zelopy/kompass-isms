# 점검 룰 카탈로그

1단계에서 구현할 초기 룰 목록이다. KISA 항목코드는 2026 주요정보통신기반시설 상세가이드 XII. 클라우드 원문과 대조해 채웠다 (쪽번호는 PDF 기준). **ISMS-P 매핑은 초안**이며 후보와 근거는 [COVERAGE.md](COVERAGE.md)에 있다. 사용자가 매핑을 확인하기 전까지 모든 룰은 `verified: false`다.

판정 기준값(일수, 길이 등)은 `kompass.yaml` 설정을 따르며, 아래 값은 기본값이다.

룰의 PASS는 그 룰이 검사한 범위에서만 양호라는 뜻이다. KISA 항목이 `partial`로 분류되어 있으면 항목 결과는 "검토 필요"가 상한이다 (ADR-013, COVERAGE.md).

## IAM

### IAM-001 루트 계정 MFA 미설정
- 심각도: critical
- API: `iam:GetAccountSummary`
- 판정: `SummaryMap.AccountMFAEnabled == 1`이면 PASS
- ISMS-P(초안): 2.5.3 사용자 인증, 2.5.5 특수 계정 및 권한 관리
- KISA: CA-03 MFA 설정 (상, 856쪽) — 근거 수준: 직접

### IAM-002 루트 계정 액세스 키 존재
- 심각도: critical
- API: `iam:GetAccountSummary`
- 판정: `SummaryMap.AccountAccessKeysPresent == 0`이면 PASS
- ISMS-P(초안): 2.5.5 특수 계정 및 권한 관리
- KISA: CA-02 사용자 정책 관리 (중, 855쪽) — 근거 수준: 해석 (Step 2 최상위 관리자 계정 운영 활용 금지)

### IAM-003 콘솔 사용자 MFA 미설정
- 심각도: high
- API: `iam:GenerateCredentialReport`, `iam:GetCredentialReport`
- 판정: `password_enabled == true`인 사용자 중 `mfa_active == false`인 사용자가 없으면 PASS. 사용자별 finding 생성.
- ISMS-P(초안): 2.5.3 사용자 인증
- KISA: CA-03 MFA 설정 (상, 856쪽) — 근거 수준: 직접

### IAM-004 비밀번호 정책 미흡
- 심각도: medium
- API: `iam:GetAccountPasswordPolicy`
- 판정 (KISA CA-04 기준, ADR-014):
  - 정책이 없으면(`NoSuchEntity`) FAIL.
  - 요구 문자 종류 수를 KISA 분류로 센다: 영문자(`RequireUppercaseCharacters` 또는 `RequireLowercaseCharacters`), 숫자(`RequireNumbers`), 특수문자(`RequireSymbols`). 대문자와 소문자를 둘 다 요구해도 영문자 1종이다.
  - 3종이면 `MinimumPasswordLength >= 8`, 2종이면 `>= 10`일 때 PASS. 1종 이하는 FAIL.
- 주의: `NoSuchEntity`는 ERROR가 아니라 FAIL이다. 정책이 없을 때 적용되는 AWS 기본 정책은 대문자·소문자·숫자·특수문자 중 3종 8자라서, 영문자+숫자 2종 8자 비밀번호를 허용한다. KISA 기준을 보장하지 못한다.
- 범위 밖: KISA 기준의 로그인 시도 제한은 IAM 비밀번호 정책에 설정 항목이 없다. evidence에 이 사실을 남기고, 항목 결과는 `partial` 상한에 따라 "검토 필요"가 된다.
- ISMS-P(초안): 2.5.4 비밀번호 관리
- KISA: CA-04 클라우드 계정 비밀번호 정책 관리 (중, 857쪽) — 근거 수준: 직접. 판정 기준 차이는 COVERAGE.md 참고

### IAM-005 장기 미사용 자격증명
- 심각도: medium
- API: 자격증명 보고서
- 판정: 비밀번호 또는 활성 액세스 키의 마지막 사용일(사용 이력 없으면 생성일)이 90일을 초과하면 FAIL. 사용자별 finding.
- ISMS-P(초안): 2.5.1 사용자 계정 관리, 2.5.6 접근권한 검토
- KISA: CA-01 사용자 계정 관리 (상, 854쪽) — 근거 수준: 직접

### IAM-006 액세스 키 교체 주기 초과
- 심각도: medium
- API: 자격증명 보고서
- 판정: 활성 액세스 키의 `last_rotated`가 90일을 초과하면 FAIL. 키별 finding.
- ISMS-P(초안): 2.5.3 사용자 인증
- KISA: 대응 항목 없음

### IAM-007 관리자 권한 사용자 현황
- 심각도: high
- API: `iam:ListUsers`, `iam:ListAttachedUserPolicies`, `iam:ListGroupsForUser`, `iam:ListAttachedGroupPolicies`, `iam:ListUserPolicies`, `iam:GetUserPolicy`
- 판정: `AdministratorAccess` 또는 `Action: "*"`, `Resource: "*"` 정책을 직접·그룹 경유로 가진 사용자를 식별한다. 사용자에게 직접 연결된 경우 FAIL, 그룹 경유는 `REVIEW`로 현황 보고.
- 비고: 관리자 수의 적정성은 사람이 판단할 영역이므로, 현황 증적 제공이 주목적이다. (`automation: partial`)
- ISMS-P(초안): 2.5.5 특수 계정 및 권한 관리
- KISA: CA-02 사용자 정책 관리 (중, 855쪽) — 근거 수준: 직접

## S3

### S3-001 계정 수준 퍼블릭 액세스 차단 미설정
- 심각도: high
- API: `s3control:GetPublicAccessBlock`
- 판정: 4개 설정(`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`)이 모두 true이면 PASS. 설정 없음(`NoSuchPublicAccessBlockConfiguration`)은 FAIL.
- ISMS-P(초안): 2.6.x (원문 확인 필요)
- KISA: CA-10 스토리지 리소스 퍼블릭 접근 관리 (중, 863쪽) — 근거 수준: 직접

### S3-002 버킷 수준 퍼블릭 액세스 차단 미설정
- 심각도: high
- API: `s3:ListBuckets`, `s3:GetPublicAccessBlock`
- 판정: 버킷별로 4개 설정이 모두 true이면 PASS. 계정 수준이 모두 true이면 버킷 수준이 없어도 PASS로 보되, evidence에 계정 수준 설정을 함께 남긴다.
- ISMS-P(초안): 2.6.x (원문 확인 필요)
- KISA: CA-10 스토리지 리소스 퍼블릭 접근 관리 (중, 863쪽) — 근거 수준: 직접

### S3-003 버킷 정책에 의한 퍼블릭 노출
- 심각도: critical
- API: `s3:GetBucketPolicyStatus`
- 판정: `PolicyStatus.IsPublic == false`이거나 정책이 없으면 PASS
- ISMS-P(초안): 2.6.x (원문 확인 필요)
- KISA: CA-10 스토리지 리소스 퍼블릭 접근 관리 (중, 863쪽) — 근거 수준: 직접

### S3-004 기본 암호화 설정
- 심각도: medium
- API: `s3:GetBucketEncryption`
- 판정: 기본 암호화 설정이 있으면 PASS. 설정에 `require_kms: true`이면 SSE-KMS일 때만 PASS.
- 비고: 2023년 1월 이후 생성 버킷은 SSE-S3가 기본 적용되므로, 기본 설정에서는 대부분 PASS가 나온다. 조직 기준이 KMS 사용이라면 설정으로 강화한다.
- ISMS-P(초안): 2.7.1 암호정책 적용
- KISA: 대응 항목 없음 (CA-11은 관계형 DB 한정)

### S3-005 서버 액세스 로깅 미설정
- 심각도: low
- API: `s3:GetBucketLogging`
- 판정: `LoggingEnabled`가 있으면 PASS. 로그 저장 버킷 자신은 제외 옵션 제공.
- 비고: CloudTrail S3 데이터 이벤트로 버킷 접근을 기록하는 경우도 이 룰에서는 FAIL이다. 룰은 `s3` 스냅샷만 보기 때문이다. 그런 경우의 재판단은 4단계 에이전트의 추가 조사로 다룬다 (ADR-015).
- ISMS-P(초안): 2.9.4 로그 및 접속기록 관리
- KISA: CA-16 오브젝트 스토리지 버킷 로깅 설정 (중, 869쪽) — 근거 수준: 직접

## EC2

EC2 룰은 모두 `ec2` 스냅샷(보안그룹, VPC, 서브넷, 라우팅 테이블, 네트워크 인터페이스)을 입력으로 받는다.

### 보안그룹

모든 SG 룰은 활성 리전 전체를 대상으로 하며, 리전별 finding을 낸다. 인바운드 규칙의 `IpRanges`(0.0.0.0/0)와 `Ipv6Ranges`(::/0)를 모두 확인한다.

### SG-001 관리 포트 전체 개방
- 심각도: critical
- API: `ec2:DescribeSecurityGroups`
- 판정: 22 또는 3389 포트를 포함하는 인바운드 규칙이 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL. 포트 범위(`FromPort`~`ToPort`)에 포함되는 경우도 FAIL.
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.6.6 원격접근 통제
- KISA: CA-09 접근 제어 설정 관리 (상, 862쪽) — 근거 수준: 직접

### SG-002 전체 포트·프로토콜 개방
- 심각도: critical
- API: `ec2:DescribeSecurityGroups`
- 판정: `IpProtocol == "-1"` 또는 0~65535 범위 인바운드 규칙이 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL
- ISMS-P(초안): 2.6.1 네트워크 접근
- KISA: CA-09 접근 제어 설정 관리 (상, 862쪽) — 근거 수준: 직접

### SG-003 데이터베이스 포트 전체 개방
- 심각도: high
- API: `ec2:DescribeSecurityGroups`
- 판정: 설정의 `db_ports` 중 하나라도 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.6.4 데이터베이스 접근
- KISA: CA-09 접근 제어 설정 관리 (상, 862쪽) — 근거 수준: 직접

### SG-004 기본 보안그룹 규칙 존재
- 심각도: low
- API: `ec2:DescribeSecurityGroups`
- 판정: 이름이 `default`인 SG에 인바운드 또는 아웃바운드 규칙이 있으면 FAIL
- ISMS-P(초안): 2.6.1 네트워크 접근
- KISA: CA-09 접근 제어 설정 관리 (상, 862쪽) — 근거 수준: 해석 (기본 SG 규칙을 불필요한 규칙으로 봄)

### VPC 공통: 퍼블릭 서브넷 판별

서브넷에 연결된 라우팅 테이블(명시적 연결이 없으면 VPC의 기본 라우팅 테이블)에 `0.0.0.0/0` 또는 `::/0` → `igw-*` 경로가 있으면 퍼블릭 서브넷, 없으면 프라이빗 서브넷으로 본다.

### VPC-001 공개·내부 서브넷 미분리
- 심각도: medium
- API: `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables`, `ec2:DescribeNetworkInterfaces`
- 판정: VPC별로 네트워크 인터페이스가 있는 서브넷을 모은다. 그 서브넷이 모두 퍼블릭이면 FAIL. 프라이빗 서브넷에 리소스가 하나라도 있으면 PASS.
- 네트워크 인터페이스가 하나도 없는 VPC(쓰지 않는 기본 VPC 등)는 `NOT_APPLICABLE`.
- 비고: 퍼블릭 서브넷에 있는 리소스가 공개용으로 의도된 것인지는 사람이 판단한다 (CA-07 `partial`).
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.10.2 클라우드 보안
- KISA: CA-07 VPC 네트워크 서브넷 관리 (상, 860쪽) — 근거 수준: 직접 ("Public 서브넷은 인터넷 게이트웨이로, Private 서브넷은 NAT 게이트웨이로 할당")

### VPC-002 공인 IP가 할당된 네트워크 인터페이스
- 심각도: medium
- API: `ec2:DescribeNetworkInterfaces`
- 판정: `Association.PublicIp`가 있는 네트워크 인터페이스마다 `REVIEW` finding을 낸다. evidence에는 인터페이스 유형, 연결된 인스턴스, 서브넷(퍼블릭/프라이빗), 보안그룹을 담는다. 리전에 해당 인터페이스가 없으면 리전 단위 PASS 하나.
- 제외: NAT 게이트웨이(`InterfaceType == "nat_gateway"`), AWS 서비스가 관리하는 인터페이스(`RequesterManaged == true`). 공개가 목적인 리소스라 현황 보고의 의미가 없다.
- 비고: 내부용 리소스인지는 사람이 판단한다 (CA-08 `partial`). KISA 원문의 다른 대상인 RDS `PubliclyAccessible`은 RDS collector가 생기면 별도 룰로 추가한다.
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.10.2 클라우드 보안
- KISA: CA-08 가상 네트워크 리소스 관리 (중, 861쪽) — 근거 수준: 직접 ("각 서비스 리소스에 공인 IP주소가 존재하지 않고")

## CloudTrail

### CT-001 멀티 리전 관리 이벤트 추적 미설정
- 심각도: high
- API: `cloudtrail:DescribeTrails`(`includeShadowTrails=true`), `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`
- 판정: 아래 조건을 모두 만족하는 추적이 하나 이상 있으면 PASS, 없으면 FAIL. 계정 단위 finding 하나.
  - `IsMultiRegionTrail == true`
  - `GetTrailStatus.IsLogging == true`
  - 관리 이벤트를 읽기·쓰기 모두 기록: 기본 이벤트 선택기는 `IncludeManagementEvents == true`이고 `ReadWriteType == "All"`. 고급 이벤트 선택기는 `eventCategory = Management`이고 `readOnly` 필터가 없는 선택기가 있음.
- 조직 추적(Organization trail)은 멤버 계정에서 섀도 추적으로 보이며, 조건을 만족하면 인정한다. 상태 조회가 `AccessDenied`이면 그 추적은 ERROR로 기록하고, 다른 추적으로 PASS가 확정되지 않으면 결과는 ERROR다.
- 비고: CA-16(버킷 로깅)을 CloudTrail S3 데이터 이벤트로 대신하는 판단은 이 룰에서 하지 않는다 (ADR-015).
- ISMS-P(초안): 2.9.4 로그 및 접속기록 관리, 2.10.2 클라우드 보안
- KISA: CA-13 클라우드 서비스 사용자 계정 로깅 설정 (상, 866쪽) — 근거 수준: 직접

## 룰 추가 절차

1. 이 문서에 룰 항목을 먼저 추가한다 (ID, 심각도, API, 판정 기준, 매핑).
2. `tests/rules/`에 PASS/FAIL/ERROR 테스트를 작성한다.
3. `kompass/rules/<service>/`에 룰을 구현하고 레지스트리에 등록한다.
4. `kompass/mappings/rules.yaml`에 매핑을 추가한다.
5. 필요한 API가 collector에 없으면 collector를 먼저 확장한다.
