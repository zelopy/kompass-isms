# 점검 룰 카탈로그

1단계에서 구현할 초기 룰 목록이다. KISA 항목코드는 2026 주요정보통신기반시설 상세가이드 XII. 클라우드 원문과 대조해 채웠다 (쪽번호는 PDF 기준). KISA 매핑은 사용자가 원문 근거를 확인했다 (2026-10-13). **ISMS-P 매핑은 초안**이며 KISA 항목별 후보와 근거는 [COVERAGE.md](COVERAGE.md)에 있다. ISMS-P 매핑을 확인하기 전까지 `rules.yaml`의 `verified`는 false로 둔다. KISA와 ISMS-P의 확인 상태를 따로 기록할 수 있도록 2단계에서 매핑 스키마를 정한다.

판정 기준값(일수, 길이 등)은 `kompass.yaml` 설정을 따르며, 아래 값은 기본값이다.

룰의 PASS는 그 룰이 검사한 범위에서만 양호라는 뜻이다. KISA 항목이 `partial`로 분류되어 있으면 항목 결과는 "검토 필요"가 상한이다 (ADR-013, COVERAGE.md).

## 공통 원칙

- **설정이 존재하면 FAIL.** 공개 허용 정책·ACL처럼 "불필요한 규칙"이 설정되어 있으면, 다른 설정(퍼블릭 액세스 차단 등)으로 실제 효과가 막혀 있어도 FAIL로 판정한다. 막고 있는 설정은 evidence에 함께 남긴다. 차단 설정이 바뀌는 순간 바로 노출되기 때문이다.
- **자격증명 보고서.** `GenerateCredentialReport`로 생성을 요청하고 완료될 때까지 기다린 뒤 `GetCredentialReport`로 받는다. 보고서는 최대 4시간 전 상태일 수 있으므로 `GeneratedTime`을 evidence에 남긴다. 제한 시간 안에 생성되지 않으면 ERROR.
- **날짜 값.** 스냅샷의 날짜는 모두 ISO 8601 문자열이다 (ADR-019). 경과 일수 계산은 `rules/base.py`의 공용 파싱 함수를 쓴다. 자격증명 보고서의 `N/A`, `no_information`, `not_supported` 같은 특수 값도 이 함수에서 처리한다.
- **리전.** 리전별 룰(EC2·VPC)은 점검 대상 리전(`ScanContext.regions`) 전체를 본다. S3 버킷은 `--regions`와 관계없이 모두 점검하고 evidence에 버킷 리전을 남긴다 (ADR-021). SCP 등으로 거부된 리전의 처리(ERROR로 둘지, 점검 제외 리전으로 따로 보고할지)는 1단계 구현 중에 결정한다.

## IAM

### IAM-001 루트 계정 MFA 미설정
- 심각도: critical
- API: `iam:GetAccountSummary`, 자격증명 보고서
- 판정: `SummaryMap.AccountMFAEnabled == 1`이면 PASS, 아니면 FAIL.
- 해당 없음: 루트 자격증명이 없는 계정(Organizations의 루트 자격증명 중앙 관리로 삭제된 멤버 계정)은 `NOT_APPLICABLE`. 자격증명 보고서 `<root_account>` 행에서 비밀번호와 액세스 키가 모두 없는 것으로 판별한다. 정확한 필드값은 구현 시 확인한다.
- ISMS-P(초안): 2.5.3 사용자 인증, 2.5.5 특수 계정 및 권한 관리, 2.10.2 클라우드 보안
- KISA: CA-03 MFA 설정 (상, 856쪽) — 근거 수준: 직접

### IAM-002 루트 계정 액세스 키 존재
- 심각도: critical
- API: `iam:GetAccountSummary`
- 판정: `SummaryMap.AccountAccessKeysPresent == 0`이면 PASS
- ISMS-P(초안): 2.5.5 특수 계정 및 권한 관리, 2.10.2 클라우드 보안
- KISA: CA-02 사용자 정책 관리 (중, 855쪽) — 근거 수준: 해석 (Step 2 최상위 관리자 계정 운영 활용 금지)

### IAM-003 콘솔 사용자 MFA 미설정
- 심각도: high
- API: 자격증명 보고서
- 판정: `password_enabled == true`인 IAM 사용자 중 `mfa_active == false`이면 FAIL, `true`이면 PASS. 사용자별 finding.
- 대상: `<root_account>` 행은 제외한다 (IAM-001 담당). 콘솔 비밀번호가 없는 사용자(프로그래밍 방식 접근 전용)도 제외한다. 대상 사용자가 없으면 `NOT_APPLICABLE`.
- 비고: 외부 IdP·IAM Identity Center 사용자는 IAM 사용자가 아니므로 이 룰의 범위 밖이다. IAM-009가 별도로 다룬다.
- ISMS-P(초안): 2.5.3 사용자 인증, 2.10.2 클라우드 보안
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
- KISA: CA-04 클라우드 계정 비밀번호 정책 관리 (중, 857쪽) — 근거 수준: 직접

### IAM-005 장기 미사용 자격증명
- 심각도: medium
- API: 자격증명 보고서
- 판정: 활성 자격증명(콘솔 비밀번호, 활성 액세스 키)별로 마지막 사용일을 구해 `iam.unused_credential_days`(기본 90일)를 초과하면 FAIL. 사용자별 finding이며, evidence에 자격증명별 마지막 사용일을 담는다.
  - 비밀번호를 한 번도 쓰지 않았으면 `password_last_changed`(비밀번호 설정일)를 기준으로 한다.
  - 액세스 키를 한 번도 쓰지 않았으면 `access_key_N_last_rotated`(키 생성일)를 기준으로 한다.
- 해당 없음: 활성 자격증명이 하나도 없는 사용자는 대상에서 제외한다. 대상 사용자가 없으면 `NOT_APPLICABLE`.
- ISMS-P(초안): 2.5.1 사용자 계정 관리, 2.5.6 접근권한 검토, 2.10.2 클라우드 보안
- KISA: CA-01 사용자 계정 관리 (상, 854쪽) — 근거 수준: 직접

### IAM-006 액세스 키 교체 주기 초과
- 심각도: medium
- API: 자격증명 보고서
- 판정: 활성 액세스 키의 `last_rotated`가 `iam.access_key_rotation_days`(기본 90일)를 초과하면 FAIL. 키별 finding.
- ISMS-P(초안): 2.10.2 클라우드 보안 (Access Key 관리 절차), 2.5.3 사용자 인증
- KISA: 대응 항목 없음

### IAM-007 관리자 권한 사용자 현황
- 심각도: high
- API: `iam:GetAccountAuthorizationDetails` (사용자·그룹·역할·관리형 정책 본문을 한 번에 받는다)
- 관리자 권한 판별: 사용자에게 직접 또는 그룹을 거쳐 아래 중 하나가 적용되면 관리자로 본다.
  - AWS 관리형 정책 `AdministratorAccess`
  - 관리형·인라인 정책 중 `Effect: Allow`이고 `Action`에 `"*"`, `Resource`에 `"*"`가 포함된 문(statement)
- 판정: 사용자에게 직접 연결된 관리자 권한은 FAIL. 그룹을 거친 관리자 권한은 `REVIEW`로 현황 보고. 관리자 권한이 없는 사용자는 finding을 내지 않으며, 관리자가 한 명도 없으면 계정 단위 PASS 하나.
- 애매한 정책: `Allow` + `NotAction`처럼 정적 분석으로 관리자 여부를 확정하기 어려운 문이 있으면 해당 사용자는 `REVIEW`.
- 범위 밖: 역할(role)의 관리자 권한은 1단계에서 판정하지 않는다. 같은 API 응답에 들어 있으므로 evidence 수집만 해 두고 이후 룰로 추가한다.
- 비고: 관리자 수의 적정성은 사람이 판단할 영역이므로, 현황 증적 제공이 주목적이다.
- ISMS-P(초안): 2.5.5 특수 계정 및 권한 관리, 2.5.6 접근권한 검토, 2.10.2 클라우드 보안
- KISA: CA-02 사용자 정책 관리 (중, 855쪽) — 근거 수준: 직접

### IAM-008 루트 계정 최근 사용
- 심각도: high
- API: 자격증명 보고서
- 판정: `<root_account>` 행의 `password_last_used`, `access_key_1_last_used_date`, `access_key_2_last_used_date` 중 가장 최근 값이 `iam.root_recent_use_days`(기본 90일) 이내이면 `REVIEW`. 그 외(사용 이력 없음 포함)는 PASS. evidence에 마지막 사용 시각을 담는다.
- 해당 없음: 루트 자격증명이 없는 계정은 `NOT_APPLICABLE` (IAM-001과 같은 판별).
- 비고: 루트 사용이 계정 복구 등 불가피한 작업이었는지, 서비스 운영 목적이었는지는 사람이 판단한다.
- ISMS-P(초안): 2.5.5 특수 계정 및 권한 관리, 2.10.2 클라우드 보안
- KISA: CA-02 사용자 정책 관리 (중, 855쪽) — 근거 수준: 직접 (Step 2 "콘솔 최상위 관리자(최초 가입계정) 계정은 서비스 운영에 활용 금지")

### IAM-009 외부 자격증명 공급자 사용 (MFA 확인 필요)
- 심각도: medium
- API: `iam:ListSAMLProviders`, `iam:ListOpenIDConnectProviders`, `sso-admin:ListInstances`
- 판정: SAML 공급자, OIDC 공급자, IAM Identity Center 인스턴스마다 `REVIEW` finding을 낸다. 하나도 없으면 계정 단위 `NOT_APPLICABLE`.
- 이유: 이 경로로 로그인하는 사용자는 IAM 사용자가 아니어서 IAM-003이 보지 못한다. MFA는 IdP 쪽 설정이라 API로 확인할 수 없으므로 사람이 확인해야 한다는 사실을 결과에 남긴다.
- 비고: OIDC 공급자는 GitHub Actions 같은 워크로드 연동에 쓰이는 경우가 많다. 사람이 로그인하는 경로가 아니면 검토자가 그렇게 기록한다.
- 구현 시 확인: Identity Center 인스턴스가 조직 관리 계정이 아닌 멤버 계정에서 어떻게 보이는지, `SecurityAudit` 정책으로 `sso:ListInstances`가 허용되는지.
- ISMS-P(초안): 2.5.3 사용자 인증, 2.10.2 클라우드 보안
- KISA: CA-03 MFA 설정 (상, 856쪽) — 근거 수준: 직접 ("각 계정별 2차 인증")

## S3

### S3-001 계정 수준 퍼블릭 액세스 차단 미설정
- 심각도: high
- API: `s3control:GetPublicAccessBlock`
- 판정: 4개 설정(`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`)이 모두 true이면 PASS. 설정 없음(`NoSuchPublicAccessBlockConfiguration`)은 FAIL.
- ISMS-P(초안): 2.10.2 클라우드 보안
- KISA: CA-10 스토리지 리소스 퍼블릭 접근 관리 (중, 863쪽) — 근거 수준: 직접

### S3-002 버킷 수준 퍼블릭 액세스 차단 미설정
- 심각도: high
- API: `s3:ListBuckets`, `s3:GetPublicAccessBlock`
- 판정: 버킷별로 4개 설정이 모두 true이면 PASS. 계정 수준이 모두 true이면 버킷 수준이 없어도 PASS로 보되, evidence에 계정 수준 설정을 함께 남긴다.
- ISMS-P(초안): 2.10.2 클라우드 보안
- KISA: CA-10 스토리지 리소스 퍼블릭 접근 관리 (중, 863쪽) — 근거 수준: 직접

### S3-003 버킷 정책에 의한 퍼블릭 노출
- 심각도: critical
- API: `s3:GetBucketPolicyStatus`
- 판정: `PolicyStatus.IsPublic == true`이면 FAIL. `false`이거나 정책이 없으면 PASS.
- 정책 없음: `GetBucketPolicyStatus`는 정책이 없는 버킷에 `NoSuchBucketPolicy` 오류를 낸다. collector는 이를 수집 실패(ERROR)가 아니라 "정책 없음"으로 기록한다 (실습 환경 확인, 2026-10-13).
- evidence: 계정·버킷 수준 `RestrictPublicBuckets` 값을 함께 남긴다 (공통 원칙: 설정이 존재하면 FAIL).
- 확인됨 (실습 환경, 2026-10-13): `RestrictPublicBuckets: true`로 실제 공개가 막혀 있어도 `IsPublic`은 `true`로 보고된다. `IsPublic`은 정책 문서 자체만 평가하므로, 공통 원칙대로 FAIL로 판정하고 차단 설정을 evidence에 남기는 것이 맞다.
- ISMS-P(초안): 2.10.2 클라우드 보안
- KISA: CA-10 스토리지 리소스 퍼블릭 접근 관리 (중, 863쪽) — 근거 수준: 직접

### S3-004 기본 암호화 설정
- 심각도: medium
- API: `s3:GetBucketEncryption`
- 판정: 기본 암호화 설정이 있으면 PASS. 설정에 `require_kms: true`이면 SSE-KMS일 때만 PASS.
- 비고: 2023년 1월부터 SSE-S3가 **모든 버킷**의 기본 암호화로 적용된다. 따라서 기본 설정(`require_kms: false`)에서는 사실상 항상 PASS이며, 암호화 방식을 증적으로 남기는 것이 주목적이다. 조직 기준이 KMS 사용이라면 설정으로 강화한다.
- ISMS-P(초안): 2.7.1 암호정책 적용
- KISA: 대응 항목 없음 (CA-11은 관계형 DB 한정)

### S3-005 서버 액세스 로깅 미설정
- 심각도: low
- API: `s3:GetBucketLogging`
- 판정: `LoggingEnabled`가 있으면 PASS. 로그 저장 버킷 자신은 제외 옵션 제공.
- 비고: CloudTrail S3 데이터 이벤트로 버킷 접근을 기록하는 경우도 이 룰에서는 FAIL이다. 룰은 `s3` 스냅샷만 보기 때문이다. 그런 경우의 재판단은 4단계 에이전트의 추가 조사로 다룬다 (ADR-015).
- ISMS-P(초안): 2.9.4 로그 및 접속기록 관리
- KISA: CA-16 오브젝트 스토리지 버킷 로깅 설정 (중, 869쪽) — 근거 수준: 직접

### S3-006 버킷 ACL에 의한 전체 공개
- 심각도: high
- API: `s3:GetBucketOwnershipControls`, `s3:GetBucketAcl`
- 판정: 객체 소유권이 `BucketOwnerEnforced`(ACL 비활성화)이면 PASS. 그 외에는 ACL에 `http://acs.amazonaws.com/groups/global/AllUsers` 또는 `.../AuthenticatedUsers` 대상 권한 부여가 있으면 FAIL, 없으면 PASS.
- evidence: 계정·버킷 수준 `IgnorePublicAcls` 값을 함께 남긴다 (공통 원칙: 설정이 존재하면 FAIL).
- 비고: 2023년 4월 이후 생성 버킷은 기본적으로 ACL이 비활성화되어 있다. 이 룰은 주로 오래된 버킷과 ACL을 다시 켠 버킷에서 의미가 있다.
- ISMS-P(초안): 2.10.2 클라우드 보안
- KISA: CA-10 스토리지 리소스 퍼블릭 접근 관리 (중, 863쪽) — 근거 수준: 직접 ("모든 인터넷 사용자 접근권한")

## EC2

EC2 룰은 모두 `ec2` 스냅샷(보안그룹, VPC, 서브넷, 라우팅 테이블, 네트워크 인터페이스)을 입력으로 받는다.

### 보안그룹

모든 SG 룰은 점검 대상 리전 전체를 보며, 보안그룹별 finding을 낸다. 인바운드 규칙의 `IpRanges`(0.0.0.0/0)와 `Ipv6Ranges`(::/0)를 모두 확인한다. 모든 SG finding의 evidence에는 그 보안그룹이 연결된 네트워크 인터페이스 수를 남긴다.

데이터 형태 (실습 계정 확인, 2026-10-13): 값이 비어 있는 키는 응답에서 빠진다(예: 태그 없는 기본 VPC에는 `Tags` 키가 없다). 서브넷이 기본 라우팅 테이블을 쓰면 그 테이블의 `Associations`에는 서브넷이 나오지 않는다(`Main: true` 항목만 있다). 룰은 키 존재를 가정하지 않는다.

한계: 규칙이 접두사 목록(`PrefixListIds`)을 참조하면 목록 안의 CIDR은 수집하지 않으므로 전체 개방 여부를 판정하지 않는다. evidence에 접두사 목록 ID를 남긴다.

포트 포함 판정: `IpProtocol == "-1"`(모든 프로토콜)인 규칙은 모든 포트를 포함한다. `tcp`·`udp` 규칙은 `FromPort`~`ToPort` 범위에 포트가 들어 있으면 포함한다.

### SG-001 관리 포트 전체 개방
- 심각도: critical
- API: `ec2:DescribeSecurityGroups`
- 판정: `ec2.admin_ports`(기본 22, 3389)를 포함하는 인바운드 규칙이 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL.
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.6.6 원격접근 통제, 2.10.1 보안시스템 운영
- KISA: CA-09 접근 제어 설정 관리 (상, 862쪽) — 근거 수준: 직접

### SG-002 전체 포트·프로토콜 개방
- 심각도: critical
- API: `ec2:DescribeSecurityGroups`
- 판정: `IpProtocol == "-1"` 또는 0~65535 범위 인바운드 규칙이 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.10.1 보안시스템 운영
- KISA: CA-09 접근 제어 설정 관리 (상, 862쪽) — 근거 수준: 직접

### SG-003 데이터베이스 포트 전체 개방
- 심각도: high
- API: `ec2:DescribeSecurityGroups`
- 판정: `ec2.db_ports` 중 하나라도 포함하는 인바운드 규칙이 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.6.4 데이터베이스 접근, 2.10.1 보안시스템 운영
- KISA: CA-09 접근 제어 설정 관리 (상, 862쪽) — 근거 수준: 직접

### SG-004 사용 중인 기본 보안그룹에 규칙 존재
- 심각도: low
- API: `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`
- 판정: 이름이 `default`인 보안그룹에 인바운드 또는 아웃바운드 규칙이 있고, 네트워크 인터페이스가 하나 이상 연결되어 있으면 FAIL. 연결된 인터페이스가 없으면 PASS (evidence에 규칙 존재를 남긴다).
- 이유: AWS는 모든 VPC의 기본 보안그룹에 기본 규칙을 만든다. 쓰지 않는 기본 보안그룹까지 FAIL로 보면 손대지 않은 계정도 리전마다 FAIL이 나와 결과가 의미를 잃는다 (ADR-018).
- ISMS-P(초안): 2.6.1 네트워크 접근
- KISA: 대응 항목 없음 (ADR-018)

### VPC 공통: 퍼블릭 서브넷 판별

서브넷에 연결된 라우팅 테이블(명시적 연결이 없으면 VPC의 기본 라우팅 테이블)에 `0.0.0.0/0` 또는 `::/0` → `igw-*` 경로가 있으면 퍼블릭 서브넷, 없으면 프라이빗 서브넷으로 본다.

### VPC-001 공개·내부 서브넷 미분리
- 심각도: medium
- API: `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables`, `ec2:DescribeNetworkInterfaces`
- 판정: VPC별로 네트워크 인터페이스가 있는 서브넷을 모은다. 그 서브넷이 모두 퍼블릭이면 FAIL. 프라이빗 서브넷에 리소스가 하나라도 있으면 PASS.
- 해당 없음: 네트워크 인터페이스가 하나도 없는 VPC(쓰지 않는 기본 VPC 등)는 `NOT_APPLICABLE`.
- 비고: 퍼블릭 서브넷에 있는 리소스가 공개용으로 의도된 것인지는 사람이 판단한다 (CA-07 `partial`).
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.10.2 클라우드 보안
- KISA: CA-07 VPC 네트워크 서브넷 관리 (상, 860쪽) — 근거 수준: 직접 ("Public 서브넷은 인터넷 게이트웨이로, Private 서브넷은 NAT 게이트웨이로 할당")

### VPC-002 공인 IP가 할당된 네트워크 인터페이스
- 심각도: medium
- API: `ec2:DescribeNetworkInterfaces`
- 판정: `Association.PublicIp`가 있는 네트워크 인터페이스마다 `REVIEW` finding을 낸다. evidence에는 인터페이스 유형, 요청 주체(`RequesterId`), 설명, 연결된 인스턴스, 서브넷(퍼블릭/프라이빗), 보안그룹을 담는다. 리전에 해당 인터페이스가 없으면 리전 단위 PASS 하나.
- 제외: 공개가 목적인 리소스만 뺀다.
  - NAT 게이트웨이: `InterfaceType == "nat_gateway"`
  - 로드 밸런서: `InterfaceType`이 `network_load_balancer` 또는 `gateway_load_balancer`이거나, `RequesterId == "amazon-elb"`
- 비고: `RequesterManaged == true` 전체를 제외하지 않는다. 공개 RDS 같은 AWS 관리형 리소스의 인터페이스도 이 값이 true이고, 그것이 CA-08의 주요 점검 대상이기 때문이다. 각 리소스 유형의 실제 필드값은 실습 환경에서 확인한다.
- 비고: 내부용 리소스인지는 사람이 판단한다 (CA-08 `partial`).
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.10.2 클라우드 보안
- KISA: CA-08 가상 네트워크 리소스 관리 (중, 861쪽) — 근거 수준: 직접 ("각 서비스 리소스에 공인 IP주소가 존재하지 않고")

## CloudTrail

### CT-001 멀티 리전 관리 이벤트 추적 미설정
- 심각도: high
- API: `cloudtrail:DescribeTrails`(`includeShadowTrails=true`), `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`
- 판정: 아래 조건을 모두 만족하는 추적이 하나 이상 있으면 PASS, 없으면 FAIL. 계정 단위 finding 하나.
  - `IsMultiRegionTrail == true`
  - `GetTrailStatus.IsLogging == true`
  - 관리 이벤트 기록: 기본 이벤트 선택기는 `IncludeManagementEvents == true`, 고급 이벤트 선택기는 `eventCategory = Management`인 선택기가 있음.
  - 읽기 이벤트: `cloudtrail.require_read_events`(기본 true)이면 읽기·쓰기 모두 기록해야 한다 (기본 선택기 `ReadWriteType == "All"`, 고급 선택기 `readOnly` 필터 없음). false이면 쓰기 이벤트만 기록해도 된다.
- evidence: 추적별 `LatestDeliveryError`, `LatestDeliveryTime`을 남긴다. 로그가 S3로 전달되지 못하고 있는 상태를 검토자가 볼 수 있게 하기 위해서다.
- 확인됨 (실습 계정, 2026-10-13):
  - `LatestDeliveryError`는 오류가 없으면 키 자체가 없다 (`None`이 아니다).
  - 실제 AWS는 `EventSelectors`와 `AdvancedEventSelectors` 중 사용 중인 하나만 돌려준다. moto는 둘 다 돌려주므로 단위 테스트는 실제 형태를 따른 가짜 데이터로 쓴다.
- 관리 이벤트 일부 제외: 기본 선택기의 `ExcludeManagementEventSources`(`kms.amazonaws.com`, `rdsdata.amazonaws.com`)나 고급 선택기의 `eventSource` `NotEquals`로 일부 관리 이벤트를 제외한 추적은 PASS로 보고, evidence의 `excluded_event_sources`에 제외 목록을 남긴다 (사용자 결정, 2026-10-13).
- 고급 선택기 해석: `eventCategory = Management`인 선택기만 본다. 읽기·쓰기 범위는 여러 선택기의 합집합이다. `eventCategory`·`readOnly`·`eventSource NotEquals` 외의 조건(예: `eventSource Equals`)이 있는 선택기는 일부 이벤트만 기록하므로 인정하지 않는다.
- 단일 리전 추적은 상태를 수집하지 못해도 조건을 만족할 수 없으므로 ERROR의 원인이 되지 않는다.
- 구현: `kompass/rules/cloudtrail/ct_001_multi_region_trail.py`. 실습 계정에서 기대값(PASS) 확인 (2026-10-13).
- 조직 추적(Organization trail)은 멤버 계정에서 섀도 추적으로 보이며, 조건을 만족하면 인정한다. 상태 조회가 `AccessDenied`이면 그 추적은 ERROR로 기록하고, 다른 추적으로 PASS가 확정되지 않으면 결과는 ERROR다. 멤버 계정에서의 실제 동작은 단일 계정 실습으로 확인할 수 없으므로 조직 환경에서 별도로 확인한다.
- 비고: CA-16(버킷 로깅)을 CloudTrail S3 데이터 이벤트로 대신하는 판단은 이 룰에서 하지 않는다 (ADR-015).
- ISMS-P(초안): 2.9.4 로그 및 접속기록 관리, 2.10.2 클라우드 보안
- KISA: CA-13 클라우드 서비스 사용자 계정 로깅 설정 (상, 866쪽) — 근거 수준: 직접

## 룰 추가 절차

1. 이 문서에 룰 항목을 먼저 추가한다 (ID, 심각도, API, 판정 기준, 매핑).
2. `tests/rules/`에 PASS/FAIL/ERROR 테스트를 작성한다.
3. `kompass/rules/<service>/`에 룰을 구현하고 레지스트리에 등록한다.
4. `kompass/mappings/rules.yaml`에 매핑을 추가한다.
5. 필요한 API가 collector에 없으면 collector를 먼저 확장한다.
6. [COVERAGE.md](COVERAGE.md)의 해당 KISA 항목에 룰을 추가한다.
