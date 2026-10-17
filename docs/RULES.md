# 점검 룰 카탈로그

1단계에서 구현할 초기 룰 목록이다. KISA 항목코드는 2026 주요정보통신기반시설 상세가이드 XII. 클라우드 원문과 대조해 채웠다 (쪽번호는 PDF 기준). KISA 매핑은 사용자가 원문 근거를 확인했다 (2026-10-13). **ISMS-P 매핑은 초안**이며 KISA 항목별 후보와 근거는 [COVERAGE.md](COVERAGE.md)에 있다. ISMS-P 매핑을 확인하기 전까지 `rules.yaml`의 `verified`는 false로 둔다. KISA와 ISMS-P의 확인 상태를 따로 기록할 수 있도록 2단계에서 매핑 스키마를 정한다.

판정 기준값(일수, 길이 등)은 `kompass.yaml` 설정을 따르며, 아래 값은 기본값이다.

룰의 PASS는 그 룰이 검사한 범위에서만 양호라는 뜻이다. KISA 항목이 `partial`로 분류되어 있으면 항목 결과는 "검토 필요"가 상한이다 (ADR-013, COVERAGE.md).

## 공통 원칙

- **설정이 존재하면 FAIL.** 공개 허용 정책·ACL처럼 "불필요한 규칙"이 설정되어 있으면, 다른 설정(퍼블릭 액세스 차단 등)으로 실제 효과가 막혀 있어도 FAIL로 판정한다. 막고 있는 설정은 evidence에 함께 남긴다. 차단 설정이 바뀌는 순간 바로 노출되기 때문이다.
- **자격증명 보고서.** `GenerateCredentialReport`로 생성을 요청하고 완료될 때까지 기다린 뒤 `GetCredentialReport`로 받는다. 보고서는 최대 4시간 전 상태일 수 있으므로 `GeneratedTime`을 evidence에 남긴다. 제한 시간 안에 생성되지 않으면 ERROR. AWS는 4시간 안에 만든 보고서를 다시 돌려주므로, 그 뒤에 만든 사용자는 보고서에 없다. 보고서를 쓰는 룰(IAM-003·005·006)은 권한 정보(`GetAccountAuthorizationDetails`)에는 있지만 보고서에 없는 사용자마다 ERROR를 낸다 (ADR-045, 실습 계정에서 확인).
- **날짜 값.** 스냅샷의 날짜는 모두 ISO 8601 문자열이다 (ADR-019). 경과 일수 계산은 `rules/base.py`의 공용 파싱 함수를 쓴다. 자격증명 보고서의 `N/A`, `no_information`, `not_supported` 같은 특수 값도 이 함수에서 처리한다.
- **리전.** 리전별 룰(EC2·VPC)은 점검 대상 리전(`ScanContext.regions`) 전체를 본다. S3 버킷은 `--regions`와 관계없이 모두 점검하고 evidence에 버킷 리전을 남긴다 (ADR-021). 리전 전체가 접근 거부되는 리전(SCP 리전 제한 등)은 `--regions`를 지정하지 않았을 때 점검 범위에서 빼고 보고서에 "점검 범위 밖"으로 표시한다. 기본 리전까지 거부되면 권한 부족으로 보고 빼지 않는다 (ADR-028).

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
- 기준 시각: 스냅샷 수집 시각. 같은 스냅샷을 언제 다시 판정해도 결과가 같다 (IAM-006, IAM-008도 같다).
- 오류: 기준일 자체를 알 수 없는 자격증명이 있고 기준을 넘은 자격증명이 없으면 ERROR.
- ISMS-P(초안): 2.5.1 사용자 계정 관리, 2.5.6 접근권한 검토, 2.10.2 클라우드 보안
- KISA: CA-01 사용자 계정 관리 (상, 854쪽) — 근거 수준: 직접

### IAM-006 액세스 키 교체 주기 초과
- 심각도: medium
- API: 자격증명 보고서
- 판정: 활성 액세스 키의 `last_rotated`가 `iam.access_key_rotation_days`(기본 90일)를 초과하면 FAIL. 키별 finding이며 `resource`는 `<사용자 ARN>#access_key_<번호>`. 루트 키는 IAM-002가 다룬다.
- ISMS-P(초안): 2.10.2 클라우드 보안 (Access Key 관리 절차), 2.5.3 사용자 인증
- KISA: 대응 항목 없음

### IAM-007 관리자 권한 사용자 현황
- 심각도: high
- API: `iam:GetAccountAuthorizationDetails` (사용자·그룹·역할·관리형 정책 본문을 한 번에 받는다)
- 관리자 권한 판별: 사용자에게 직접 또는 그룹을 거쳐 아래 중 하나가 적용되면 관리자로 본다.
  - AWS 관리형 정책 `AdministratorAccess`
  - 관리형·인라인 정책 중 `Effect: Allow`이고 `Action`에 `"*"`, `Resource`에 `"*"`가 포함된 문(statement)
- 판정: 사용자에게 직접 연결된 관리자 권한은 FAIL. 그룹을 거친 관리자 권한은 `REVIEW`로 현황 보고. 관리자 권한이 없는 사용자는 finding을 내지 않으며, 관리자가 한 명도 없으면 계정 단위 PASS 하나.
- 애매한 정책: `Allow` + `NotAction`/`NotResource`처럼 정적 분석으로 관리자 여부를 확정하기 어려운 문이 있거나, 연결된 고객 관리형 정책의 본문이 응답에 없으면 해당 사용자는 `REVIEW`.
- `Deny` 문으로 일부 권한을 막은 경우도 보수적으로 관리자로 판정한다. 권한 경계(permissions boundary)는 evidence에 남기고 판정은 바꾸지 않는다.
- 확인됨 (실습 계정, 2026-10-14): `GetAccountAuthorizationDetails`는 여러 페이지로 나뉘며(`IsTruncated`), 정책 문서는 dict로 풀려서 온다. collector는 관리형 정책의 기본 버전 본문만 보관하고, 룰은 정책을 ARN으로 찾는다.
- 범위 밖: 역할(role)의 관리자 권한은 1단계에서 판정하지 않는다. 같은 API 응답에 들어 있으므로 evidence 수집만 해 두고 이후 룰로 추가한다.
- 비고: 관리자 수의 적정성은 사람이 판단할 영역이므로, 현황 증적 제공이 주목적이다.
- ISMS-P(초안): 2.5.5 특수 계정 및 권한 관리, 2.5.6 접근권한 검토, 2.10.2 클라우드 보안
- KISA: CA-02 사용자 정책 관리 (중, 855쪽) — 근거 수준: 직접

### IAM-008 루트 계정 최근 사용
- 심각도: high
- API: 자격증명 보고서
- 판정: `<root_account>` 행의 `password_last_used`, `access_key_1_last_used_date`, `access_key_2_last_used_date` 중 가장 최근 값이 `iam.root_recent_use_days`(기본 90일) 이내이면 `REVIEW`. 그 외(사용 이력 없음 포함)는 PASS. evidence에 마지막 사용 시각을 담는다.
- 해당 없음: 루트 자격증명이 없는 계정은 `NOT_APPLICABLE` (IAM-001과 같은 판별).
- 사용 이력 확인 불가: 루트 비밀번호가 있는데 `password_last_used`가 `no_information`이면 `REVIEW` (사용자 결정, 2026-10-14). 실습 계정에서 루트로 로그인한 직후에도 `no_information`이었으므로 "사용 안 함"으로 보지 않는다.
- 오류: 자격증명 보고서에 루트 행이 없으면 ERROR.
- 비고: 루트 사용이 계정 복구 등 불가피한 작업이었는지, 서비스 운영 목적이었는지는 사람이 판단한다.
- ISMS-P(초안): 2.5.5 특수 계정 및 권한 관리, 2.10.2 클라우드 보안
- KISA: CA-02 사용자 정책 관리 (중, 855쪽) — 근거 수준: 직접 (Step 2 "콘솔 최상위 관리자(최초 가입계정) 계정은 서비스 운영에 활용 금지")

### IAM-009 외부 자격증명 공급자 사용 (MFA 확인 필요)
- 심각도: medium
- API: `iam:ListSAMLProviders`, `iam:ListOpenIDConnectProviders`, `sso-admin:ListInstances`
- 판정: SAML 공급자, OIDC 공급자, IAM Identity Center 인스턴스마다 `REVIEW` finding을 낸다. Identity Center가 만든 역할(`/aws-reserved/sso.amazonaws.com/` 경로)이 있으면 그 역할 목록으로 `REVIEW` 하나를 낸다 (조직 멤버 계정은 인스턴스가 관리 계정에 있어 조회되지 않기 때문, 사용자 결정 2026-10-14). 하나도 없으면 계정 단위 `NOT_APPLICABLE`이지만, 조회에 실패한 곳이 있으면 ERROR.
- Identity Center 인스턴스는 `--regions`와 관계없이 활성 리전 전체에서 조회한다 (인스턴스는 한 리전에만 있다).
- 이유: 이 경로로 로그인하는 사용자는 IAM 사용자가 아니어서 IAM-003이 보지 못한다. MFA는 IdP 쪽 설정이라 API로 확인할 수 없으므로 사람이 확인해야 한다는 사실을 결과에 남긴다.
- 비고: OIDC 공급자는 GitHub Actions 같은 워크로드 연동에 쓰이는 경우가 많다. 사람이 로그인하는 경로가 아니면 검토자가 그렇게 기록한다.
- 확인됨 (실습 계정, 2026-10-14): `SecurityAudit` 정책으로 `sso-admin:ListInstances`를 17개 활성 리전 모두에서 조회할 수 있다.
- ISMS-P(초안): 2.5.3 사용자 인증, 2.10.2 클라우드 보안
- KISA: CA-03 MFA 설정 (상, 856쪽) — 근거 수준: 직접 ("각 계정별 2차 인증")

### 권한 보유 주체 현황 공통 (IAM-010~011, ADR-044)

`iam:GetAccountAuthorizationDetails`로 받은 정책 문서를 정적으로 분석해, 대상 작업 중 하나라도 허용된 사용자·역할을 찾는다.

- 주체: IAM 사용자(직접 연결한 관리형·인라인 정책과 소속 그룹의 정책)와 역할. AWS 서비스 연결 역할(경로 `/aws-service-role/`)은 AWS가 관리하므로 빼고 개수만 남긴다.
- 일치: `Allow` 문의 `Action`이 대상 작업과 일치하면(와일드카드 `*`·`?`, 대소문자 무시) 권한이 있다고 본다. `Allow` + `NotAction`은 목록에 없는 작업을 모두 허용한 것으로 본다.
- 근사 (보수적): `Resource`는 보지 않는다. `Condition`이 있는 문도 권한으로 세고 evidence에 조건부임을 남긴다. `Deny` 문과 권한 경계는 판정에 쓰지 않는다 (경계 ARN은 evidence). 본문을 확인할 수 없는 관리형 정책은 `unknown_policies`로 남기고, 그런 정책만 있는 주체도 REVIEW로 낸다.
- 판정: 권한을 가진 주체마다 `REVIEW` (권한의 적절성은 사람이 판단). 그런 주체가 없으면 계정 단위 PASS 하나. 권한 정보를 수집하지 못하면 ERROR.
- evidence: 허용된 대상 작업, 정책별 출처(`via`: user·role·`group:<이름>`)와 조건부·NotAction 여부, 권한 경계.
- 비고: 정확한 유효 권한은 `iam:SimulatePrincipalPolicy`로만 확인할 수 있으며, 이는 에이전트 추가 조사에서 쓴다 (ADR-036).

### IAM-010 인스턴스 생성·접근 권한 보유 주체 현황
- 심각도: medium
- API: `iam:GetAccountAuthorizationDetails`
- 대상 작업: `iam.instance_actions` (기본: `ec2:RunInstances`, `ec2:TerminateInstances`, `ec2:StartInstances`, `ec2:StopInstances`, `ec2:ModifyInstanceAttribute`, `ssm:StartSession`, `ssm:SendCommand`, `ec2-instance-connect:SendSSHPublicKey`, `ec2-instance-connect:SendSerialConsoleSSHPublicKey`)
- ISMS-P(초안): 2.6.2 정보시스템 접근, 2.10.2 클라우드 보안
- KISA: CA-05 인스턴스 서비스 정책 관리 (상, 858쪽) — 근거 수준: 직접 ("인스턴스 생성, 삭제, 수정 등에 대한 접근 권한을 설정")

### IAM-011 네트워크 리소스 변경 권한 보유 주체 현황
- 심각도: medium
- API: `iam:GetAccountAuthorizationDetails`
- 대상 작업: `iam.network_actions` (기본: 보안그룹 생성·삭제·규칙 변경, 네트워크 ACL 항목, VPC·서브넷·라우팅·인터넷/NAT 게이트웨이·피어링·탄력적 IP 연결, ELB 생성·삭제·리스너, Route 53 호스팅 영역·레코드 변경)
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.10.2 클라우드 보안
- KISA: CA-06 네트워크 서비스 정책 관리 (상, 859쪽) — 근거 수준: 직접 ("네트워크 리소스 생성, 삭제, 수정 등에 대한 접근 권한을 설정")

## S3

데이터 형태: `bucket_details.<버킷>.<항목>`의 값이 null이면 "설정 없음", 키가 없으면 "수집 실패"다. 로깅이 꺼진 버킷은 AWS가 빈 응답을 주므로 `logging`이 null이다. `ListBuckets`는 버킷 리전을 주지 않아 버킷마다 `GetBucketLocation`으로 확인한다 (실습 계정 확인, 2026-10-13). S3 룰의 `resource`는 버킷 이름(전역 고유)이고 `region`은 버킷 리전이다.

### S3-001 계정 수준 퍼블릭 액세스 차단 미설정
- 심각도: high
- API: `s3control:GetPublicAccessBlock`
- 판정: 4개 설정(`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`)이 모두 true이면 PASS. 설정 없음(`NoSuchPublicAccessBlockConfiguration`)은 FAIL.
- ISMS-P(초안): 2.10.2 클라우드 보안
- KISA: CA-10 스토리지 리소스 퍼블릭 접근 관리 (중, 863쪽) — 근거 수준: 직접

### S3-002 버킷 수준 퍼블릭 액세스 차단 미설정
- 심각도: high
- API: `s3:ListBuckets`, `s3:GetPublicAccessBlock`
- 판정: 버킷별로 4개 설정이 모두 true이면 PASS. 계정 수준이 모두 true이면 버킷 수준이 없어도 PASS로 보되, evidence에 계정 수준 설정을 함께 남긴다. 둘 다 만족하지 않고 버킷·계정 설정 중 하나라도 수집하지 못했으면 ERROR.
- ISMS-P(초안): 2.10.2 클라우드 보안
- KISA: CA-10 스토리지 리소스 퍼블릭 접근 관리 (중, 863쪽) — 근거 수준: 직접

### S3-003 버킷 정책에 의한 퍼블릭 노출
- 심각도: critical
- API: `s3:GetBucketPolicyStatus`
- 판정: `PolicyStatus.IsPublic == true`이면 FAIL. `false`이거나 정책이 없으면 PASS.
- 정책 없음: `GetBucketPolicyStatus`는 정책이 없는 버킷에 `NoSuchBucketPolicy` 오류를 낸다. collector는 이를 수집 실패(ERROR)가 아니라 "정책 없음"으로 기록한다 (실습 환경 확인, 2026-10-13).
- evidence: 계정·버킷 수준 `RestrictPublicBuckets` 값을 함께 남긴다 (공통 원칙: 설정이 존재하면 FAIL).
- 확인됨 (실습 환경, 2026-10-13): `RestrictPublicBuckets: true`로 실제 공개가 막혀 있어도 `IsPublic`은 `true`로 보고된다. evidence의 `restrict_public_buckets`에 버킷·계정 값을 남긴다. `IsPublic`은 정책 문서 자체만 평가하므로, 공통 원칙대로 FAIL로 판정하고 차단 설정을 evidence에 남기는 것이 맞다.
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
- 판정: `LoggingEnabled`가 있으면 PASS. 로그 저장 버킷 자신은 제외 옵션 제공: `s3.exclude_log_target_buckets`(기본 false)를 켜면 다른 버킷의 로그를 받는 버킷은 `NOT_APPLICABLE`.
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

### S3-007 버킷 정책 HTTPS 미강제
- 심각도: medium
- API: `s3:GetBucketPolicy`
- 판정: 버킷 정책에 아래 조건을 모두 만족하는 문장이 있으면 PASS, 정책이 없거나 그런 문장이 없으면 FAIL. 버킷별 finding.
  - `Effect == "Deny"`
  - `Principal`이 `"*"` 또는 `{"AWS": "*"}` (목록이면 `"*"` 포함)
  - `Action`에 `s3:*` 또는 `*` 포함
  - `Resource`가 객체를 포함: `arn:<파티션>:s3:::<버킷>/*` 또는 `*`
  - `Condition`의 `Bool` 또는 `BoolIfExists`에서 `aws:SecureTransport`가 `false` (조건 키는 대소문자 구분 없음)
- 오류: 정책 문서를 수집하지 못했으면 ERROR. 정책 문서를 JSON으로 해석할 수 없으면 ERROR.
- evidence: 조건을 만족한 문장의 `Sid`. 최소 TLS 버전(`s3:TlsVersion`) 조건은 판정하지 않는다.
- 비고: S3 API는 HTTP 요청도 받으므로 HTTPS만 허용하려면 정책으로 거부해야 한다. 서버 원격 접근·데이터 이관 등 나머지 통신 구간은 사람이 확인한다 (CA-12 `partial`).
- ISMS-P(초안): 2.7.1 암호정책 적용, 2.10.2 클라우드 보안
- KISA: CA-12 통신구간 암호화 설정 (중, 865쪽) — 근거 수준: 해석 ("클라우드 리소스 통신 구간에 암호화가 적용된 경우". S3 API 통신을 클라우드 리소스 통신 구간으로 해석. TLS 버전은 판정하지 않음)

## EC2

EC2 룰은 모두 `ec2` 스냅샷(보안그룹, VPC, 서브넷, 라우팅 테이블, 네트워크 인터페이스)을 입력으로 받는다.

### 보안그룹

모든 SG 룰은 점검 대상 리전 전체를 보며, 보안그룹별 finding을 낸다. 인바운드 규칙의 `IpRanges`(0.0.0.0/0)와 `Ipv6Ranges`(::/0)를 모두 확인한다. 모든 SG finding의 evidence에는 그 보안그룹이 연결된 네트워크 인터페이스 수를 남긴다.

데이터 형태 (실습 계정 확인, 2026-10-13): 값이 비어 있는 키는 응답에서 빠진다(예: 태그 없는 기본 VPC에는 `Tags` 키가 없다). 서브넷이 기본 라우팅 테이블을 쓰면 그 테이블의 `Associations`에는 서브넷이 나오지 않는다(`Main: true` 항목만 있다). 룰은 키 존재를 가정하지 않는다.

한계: 규칙이 접두사 목록(`PrefixListIds`)을 참조하면 목록 안의 CIDR은 수집하지 않으므로 전체 개방 여부를 판정하지 않는다. evidence에 접두사 목록 ID를 남긴다.

finding 단위: SG 룰은 보안그룹별, VPC-001은 VPC별, VPC-002는 공인 IP 인터페이스별이다. `resource`는 리소스 ID(`sg-…`, `vpc-…`, `eni-…`)이고 `region`과 함께 리소스를 가리킨다. 스냅샷에 파티션이 없어 ARN을 만들지 않는다. 리전 데이터를 수집하지 못하면 그 리전에 `resource="account"`인 ERROR finding 하나, 리소스가 없으면 NOT_APPLICABLE 하나를 낸다.

포트 포함 판정: `IpProtocol == "-1"`(모든 프로토콜)인 규칙은 모든 포트를 포함한다. 프로토콜은 `tcp`/`udp`와 숫자 표기 `6`/`17`을 모두 인식한다. `tcp`·`udp` 규칙은 `FromPort`~`ToPort` 범위에 포트가 들어 있으면 포함한다.

### SG-001 관리 포트 전체 개방
- 심각도: critical
- API: `ec2:DescribeSecurityGroups`
- 판정: `ec2.admin_ports`(기본 22, 3389)를 포함하는 인바운드 규칙이 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL.
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.6.6 원격접근 통제, 2.10.1 보안시스템 운영
- KISA: CA-09 접근 제어 설정 관리 (상, 862쪽) — 근거 수준: 직접

### SG-002 전체 포트·프로토콜 개방
- 심각도: critical
- API: `ec2:DescribeSecurityGroups`
- 판정: `IpProtocol == "-1"` 또는 0~65535 범위 인바운드 규칙이 0.0.0.0/0 또는 ::/0에 열려 있으면 FAIL. 시작 포트가 1인 `1~65535`도 사실상 전체 개방이므로 포함한다.
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
- 판정: 이름이 `default`인 보안그룹에 인바운드 또는 아웃바운드 규칙이 있고, 네트워크 인터페이스가 하나 이상 연결되어 있으면 FAIL. 연결된 인터페이스가 없으면 PASS (evidence에 규칙 존재를 남긴다). 규칙이 없으면 연결 여부와 관계없이 PASS. 규칙이 있는데 인터페이스를 수집하지 못해 연결 여부를 모르면 ERROR.
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
- 오류: 리소스가 있는 서브넷의 퍼블릭 여부를 판별할 수 없고(연결된 라우팅 테이블도 VPC 기본 테이블도 없음) 프라이빗 서브넷의 리소스도 없으면 FAIL로 단정하지 않고 ERROR. `blackhole` 상태의 IGW 경로는 퍼블릭 경로로 보지 않는다.
- 비고: 퍼블릭 서브넷에 있는 리소스가 공개용으로 의도된 것인지는 사람이 판단한다 (CA-07 `partial`).
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.10.2 클라우드 보안
- KISA: CA-07 VPC 네트워크 서브넷 관리 (상, 860쪽) — 근거 수준: 직접 ("Public 서브넷은 인터넷 게이트웨이로, Private 서브넷은 NAT 게이트웨이로 할당")

### VPC-002 공인 IP가 할당된 네트워크 인터페이스
- 심각도: medium
- API: `ec2:DescribeNetworkInterfaces`
- 판정: `Association.PublicIp`가 있는 네트워크 인터페이스마다 `REVIEW` finding을 낸다. evidence에는 인터페이스 유형, 요청 주체(`RequesterId`), 설명, 연결된 인스턴스, 서브넷(퍼블릭/프라이빗, 라우팅 테이블을 수집하지 못했으면 null), 보안그룹을 담는다. 리전에 해당 인터페이스가 없으면 리전 단위 PASS 하나이며, evidence에 제외한 인터페이스 ID를 남긴다.
- 제외: 공개가 목적인 리소스만 뺀다.
  - NAT 게이트웨이: `InterfaceType == "nat_gateway"`
  - 로드 밸런서: `InterfaceType`이 `network_load_balancer` 또는 `gateway_load_balancer`이거나, `RequesterId == "amazon-elb"`
- 비고: `RequesterManaged == true` 전체를 제외하지 않는다. 공개 RDS 같은 AWS 관리형 리소스의 인터페이스도 이 값이 true이고, 그것이 CA-08의 주요 점검 대상이기 때문이다.
- 확인됨 (실습 계정, 2026-10-16): 공개 RDS의 인터페이스는 `InterfaceType: interface`, `RequesterId: amazon-rds`, `RequesterManaged: true`, 설명 `RDSNetworkInterface`이며 REVIEW로 잡힌다. 비공개 RDS의 인터페이스는 공인 IP가 없어 잡히지 않는다.
- 비고: 내부용 리소스인지는 사람이 판단한다 (CA-08 `partial`).
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.10.2 클라우드 보안
- KISA: CA-08 가상 네트워크 리소스 관리 (중, 861쪽) — 근거 수준: 직접 ("각 서비스 리소스에 공인 IP주소가 존재하지 않고")

### VPC-003 VPC 흐름 로그 미설정
- 심각도: medium
- API: `ec2:DescribeVpcs`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeFlowLogs`
- 판정: VPC별로 네트워크 인터페이스가 활성 흐름 로그(`FlowLogStatus == "ACTIVE"`)로 기록되는지 본다. 흐름 로그는 VPC·서브넷·네트워크 인터페이스 중 어느 단위에 걸려 있어도 인정한다. 모든 인터페이스가 기록되면 PASS, 기록되지 않는 인터페이스가 하나라도 있으면 FAIL.
- 해당 없음: 네트워크 인터페이스가 하나도 없는 VPC는 `NOT_APPLICABLE` (VPC-001과 같다).
- evidence: VPC에 적용되는 흐름 로그(트래픽 유형 `ACCEPT`/`REJECT`/`ALL`, 저장 대상 유형, `DeliverLogsStatus`)와 기록되지 않는 인터페이스 수를 남긴다. 트래픽 유형과 전달 상태는 판정하지 않는다 (기관 정책).
- 비고: 흐름 로그는 네트워크 수준 기록이다. KISA CA-14의 인스턴스 OS·애플리케이션 로그는 API로 확인할 수 없으므로 사람이 판단한다 (CA-14 `partial`).
- ISMS-P(초안): 2.9.4 로그 및 접속기록 관리
- KISA: CA-14 인스턴스 로깅 설정 (중, 867쪽) — 근거 수준: 해석 ("인스턴스 로깅 설정 적용 및 활동 로그 기록 여부 확인". 흐름 로그를 인스턴스 네트워크 활동 기록으로 해석)

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

### CT-002 CloudTrail 로그 버킷 보존 기간 부족
- 심각도: medium
- API: `cloudtrail:DescribeTrails`, `s3:GetBucketLocation`, `s3:GetBucketLifecycleConfiguration` (CloudTrail collector가 추적 버킷에 대해 수집, ADR-043)
- 판정: 추적이 로그를 보내는 S3 버킷마다, 추적 로그 경로(`<S3KeyPrefix>/AWSLogs/`)와 겹치는 활성(`Status == "Enabled"`) 수명주기 규칙이 `logs.min_retention_days`(기본 365일)보다 짧은 `Expiration.Days`를 가지면 FAIL. 날짜 지정 삭제(`Expiration.Date`)도 보존 일수를 보장할 수 없으므로 FAIL. 삭제 규칙이 없으면(수명주기 설정 없음 포함) PASS. 버킷별 finding.
- 경로 겹침: 규칙 접두사(`Filter.Prefix`, `Filter.And.Prefix`, 옛 형식 `Prefix`, 없으면 버킷 전체)가 로그 경로의 앞부분이거나 로그 경로가 규칙 접두사의 앞부분이면 겹친다고 본다. 태그·크기 조건은 보지 않는다 (보수적으로 겹친다고 본다).
- 해당 없음: S3로 로그를 보내는 추적이 없으면 `NOT_APPLICABLE`.
- 오류: 추적 목록이나 버킷의 수명주기 설정을 수집하지 못하면 ERROR. 조직 추적처럼 버킷이 다른 계정에 있으면 보통 조회가 거부되어 ERROR가 된다.
- 비고: 이전 버전 삭제(`NoncurrentVersionExpiration`)와 저장 등급 전환(Glacier 등)은 보존을 해치지 않으므로 보지 않는다. 로그 백업·주기적 검토는 사람이 확인한다 (CA-17 `partial`).
- ISMS-P(초안): 2.9.4 로그 및 접속기록 관리
- KISA: CA-17 로그 보관 기간 설정 (중, 870쪽) — 근거 수준: 직접 ("클라우드 서비스 로그 보관 기간을 기관 정책에 맞게 수립된 경우")

## CloudWatch Logs

### LOG-001 보안 로그 보존 기간 부족
- 심각도: medium
- API: `logs:DescribeLogGroups`, `ec2:DescribeFlowLogs`, `cloudtrail:DescribeTrails` (`logs` collector, ADR-043)
- 판정 대상: 리전마다 보안 로그 그룹만 본다.
  - 같은 계정·리전의 CloudTrail 추적이 보내는 그룹 (`CloudWatchLogsLogGroupArn`)
  - VPC 흐름 로그가 보내는 그룹 (`LogDestinationType == "cloud-watch-logs"`)
  - 이름이 `logs.security_log_group_prefixes`(기본 `/aws/rds/`)로 시작하는 그룹
- 판정: `retentionInDays`가 `logs.min_retention_days`(기본 365일) 미만이면 FAIL, 이상이면 PASS. 키가 없으면(영구 보관) PASS. 추적·흐름 로그가 가리키는 그룹이 없으면 로그가 저장되지 않으므로 FAIL. 로그 그룹별 finding.
- 해당 없음: 리전에 보안 로그 그룹이 없으면 리전 단위 `NOT_APPLICABLE` (evidence에 전체 로그 그룹 수).
- 오류: 로그 그룹 목록, 흐름 로그 목록, 추적 목록 중 하나라도 수집하지 못하면 그 리전은 ERROR (보안 로그 그룹을 빠뜨릴 수 있으므로).
- 비고: Lambda 실행 로그 등 보안 로그로 확인되지 않는 그룹은 판정하지 않는다. 기관이 보안 로그로 쓰는 그룹이 더 있으면 접두사를 설정에 더한다.
- ISMS-P(초안): 2.9.4 로그 및 접속기록 관리
- KISA: CA-17 로그 보관 기간 설정 (중, 870쪽) — 근거 수준: 직접 ("클라우드 서비스 로그 보관 기간을 기관 정책에 맞게 수립된 경우")

## RDS

5단계에서 추가한 룰이다 (ADR-039). 점검 리전(`ScanContext.regions`)마다 `rds:DescribeDBInstances`와 `rds:DescribeDBClusters`로 수집한다. RDS-005(ADR-051)를 위해 인스턴스·클러스터가 쓰는 파라미터 그룹을 `rds:DescribeDBParameters`·`rds:DescribeDBClusterParameters`로 조회하고 SSL 강제 파라미터만 저장한다.

- **대상 엔진.** 관계형 데이터베이스만 본다. `docdb`(DocumentDB)·`neptune`(Neptune)은 같은 API로 조회되지만 대상에서 빼고, 리전 finding의 evidence에 제외한 식별자를 남긴다.
- **클러스터 단위 판정.** `DBClusterIdentifier`가 있는 인스턴스(Aurora, Multi-AZ DB 클러스터)는 암호화·로그·백업이 클러스터 설정이므로 클러스터로 판정한다. 클러스터 finding의 resource는 `cluster:<클러스터 식별자>`로 써서 같은 이름의 인스턴스와 구분한다. 퍼블릭 접근(`PubliclyAccessible`)은 인스턴스 설정이라 RDS-002는 클러스터 소속 인스턴스도 인스턴스 단위로 판정한다.
- **오류.** 리전의 인스턴스 목록이나 클러스터 목록 중 판정에 필요한 것을 수집하지 못하면 그 리전은 ERROR 하나다. 대상 데이터베이스가 없으면 리전 단위 `NOT_APPLICABLE`. 판정에 쓰는 필드가 응답에 없으면 그 리소스는 ERROR다 (데이터가 없다고 양호로 보지 않는다). 예외: `EnabledCloudwatchLogsExports`는 내보내기가 없으면 키가 생략되므로 RDS-003은 키가 없는 것을 "내보내기 없음"으로 본다 (실습 계정에서 확인, 2026-10-16).

- 확인됨 (실습 계정, 2026-10-16): `enable_public_rds = true`로 만든 인스턴스 2개에서 RDS-001~004가 기대값(`public` FAIL, `private` PASS)과 일치한다. 로그 내보내기가 없는 인스턴스는 `EnabledCloudwatchLogsExports` 키가 응답에 없다.

### RDS-001 데이터베이스 스토리지 암호화 미적용
- 심각도: high
- API: `rds:DescribeDBInstances`, `rds:DescribeDBClusters`
- 판정: 클러스터에 속하지 않은 인스턴스와 클러스터마다 `StorageEncrypted == true`이면 PASS, `false`이면 FAIL. evidence에 엔진과 `KmsKeyId`를 남긴다.
- 비고: 클라우드 암호화는 스토리지·백업·스냅샷 암호화이며 테이블·컬럼 단위 암호화가 아니다 (KISA 864쪽 주석). 중요정보 암호화는 증적 요청 목록으로 확인한다.
- ISMS-P(초안): 2.7.1 암호정책 적용
- KISA: CA-11 관계형 데이터베이스 암호화 설정 (중, 864쪽) — 근거 수준: 직접 ("데이터 스토리지 암호화 적용 여부 확인")

### RDS-002 데이터베이스 퍼블릭 접근 허용
- 심각도: high
- API: `rds:DescribeDBInstances`
- 판정: 인스턴스마다 `PubliclyAccessible == true`이면 FAIL, `false`이면 PASS. evidence에 엔진, 서브넷 그룹, VPC 보안그룹, 엔드포인트 주소를 남긴다.
- 비고: `PubliclyAccessible`은 공인 IP를 가진 엔드포인트를 만든다는 뜻이며, 실제 접근 가능 여부는 서브넷 라우팅과 보안그룹에 달려 있다. 공통 원칙("설정이 존재하면 FAIL")에 따라 보안그룹이 막고 있어도 FAIL로 본다.
- ISMS-P(초안): 2.6.1 네트워크 접근, 2.10.2 클라우드 보안
- KISA: CA-08 가상 네트워크 리소스 관리 (중, 861쪽) — 근거 수준: 직접 ("각 서비스 리소스에 공인 IP주소가 존재하지 않고")

### RDS-003 데이터베이스 로그 내보내기 미설정
- 심각도: medium
- API: `rds:DescribeDBInstances`, `rds:DescribeDBClusters`
- 판정: 클러스터에 속하지 않은 인스턴스와 클러스터마다 `EnabledCloudwatchLogsExports`가 비어 있으면 FAIL, 하나 이상이면 PASS. evidence에 내보내는 로그 종류를 남긴다.
- 비고: 필요한 로그 종류(감사·오류·느린 쿼리 등)는 엔진과 기관 정책에 따라 다르므로 종류는 판정하지 않는다. 항목이 `partial`이라 결과는 "검토 필요"가 상한이다.
- ISMS-P(초안): 2.9.4 로그 및 접속기록 관리
- KISA: CA-15 관계형 데이터베이스 로깅 설정 (중, 868쪽) — 근거 수준: 직접 ("관계형 데이터베이스 로깅 설정 적용 및 활동 로그 기록 여부 확인")

### RDS-004 자동 백업 보존 기간 부족
- 심각도: medium
- API: `rds:DescribeDBInstances`, `rds:DescribeDBClusters`
- 판정: 클러스터에 속하지 않은 인스턴스와 클러스터마다 `BackupRetentionPeriod`가 `rds.min_backup_retention_days`(기본 7일) 이상이면 PASS, 미만이면 FAIL. 0은 자동 백업 꺼짐이다.
- 제외: 읽기 전용 복제본(`ReadReplicaSourceDBInstanceIdentifier`가 있는 인스턴스)은 원본의 백업을 따르고 엔진에 따라 자동 백업을 켤 수 없으므로 `NOT_APPLICABLE`.
- 비고: AWS Backup 계획으로 백업하는 경우는 이 룰에서 인정하지 않는다 (AWS Backup collector 이후). 백업·복구 절차는 증적 요청 목록으로 확인한다.
- ISMS-P(초안): 2.9.3 백업 및 복구관리
- KISA: CA-18 백업 사용 여부 (중, 871쪽) — 근거 수준: 직접 ("클라우드 리소스를 기관 정책에 따라 주기적으로 백업이 수행된 경우")

### RDS-005 데이터베이스 SSL 연결 미강제
- 심각도: medium
- API: `rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `rds:DescribeDBParameters`, `rds:DescribeDBClusterParameters`
- 판정: 클러스터에 속하지 않은 인스턴스는 DB 파라미터 그룹, 클러스터는 클러스터 파라미터 그룹에서 엔진별 SSL 강제 파라미터를 본다. 값이 `1`·`ON`·`TRUE`이면 PASS, `0`·`OFF`·`FALSE`이면 FAIL (대소문자 구분 없음).
  - `postgres`·`aurora-postgresql`·`sqlserver-*`: `rds.force_ssl`
  - `mysql`·`mariadb`·`aurora-mysql`: `require_secure_transport`
- 값 없음: `ParameterValue`가 없는 파라미터는 엔진 기본값이며 강제하지 않는 것으로 보고 FAIL. evidence에 `Source`(예: `engine-default`)를 남긴다. PostgreSQL 15 이상의 기본 그룹은 `rds.force_ssl` 값 `1`을 돌려주는 것으로 예상하며 실습 계정에서 확인한다.
- 오류: 파라미터 그룹 이름이 응답에 없거나, 그룹의 파라미터를 수집하지 못했거나, 그룹에 SSL 강제 파라미터가 없거나, 값을 해석할 수 없으면 ERROR.
- REVIEW: 파라미터 그룹으로 SSL을 강제하지 않는 엔진(Oracle은 옵션 그룹의 SSL 옵션, Db2, RDS Custom 등)은 사람이 확인한다.
- evidence: 파라미터 그룹, 파라미터 이름, 값, `Source`, 인스턴스의 `ParameterApplyStatus`.
- 비고: 클라이언트가 실제로 TLS로 접속하는지와 TLS 버전·인증서 검증은 판정하지 않는다. collector는 파라미터 그룹마다 SSL 강제 파라미터만 저장한다.
- ISMS-P(초안): 2.7.1 암호정책 적용, 2.10.2 클라우드 보안
- KISA: CA-12 통신구간 암호화 설정 (중, 865쪽) — 근거 수준: 직접 ("클라우드 리소스 통신 구간에 암호화가 적용된 경우"). 사용자 확인 전 (`kisa_verified: false`)

## GuardDuty

5단계에서 추가한 룰이다 (ADR-041). 점검 리전마다 `guardduty:ListDetectors`·`guardduty:GetDetector`와, GuardDuty 결과의 알림 경로를 보기 위해 `events:ListRules`·`events:ListTargetsByRule`(기본 이벤트 버스)을 같은 스냅샷에 수집한다 (룰은 스냅샷 하나만 본다, ADR-015).

### GD-001 GuardDuty 미활성화
- 심각도: medium
- API: `guardduty:ListDetectors`, `guardduty:GetDetector`
- 판정: 리전마다 `Status == "ENABLED"`인 탐지기가 있으면 PASS, 탐지기가 없거나 모두 `DISABLED`이면 FAIL. 리전 단위 finding 하나.
- 오류: 탐지기 목록을 수집하지 못했거나, 활성 탐지기가 확인되지 않은 상태에서 탐지기 상세를 수집하지 못한 탐지기가 있으면 ERROR.
- evidence: 탐지기별 상태, 결과 게시 주기(`FindingPublishingFrequency`), 보호 기능(`Features`) 상태.
- 비고: Organizations 위임 관리자가 관리하는 멤버 계정도 자기 계정에 탐지기가 있으므로 같은 방식으로 판정한다.
- ISMS-P(초안): 2.11.3 이상행위 분석 및 모니터링, 2.10.2 클라우드 보안
- KISA: CA-19 가상 리소스 이상징후 알림 설정 (중, 872쪽) — 근거 수준: 해석 ("모니터링 또는 이상징후 알림 설정 확인". 이상징후 탐지 서비스 활성화를 알림 설정의 전제로 해석)

### GD-002 GuardDuty 결과 알림 미설정
- 심각도: medium
- API: `events:ListRules`, `events:ListTargetsByRule`
- 판정: GuardDuty가 활성화된 리전에서, 기본 이벤트 버스에 `State == "ENABLED"`이고 이벤트 패턴의 `source`에 `aws.guardduty`가 있으며 대상이 하나 이상인 규칙이 있으면 PASS, 없으면 FAIL.
- 해당 없음: GuardDuty가 활성화되지 않은 리전(GD-001 FAIL)은 `NOT_APPLICABLE`. 탐지기 상태를 모르면 ERROR.
- 오류: 규칙 목록을 수집하지 못했거나, 조건을 만족하는 규칙이 없는데 대상 목록을 수집하지 못한 GuardDuty 규칙이 있으면 ERROR.
- 비고: 알림이 실제로 담당자에게 전달되는지(SNS 구독, 메신저 연동 등)와 Security Hub·다른 계정(위임 관리자) 경유 알림은 판정하지 않는다. 사람이 확인한다 (CA-19 `partial`).
- ISMS-P(초안): 2.11.3 이상행위 분석 및 모니터링, 2.10.2 클라우드 보안
- KISA: CA-19 가상 리소스 이상징후 알림 설정 (중, 872쪽) — 근거 수준: 직접 ("가상 리소스 이상징후 알림 설정이 적용된 경우")

## 룰 추가 절차

1. 이 문서에 룰 항목을 먼저 추가한다 (ID, 심각도, API, 판정 기준, 매핑).
2. `tests/rules/`에 PASS/FAIL/ERROR 테스트를 작성한다.
3. `kompass/rules/<service>/`에 룰을 구현하고 레지스트리에 등록한다.
4. `kompass/mappings/rules.yaml`에 매핑을 추가한다.
5. 필요한 API가 collector에 없으면 collector를 먼저 확장한다.
6. [COVERAGE.md](COVERAGE.md)의 해당 KISA 항목에 룰을 추가한다.
