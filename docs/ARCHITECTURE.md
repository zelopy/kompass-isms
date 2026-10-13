# 아키텍처

## 계층 구조

```
Collector ──► Snapshot ──► Rule Engine ──► Finding ──► Mapper ──► Interpreter ──► Reporter
(boto3,      (원본 설정    (결정론적       (판정 결과)   (KISA/       (LLM+RAG,       (JSON/MD/
 읽기 전용)    JSON 저장)    PASS/FAIL)                  ISMS-P 부착)  해석·조치안)     XLSX)
```

수집과 판정을 분리한다. 스냅샷을 저장해 두면 AWS를 다시 호출하지 않고 룰만 바꿔 재판정할 수 있고, 감사 시 "어떤 데이터로 어떻게 판정했는지"를 재현할 수 있다.

LLM(Interpreter)은 파이프라인 맨 뒤에서 이미 확정된 finding을 읽기만 한다. finding의 `status`는 Rule Engine 이후 변경되지 않는다.

## 디렉터리 구조

```
kompass-isms/
├── kompass/
│   ├── cli.py
│   ├── models.py            # 공용 pydantic 모델
│   ├── aws/
│   │   ├── session.py       # 세션, 리전
│   │   └── guard.py         # 읽기 전용 가드
│   ├── collectors/
│   │   ├── base.py
│   │   ├── iam.py
│   │   ├── s3.py
│   │   ├── ec2.py           # 보안그룹, VPC·서브넷·라우팅 테이블·ENI
│   │   └── cloudtrail.py
│   ├── rules/
│   │   ├── base.py
│   │   ├── registry.py
│   │   ├── iam/
│   │   ├── s3/
│   │   ├── ec2/
│   │   └── cloudtrail/
│   ├── mappings/
│   │   ├── rules.yaml       # 룰 → KISA → ISMS-P
│   │   └── mapper.py
│   ├── interpreter/         # 3단계
│   │   ├── llm.py
│   │   ├── rag.py
│   │   └── masking.py
│   ├── reporters/
│   │   ├── json_reporter.py
│   │   ├── markdown_reporter.py
│   │   └── xlsx_reporter.py
│   └── agent/               # 4단계
├── knowledge/               # RAG 원문 (KISA 가이드, ISMS-P)
├── lab/                     # 취약 실습 환경 Terraform
├── tests/
│   ├── collectors/
│   ├── rules/
│   └── fixtures/
└── docs/
```

## 핵심 모델

아래는 개요이며 정본은 [kompass/models.py](../kompass/models.py)다. 모든 모델은 frozen(생성 후 변경 불가)이고 정의되지 않은 필드를 거부하며, 시각은 시간대가 있는 값만 받는다.

```python
class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"               # 수집 실패, 권한 없음
    REVIEW = "REVIEW"             # 수집은 자동, 양호/취약 판단은 사람이 함
    NOT_APPLICABLE = "N/A"        # 점검 대상 리소스 없음

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Snapshot(BaseModel):
    service: str                  # "iam" | "s3" | "ec2" | "cloudtrail"
    account_id: str
    regions: tuple[str, ...]
    collected_at: datetime        # UTC
    data: dict[str, Any]          # API 응답 원본(필요한 부분), JSON 호환으로 정규화
    errors: tuple[CollectError, ...]  # API별 실패 기록

class Finding(BaseModel):
    rule_id: str                  # "S3-001" (형식 ^[A-Z][A-Z0-9]*-\d{3}$)
    resource: str                 # ARN 또는 계정 단위면 "account"
    region: str | None
    status: Status
    severity: Severity
    message: str                  # 사람이 읽는 판정 요약
    evidence: dict[str, Any]      # 판정 근거가 된 원본 설정 (증적), JSON 호환으로 정규화
    collected_at: datetime        # UTC
    mappings: Mappings | None     # Mapper가 with_mappings()로 채움

class Mappings(BaseModel):
    kisa: tuple[str, ...]
    isms_p: tuple[str, ...]
    verified: bool
```

`evidence`에는 판정에 실제로 쓴 값만 원본 그대로 담는다. 이것이 ISMS-P 증적이 된다.

`data`와 `evidence`는 생성 시 JSON으로 한 번 왕복시켜 정규화한다 (ADR-019). boto3 응답의 `datetime`은 ISO 8601 문자열(`"2026-01-01T00:00:00Z"`)이, 튜플은 리스트가 된다. 바로 수집한 스냅샷과 저장했다 불러온 스냅샷이 같은 모양이므로 룰은 두 경우를 구분하지 않는다. 날짜 계산이 필요한 룰은 `rules/base.py`의 공용 파싱 함수를 쓴다.

`REVIEW`는 룰이 결정론적으로 내리는 상태다. "사람이 판단할 영역"임을 룰 정의에서 미리 정해 두는 것이며, LLM이나 에이전트가 다른 상태를 `REVIEW`로 바꾸는 것이 아니다.

## 항목 단위 집계

finding은 리소스 단위(버킷별, 사용자별, 보안그룹별)로 나오지만, KISA·ISMS-P 점검표는 항목 단위로 결과를 적는다. 항목 결과는 그 항목에 매핑된 모든 finding의 상태를 아래 우선순위로 집계한다.

```
FAIL > ERROR > REVIEW > PASS > N/A
```

| 항목 결과 | 조건 | 점검표 표기 |
|---|---|---|
| FAIL | FAIL이 하나라도 있음 | 취약 |
| ERROR | FAIL 없음, ERROR가 하나라도 있음 | 확인 불가 |
| REVIEW | FAIL·ERROR 없음, REVIEW가 하나라도 있음 | 검토 필요 |
| PASS | 모두 PASS 또는 N/A이고 PASS가 하나 이상 | 양호 |
| N/A | 모두 N/A | 해당 없음 |

- FAIL과 ERROR가 섞여 있으면 FAIL이다. 확인된 취약점이 있으면 항목은 취약이며, 확인 불가 리소스 수는 별도로 표시한다.
- ERROR가 섞인 항목은 절대 양호가 되지 않는다 (ADR-005).
- 집계 함수는 `models.py`에 두고, 우선순위 조합 전체에 대한 테스트를 둔다.

### `partial` 항목의 상한 (ADR-013)

[COVERAGE.md](COVERAGE.md)에서 `partial`로 분류한 항목은 위 규칙으로 PASS가 나오더라도 항목 결과를 `REVIEW`(검토 필요)로 낮춘다. 룰은 자기가 검사한 범위에서 정직하게 PASS를 내고(예: "이 보안그룹에는 전체 개방된 관리 포트가 없음"), 항목 기준 중 API로 확인할 수 없는 나머지(예: "주기적 검토")가 있다는 사실은 집계 단계가 반영한다.

- `partial` 항목에서 자동으로 나올 수 있는 결과: 취약, 확인 불가, 검토 필요. 양호는 나오지 않는다.
- 항목별 분류(full/partial/manual)는 매핑 데이터에 둔다.

## 인터페이스

```python
class Collector(Protocol):
    service: str
    def collect(self, scan: ScanContext) -> Snapshot: ...  # aws/session.py

class Rule(Protocol):
    id: str
    service: str
    title: str
    severity: Severity
    def evaluate(self, snapshot: Snapshot, settings: Settings) -> list[Finding]: ...  # rules/base.py BaseRule
```

- collector는 AWS 호출을 `collectors/base.py`의 `CallRecorder`로 감싼다.
  - 정상 응답은 데이터로, collector가 지정한 "설정 없음" 오류 코드(예: `NoSuchBucketPolicy`, 비밀번호 정책 `NoSuchEntity`)는 `Absent`로 받아 데이터로 기록한다.
  - 그 외 실패(권한 오류, 연결 실패, 호출 제한)는 `CollectError`(operation, region, error_code, message, resource)로 스냅샷 `errors`에 남긴다. 리소스 단위 호출이면 `resource`에 대상(버킷 이름 등)을 적어 그 리소스만 ERROR로 판정할 수 있게 한다.
  - 페이지 조회가 중간에 실패하면 받은 페이지도 버리고 실패로 기록한다. 목록 일부만 보고 "리소스 없음"으로 판정하지 않기 위해서다.
  - 정상 응답에서는 `ResponseMetadata`(HTTP 헤더, 요청 ID 등)를 뺀다. 헤더의 날짜 때문에 같은 설정도 매번 다른 스냅샷이 되는 것을 막는다.
  - 세션 전체 실패(`ExpiredToken`, `InvalidClientTokenId`, `UnrecognizedClientException`, `SignatureDoesNotMatch`, 자격증명 없음)는 기록하지 않고 `SessionError`로 중단한다. 호출마다 ERROR로 쌓으면 보고서 전체가 "확인 불가"로 채워질 뿐이다 (ADR-021).
  - kompass 코드 버그는 잡지 않고 실행을 중단한다: 가드 위반(`ReadOnlyViolation`), 잘못된 파라미터(`ParamValidationError`), 페이지 조회가 안 되는 API(`OperationNotPageableError`), 응답 형식에 없는 `result_key`. 특히 `result_key` 오타는 빈 목록, 즉 "리소스 없음"으로 둔갑하므로 호출 전에 응답 형식과 대조한다.
  - "설정 없음" 오류 코드는 호출마다 collector가 지정한다. 같은 코드가 다른 상황에서도 나올 수 있으므로(예: `GetLoginProfile`의 `NoSuchEntity`는 사용자 자체가 없을 때도 나온다) 호출별로 의미를 확인한다.
- 룰은 하나의 서비스 스냅샷만 입력으로 받는다. 여러 서비스를 엮는 판단은 Interpreter나 Agent의 몫이다.
- 룰은 스냅샷의 `errors`를 확인해서, 필요한 데이터 수집이 실패했으면 `ERROR` finding을 낸다.
- 점검 대상 리소스가 없으면 `NOT_APPLICABLE` finding 하나를 낸다.
- 실행기(`rules/registry.py`)의 규칙 (ADR-023)
  - 스냅샷이 없는 서비스의 룰은 실행하지 않고 "건너뛴 룰"로 따로 돌려준다. PASS가 아니며, 해당 항목은 집계에서 "점검하지 않음"이 된다.
  - 룰은 항상 finding을 하나 이상 내야 하고, 자기 ID의 finding만 내야 한다. 어기면 실행을 중단한다.
  - 룰 코드의 예외는 잡지 않는다. 버그를 ERROR finding으로 숨기지 않는다.
  - finding의 `collected_at`은 스냅샷의 수집 시각이다 (판정 시각이 아니다).
  - 등록된 룰의 ID와 제목이 RULES.md와 일치하는지 테스트로 검사한다.
- 판정 기준값은 `config.py`의 `Settings`(`kompass.yaml`)로 받는다. 정의되지 않은 키는 거부한다. 오타가 조용히 무시되어 기본값으로 판정되는 것을 막는다.

## 스냅샷 저장

`snapshots.py`가 점검 결과를 파일로 남긴다 (ADR-003, ADR-022).

```
.kompass/
├── .gitignore                 # "*" (자동 생성, 실제 계정 데이터 커밋 방지)
└── snapshots/<account_id>/<scan_id>/   # scan_id = 20261013T120000Z-a1b2
    ├── iam.json, s3.json, ...  # 서비스별 Snapshot
    └── scan.json               # ScanManifest: 계정, 호출자, 리전, kompass 버전, 시작·종료 시각, 파일별 SHA-256
```

- `scan.json`은 맨 마지막에 쓴다. 이 파일이 없는 폴더는 중단된 점검이므로 불러오지 않는다.
- 불러올 때 파일별 SHA-256을 `scan.json`과 대조해 손상·수정을 찾는다. 증적 신뢰성을 위한 장치이며, `scan.json` 자체까지 바꾸는 의도적 위조는 막지 못한다.
- 모든 파일은 UTF-8로 쓰고, 임시 파일에 쓴 뒤 이름을 바꾼다. 점검 폴더는 이미 있으면 덮어쓰지 않고 실패하며, POSIX에서는 소유자 전용 권한(0700)으로 만든다.
- 최신 점검 찾기는 완료된 점검 중 시작 시각이 가장 늦은 것이다. 계정을 지정하지 않았는데 여러 계정의 점검이 있으면 오류를 낸다.
- `format_version`을 기록하고, 모르는 버전은 불러오지 않는다.
- 오래된 스냅샷은 자동으로 지우지 않는다.

## 점검 세션

`aws/session.py`의 `open_scan()`이 한 번의 점검 실행에 쓸 `ScanContext`를 만든다 (ADR-021).

- 가드가 걸린 세션(`read_only_session()`), 계정 ID, 파티션, 호출자 ARN(점검 수행 주체), 기본 리전, 점검 리전을 묶는다. 모든 collector가 같은 값을 쓰므로 스냅샷 간 계정·리전이 어긋나지 않는다.
- 자격증명은 AWS 프로필로만 받는다: 액세스 키 프로필, 또는 `role_arn` + `source_profile` 역할 프로필. 역할 자격증명 발급·갱신은 botocore가 하며 `sts:AssumeRole`이 가드를 통과한다 (ADR-020, 확인됨). SSO 프로필은 1단계 미지원(토큰 갱신이 가드에 막힐 수 있음, 미검증).
- 기본 리전은 `--region` → 프로필 리전 순서로 정하고, 없으면 중단한다. 다른 파티션에서 틀릴 수 있으므로 몰래 대체하지 않는다.
- 점검 리전은 `DescribeRegions(AllRegions=True)`의 활성 리전(`opt-in-not-required`, `opted-in`) 중에서 고른다. `--regions`에 알 수 없거나 비활성인 리전이 있으면 점검 전에 중단한다.
- 세션 단계 실패는 `SessionError`로 실행을 중단한다. 계정 ID조차 모르는 상태라 스냅샷을 만들 수 없기 때문이다. 개별 API의 권한 오류를 ERROR finding으로 기록하는 것(ADR-005)과 구분한다.
- `--regions`는 리전 리소스(EC2·VPC 등)에만 적용한다. S3 버킷은 버킷 목록이 전역이므로 리전과 관계없이 모두 점검하고 버킷 리전을 증적에 남긴다. IAM과 계정 단위 설정은 전역이다.
- 모든 client는 점검 도구용 기본 설정을 쓴다: 재시도 `standard` 방식 최대 10회(호출 제한 대응), 연결 대기 10초, 요청 식별자 `kompass/<버전>`. 요청 식별자로 점검 대상 계정의 CloudTrail에서 kompass의 호출을 구분할 수 있다.
- `expected_account_id`(CLI `--account-id`)를 주면 실제 계정이 다를 때 중단한다. 엉뚱한 프로필로 다른 계정을 점검하는 실수를 막는다.
- `regions`에 문자열 하나를 넘기면 `TypeError`. 리전 상태 필드(`OptInStatus`)가 없는 리전은 활성으로 넣는다 (조용히 빠지지 않고 collector 단계에서 드러나도록).
- MFA가 필요한 역할 프로필(`mfa_serial`)은 botocore가 터미널에서 코드를 물으므로 대화형 실행에서만 쓴다.
- boto3 세션은 스레드 안전하지 않다. 병렬 수집을 도입하면 client를 미리 만들거나 스레드마다 `read_only_session()`으로 세션을 만든다.

## 읽기 전용 가드

`aws/guard.py`는 boto3 세션에 botocore `before-call` 이벤트 훅을 등록해서, 허용 목록에 없는 오퍼레이션 호출 시 예외를 발생시킨다.

- 허용: 이름이 `Describe`, `Get`, `List`로 시작하는 오퍼레이션, `GenerateCredentialReport`
- 예외: `sts:AssumeRole` (서비스까지 일치해야 함). 역할 기반 점검 세션에 필요하다 (ADR-020). `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity` 등 변형은 허용하지 않는다
- 그 외 모든 오퍼레이션은 `ReadOnlyViolation` 예외. 요청이 나가기 전에 막으며 paginator, waiter, resource API도 같은 경로로 막힌다
- 모든 collector와 에이전트 도구는 가드가 적용된 세션만 사용한다
- 세션은 `read_only_session()`으로만 만든다. botocore client는 생성 시점의 이벤트 훅만 복사하므로, 이미 있는 세션에 나중에 가드를 걸면 그 전에 만든 client는 보호되지 않는다 (확인됨). 그래서 기존 세션에 가드를 "설치"하는 함수는 두지 않는다
- `ReadOnlyViolation`은 botocore 예외(`ClientError`, `BotoCoreError`)를 상속하지 않는다. collector가 수집 실패를 잡아 ERROR로 기록할 때 가드 위반을 함께 삼키지 않게 하기 위해서다. 가드 위반은 수집 실패가 아니라 코드 버그이므로 실행을 중단시킨다

IAM 역할을 `SecurityAudit`로 제한하는 것과 별개로, 코드 레벨에서도 이중으로 막는다.

## 매핑 파일 형식

```yaml
S3-001:
  title: 계정 수준 S3 퍼블릭 액세스 차단 미설정
  kisa: []                 # 0단계에서 원문 확인 후 채움
  kisa_importance: null    # KISA 원문 중요도 (상 | 중 | 하), 원문 확인 후 채움
  isms_p: ["2.6.1"]
  automation: full         # full | partial | manual
  verified: false          # 원문 근거 확인 전까지 false
```

## 설정

`kompass.yaml`(선택)로 조직별 기준을 조정한다. 예: 비밀번호 정책 기준, 미사용 자격증명 기간, 액세스 키 교체 주기, 위험 포트 목록.

```yaml
iam:
  unused_credential_days: 90
  access_key_rotation_days: 90
  root_recent_use_days: 90
  password_policy:            # KISA CA-04 기준 (ADR-014)
    min_length_two_types: 10
    min_length_three_types: 8
ec2:
  admin_ports: [22, 3389]
  db_ports: [3306, 5432, 1433, 1521, 27017, 6379]
cloudtrail:
  require_read_events: true  # false면 쓰기 이벤트만 기록해도 PASS (ADR-017)
```

## 3단계 이후: Interpreter

1. finding을 마스킹한다 (`masking.py`, 치환 테이블은 로컬에만 보관).
2. 매핑된 항목코드로 RAG에서 원문 청크를 검색한다.
3. LLM은 구조화된 출력(pydantic 스키마)으로 해설, 인용, 위험도 의견, 조치안을 낸다.
4. 인용 검증: 인용된 항목코드가 매핑과 원문에 존재하지 않으면 해당 해설을 폐기하고 재시도하거나 표시한다.
5. 마스킹을 복원해서 보고서에 넣는다.

LLM 응답 스키마에는 `status` 필드를 두지 않는다.
