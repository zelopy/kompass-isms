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
│   │   └── ec2_sg.py
│   ├── rules/
│   │   ├── base.py
│   │   ├── registry.py
│   │   ├── iam/
│   │   ├── s3/
│   │   └── ec2/
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

```python
class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"               # 수집 실패, 권한 없음
    NOT_APPLICABLE = "N/A"        # 점검 대상 리소스 없음

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Snapshot(BaseModel):
    service: str                  # "iam" | "s3" | "ec2_sg"
    account_id: str
    regions: list[str]
    collected_at: datetime
    data: dict[str, Any]          # API 응답 원본(필요한 부분)
    errors: list[CollectError]    # API별 실패 기록

class Finding(BaseModel):
    rule_id: str                  # "S3-001"
    resource: str                 # ARN 또는 계정 단위면 "account"
    region: str | None
    status: Status
    severity: Severity
    message: str                  # 사람이 읽는 판정 요약
    evidence: dict[str, Any]      # 판정 근거가 된 원본 설정 (증적)
    collected_at: datetime
    mappings: Mappings | None     # Mapper가 채움

class Mappings(BaseModel):
    kisa: list[str]
    isms_p: list[str]
    verified: bool
```

`evidence`에는 판정에 실제로 쓴 값만 원본 그대로 담는다. 이것이 ISMS-P 증적이 된다.

## 인터페이스

```python
class Collector(Protocol):
    service: str
    def collect(self, session: boto3.Session, regions: list[str]) -> Snapshot: ...

class Rule(Protocol):
    id: str
    service: str
    title: str
    severity: Severity
    def evaluate(self, snapshot: Snapshot) -> list[Finding]: ...
```

- 룰은 하나의 서비스 스냅샷만 입력으로 받는다. 여러 서비스를 엮는 판단은 Interpreter나 Agent의 몫이다.
- 룰은 스냅샷의 `errors`를 확인해서, 필요한 데이터 수집이 실패했으면 `ERROR` finding을 낸다.
- 점검 대상 리소스가 없으면 `NOT_APPLICABLE` finding 하나를 낸다.

## 읽기 전용 가드

`aws/guard.py`는 boto3 세션에 botocore `before-call` 이벤트 훅을 등록해서, 허용 목록에 없는 오퍼레이션 호출 시 예외를 발생시킨다.

- 허용: 이름이 `Describe`, `Get`, `List`로 시작하는 오퍼레이션, `GenerateCredentialReport`
- 그 외 모든 오퍼레이션은 `ReadOnlyViolation` 예외
- 모든 collector와 에이전트 도구는 가드가 적용된 세션만 사용한다

IAM 역할을 `SecurityAudit`로 제한하는 것과 별개로, 코드 레벨에서도 이중으로 막는다.

## 매핑 파일 형식

```yaml
S3-001:
  title: 계정 수준 S3 퍼블릭 액세스 차단 미설정
  kisa: []                 # 0단계에서 원문 확인 후 채움
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
  password_policy:
    min_length: 8
    require_char_types: 3
ec2_sg:
  admin_ports: [22, 3389]
  db_ports: [3306, 5432, 1433, 1521, 27017, 6379]
```

## 3단계 이후: Interpreter

1. finding을 마스킹한다 (`masking.py`, 치환 테이블은 로컬에만 보관).
2. 매핑된 항목코드로 RAG에서 원문 청크를 검색한다.
3. LLM은 구조화된 출력(pydantic 스키마)으로 해설, 인용, 위험도 의견, 조치안을 낸다.
4. 인용 검증: 인용된 항목코드가 매핑과 원문에 존재하지 않으면 해당 해설을 폐기하고 재시도하거나 표시한다.
5. 마스킹을 복원해서 보고서에 넣는다.

LLM 응답 스키마에는 `status` 필드를 두지 않는다.
