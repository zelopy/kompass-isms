# kompass 사용 매뉴얼

## 0. 이 문서에 대해

kompass로 AWS 계정을 점검하는 진단 담당자를 위한 문서다. 설치부터 점검, 보고서 해석, 수동 항목의 증적 처리, LLM 기능, 결과물 관리까지 다룬다.

명령·옵션, 결과물 경로, 설정 키, 종료 코드는 이 문서가 정본이다. 다른 문서는 이 문서를 가리킨다.

다루지 않는 것과 찾을 곳:

| 내용 | 문서 |
|---|---|
| 룰별 판정 기준 | [RULES.md](RULES.md) |
| KISA 항목별 자동화 범위 | [COVERAGE.md](COVERAGE.md) |
| ISMS-P 매핑 근거 | [ISMS_P_MAPPING_REVIEW.md](ISMS_P_MAPPING_REVIEW.md) |
| 내부 구조 | [ARCHITECTURE.md](ARCHITECTURE.md) |
| 설계 결정과 이유 | [DECISIONS.md](DECISIONS.md) |
| 개발 규칙, 테스트 | [CLAUDE.md](../CLAUDE.md), [PLAN.md](PLAN.md) |
| LLM 평가셋 | [evals/README.md](../evals/README.md) |
| 실습 환경 | [lab/README.md](../lab/README.md) |

표기:
- `<자리표시자>`는 실제 값으로 바꾼다.
- 💲 표시가 있는 명령은 Claude API를 호출해 비용이 발생한다.
- 명령 예시는 저장소 최상위에서 `uv run kompass …`로 실행하는 것을 기준으로 한다.

## 1. 개요

### 1.1 kompass가 하는 일과 하지 않는 일

kompass는 AWS 계정의 설정을 **읽기 전용**으로 수집하고, 코드로 작성한 룰로 양호·취약을 판정해 KISA 클라우드 취약점 점검 항목(CA-01~19)과 ISMS-P 통제항목 기준의 점검표를 만든다.

| 하는 일 | 하지 않는 일 |
|---|---|
| IAM, S3, EC2(보안그룹·VPC), CloudTrail, CloudWatch Logs, RDS, ELB, GuardDuty, AWS Backup 설정 수집 | 대상 계정의 설정 변경 (조회 외의 호출은 코드에서 막힘) |
| 룰 41개로 판정하고 판정 근거(원본 설정)를 증적으로 남김 | LLM으로 양호·취약 판정 |
| KISA 항목·ISMS-P 통제항목 단위로 집계한 보고서 (Markdown, Excel, JSON) | 정책·절차·주기적 검토처럼 API로 볼 수 없는 기준의 자동 판정 |
| 자동 점검으로 확인할 수 없는 항목의 증적 요청서 | ISMS-P 인증 심사 결과 보장 |
| (선택) LLM 해설, 에이전트 추가 조사, 제출 증적 검토 | 인스턴스 내부(OS·애플리케이션) 점검 |

결과는 점검 보조 자료다. ISMS-P 매핑은 담당자 협의 전의 초안이다.

### 1.2 동작 원칙

- **판정은 코드가 한다.** 같은 스냅샷을 판정하면 언제나 같은 결과가 나온다. LLM 해설·추가 조사·증적 검토는 판정 결과를 읽기만 하고 바꾸지 않는다.
- **읽기 전용을 두 번 막는다.** 점검 프로필에는 `SecurityAudit` 정책만 부여하고, 코드에서도 조회 외의 AWS 호출을 요청 전에 차단한다 (허용 범위는 [11장](#11-보안과-데이터-취급)).
- **확인하지 못한 것은 양호가 아니다.** 권한 오류나 수집 실패는 "확인 불가"로 보고한다. 자동 점검만으로 판단할 수 없는 항목은 "검토 필요"를 넘지 않는다.
- **LLM에는 가린 값만 보낸다.** 계정 ID, IP, ARN, 리소스 이름(증적 검토는 개인정보까지)을 자리표시자로 바꿔 보내고, 응답을 받은 뒤 로컬에서 되돌린다.

### 1.3 전체 흐름

```
 collect ──► evaluate ──► report ─────────────► 보고서 (md, xlsx, json)
 └───── scan ─────┘          │
                             ├─ evidence ───────► 증적 요청서 → 담당자 → 제출 문서
                             │                                            │
 (선택)                       ├─ explain 💲       ─┐                       │
                             ├─ investigate 💲   ─┼─► 보고서에 "참고" 절   │
                             ├─ review-evidence 💲 ┘◄───────────────────────┘
                             └─ mcp ─────────────► MCP 클라이언트 (Claude Code 등)
```

| 명령 | AWS 호출 | LLM 호출 | 하는 일 |
|---|---|---|---|
| `collect` | 함 (읽기) | 안 함 | 설정을 수집해 스냅샷으로 저장 |
| `evaluate` | 안 함 | 안 함 | 저장된 스냅샷을 판정 |
| `scan` | 함 (읽기) | 안 함 | collect + evaluate (+ 보고서) |
| `report` | 안 함 | 안 함 | 판정 결과에 매핑을 붙여 보고서 생성 |
| `evidence` | 안 함 | 안 함 | 담당자 증적 요청서 생성 |
| `explain` 💲 | 안 함 | 함 | 조치가 필요한 결과의 룰별 해설, 종합 위험 평가 |
| `investigate` 💲 | 함 (읽기) | 함 | 취약·검토 필요 결과의 추가 조사 |
| `review-evidence` 💲 | 안 함 | 함 | 제출된 증적 문서 검토 |
| `mcp` | 함 (읽기) | 클라이언트가 함 | 판정 결과와 조사 도구를 MCP 서버로 제공 |

## 2. 설치와 준비

### 2.1 요구 사항

- Python 3.12, [uv](https://docs.astral.sh/uv/)
- Windows, macOS, Linux
- 점검 대상 AWS API에 접속할 수 있는 네트워크. LLM 기능을 쓰면 Anthropic API에도 접속해야 한다.

### 2.2 설치

```bash
git clone <저장소 주소> kompass-isms
cd kompass-isms
uv sync
uv run kompass --version
```

### 2.3 점검용 AWS 자격증명

점검 주체(IAM 사용자 또는 역할)에는 AWS 관리형 정책 `SecurityAudit`만 부여한다. kompass는 AWS CLI 프로필(`~/.aws/config`, `~/.aws/credentials`)로만 자격증명을 받는다.

**액세스 키 프로필**

```ini
# ~/.aws/credentials
[kompass-audit]
aws_access_key_id = <액세스 키 ID>
aws_secret_access_key = <비밀 액세스 키>

# ~/.aws/config
[profile kompass-audit]
region = ap-northeast-2
```

**역할 프로필** (점검 대상 계정에 점검 전용 역할을 두는 경우)

```ini
# ~/.aws/config
[profile kompass-audit]
role_arn = arn:aws:iam::<대상 계정 ID>:role/<점검 역할 이름>
source_profile = <자격증명이 있는 프로필>
region = ap-northeast-2
```

- 역할 자격증명의 발급·갱신은 AWS SDK가 처리한다. 점검이 길어져도 다시 로그인할 필요가 없다.
- `mfa_serial`이 있는 역할 프로필은 터미널에서 MFA 코드를 묻는다. 대화형으로 실행할 때만 쓴다.
- **SSO(IAM Identity Center) 프로필은 지원하지 않는다.** 토큰 갱신 호출이 읽기 전용 가드에 막힐 수 있다.
- 기본 리전은 `--region` → 프로필의 `region` 순서로 정한다. 둘 다 없으면 시작하지 않는다.

엉뚱한 프로필로 다른 계정을 점검하는 실수를 막으려면 `--account-id <대상 계정 ID>`를 함께 준다. 실제 계정이 다르면 아무것도 수집하지 않고 멈춘다.

### 2.4 LLM 기능 준비 (선택)

`explain`, `investigate`, `review-evidence`를 쓸 때만 필요하다.

1. Anthropic API 키를 환경 변수로 설정한다. 설정 파일에는 키를 두지 않는다.
   ```bash
   export ANTHROPIC_API_KEY=<API 키>          # macOS·Linux
   $env:ANTHROPIC_API_KEY = "<API 키>"        # Windows PowerShell
   ```
2. 원문 색인을 만든다 (`explain`, `review-evidence`에 필요). KISA 가이드와 ISMS-P 고시 PDF를 [knowledge/SOURCES.md](../knowledge/SOURCES.md)의 출처에서 받아 지정된 경로에 둔 뒤 실행한다. 파일 해시가 기록과 다르면 만들지 않는다.
   ```bash
   uv run python scripts/build_source_index.py
   ```

모델과 추론 깊이(effort)는 `kompass.yaml`의 `llm:`에서 바꾼다 ([부록 B](#b-kompassyaml-전체-키)).

### 2.5 판정 기준값 파일 `kompass.yaml`

조직의 기준이 기본값과 다르면 `kompass.yaml`을 만든다. 파일이 없으면 기본값으로 판정한다.

```yaml
# kompass.yaml 예시: 바꿀 값만 적는다
iam:
  unused_credential_days: 60
logs:
  min_retention_days: 730
ec2:
  admin_ports: [22, 3389, 5985, 5986]
```

- 위치: `--config <경로>`로 지정하거나, 실행하는 폴더의 `kompass.yaml`을 자동으로 읽는다.
- 정의되지 않은 키나 잘못된 값이 있으면 판정 전에 멈춘다 (종료 코드 2). 오타가 조용히 무시되어 기본값으로 판정되는 일을 막기 위해서다.
- 적용한 기준값은 판정 결과 파일과 보고서 "점검 정보"에 남는다. `llm:` 설정은 판정과 무관하므로 남기지 않는다.

전체 키와 기본값은 [부록 B](#b-kompassyaml-전체-키).

## 3. 빠른 시작

```bash
uv run kompass scan --profile <점검 프로필> --account-id <대상 계정 ID> --report md --report xlsx
```

1. 계정·호출자·리전을 확인해 출력한다.
2. 서비스별로 수집하고 스냅샷을 저장한다.
3. 판정하고 룰별 상태 개수를 출력한다.
4. 보고서 경로를 출력한다: `reports/<계정 ID>/<점검 ID>.md`, `.xlsx`

Excel 점검표의 "KISA 항목" 시트부터 본다. 결과 읽는 법은 [6.2](#62-보고서-읽는-법).

`--regions`를 생략하면 활성 리전 전체를 점검한다. 사용하는 리전만 보려면 `--regions ap-northeast-2,us-east-1`처럼 지정한다 ([5.1](#51-수집-collect)).

## 4. 점검 업무 절차

실제 진단 한 건의 흐름이다. 담당자와의 협의 방식은 조직마다 다르므로 필요한 부분만 쓴다.

| 단계 | 할 일 | 명령 |
|---|---|---|
| 1. 사전 협의 | 대상 계정·리전 확정, 점검용 IAM 사용자 또는 역할 발급(`SecurityAudit`만), 기관 기준값 확인 | — |
| 2. 준비 | 프로필 설정, `kompass.yaml` 작성 | [2.3](#23-점검용-aws-자격증명), [2.5](#25-판정-기준값-파일-kompassyaml) |
| 3. 점검 | 수집·판정·보고서 | `scan --account-id … --report md --report xlsx` |
| 4. 결과 확인 | "확인 불가" 결과의 원인(권한·SCP) 확인, 필요하면 권한 보완 후 다시 점검 | [5.4](#54-판정-상태), [13장](#13-문제-해결) |
| 5. 수동 항목 | 증적 요청서를 담당자에게 전달, 제출 문서 수령 | `evidence` |
| 6. 증적 검토 (선택) | 제출 문서를 LLM으로 1차 검토하고 사람이 최종 판단 | `review-evidence` 💲 |
| 7. 해설·조사 (선택) | 조치 방안 초안, 추가 근거 수집 | `explain` 💲, `investigate` 💲 |
| 8. 최종 보고서 | 해설·조사·검토 결과를 붙여 보고서 다시 생성 | `report --format md --format xlsx` |
| 9. 결과물 정리 | 보고서 전달, 점검 자격증명 회수, `reports/`의 계정 데이터 보관·폐기 | [11장](#11-보안과-데이터-취급) |

kompass의 "검토 필요"·"수동 점검" 항목은 사람이 증적을 보고 최종 결과를 정해야 한다. kompass는 그 판단을 대신하지 않는다.

## 5. 수집과 판정

### 5.1 수집 (`collect`)

```bash
uv run kompass collect --profile <점검 프로필> --account-id <대상 계정 ID> [--regions <리전,…>] [--service <서비스>]
```

**점검 범위**

| 대상 | 범위 |
|---|---|
| EC2·VPC·RDS·ELB·GuardDuty·AWS Backup·CloudWatch Logs (리전 리소스) | `--regions`로 지정한 리전. 생략하면 계정의 활성 리전 전체 |
| S3 버킷 | 리전과 관계없이 모든 버킷. 버킷 리전은 증적에 남는다 |
| IAM, 계정 단위 설정 | 전역 |
| IAM Identity Center 인스턴스 | 리전과 관계없이 활성 리전 전체에서 찾는다 |

- `--regions`에 모르는 리전이나 활성화되지 않은 리전이 있으면 시작하지 않는다.
- `--regions`를 생략했을 때 접근이 거부되는 리전(SCP로 리전을 제한한 조직 등)은 점검 범위에서 빼고 경고한다. 보고서 "점검 정보"에 "점검 범위 밖"으로 남는다. 기본 리전까지 거부되면 권한 부족으로 보고 빼지 않는다. 직접 지정한 리전은 빼지 않는다.
- `--service`로 일부 서비스만 수집할 수 있다 (`backup`, `cloudtrail`, `ec2`, `elb`, `guardduty`, `iam`, `logs`, `rds`, `s3`, 여러 번 지정). 수집하지 않은 서비스의 룰은 "건너뛴 룰"이 되고, 해당 KISA 항목은 "점검하지 않음"이 된다.

**수집 결과**

- 서비스별 스냅샷(원본 설정 JSON)과 점검 정보(`scan.json`: 계정, 호출자, 리전, 버전, 시각, 파일별 SHA-256)를 `reports/snapshots/<계정 ID>/<점검 ID>/`에 저장한다.
- 개별 API의 권한 오류·호출 실패는 스냅샷에 기록되고 판정에서 "확인 불가"가 된다. 수집은 계속한다.
- 자격증명 만료처럼 점검 전체가 불가능한 오류는 즉시 멈춘다 (종료 코드 3).
- kompass의 AWS 호출에는 요청 식별자 `kompass/<버전>`이 붙는다. 대상 계정의 CloudTrail에서 kompass의 호출을 구분할 수 있다.

### 5.2 판정 (`evaluate`)

```bash
uv run kompass evaluate [--scan <점검 폴더>] [--config kompass.yaml] [--fail-on fail]
```

- 저장된 스냅샷을 다시 판정한다. AWS를 호출하지 않는다. `--scan`을 생략하면 가장 최근에 완료된 점검을 쓴다.
- 판정 전에 스냅샷 파일의 SHA-256을 `scan.json`과 대조한다. 다르면 판정하지 않는다 (종료 코드 4).
- 판정 결과는 `reports/findings/<계정 ID>/<점검 ID>.findings.json`에 쓴다 (`--output`으로 바꿀 수 있음).
- 기준값만 바꿔 다시 판정할 때 쓴다. 같은 스냅샷과 같은 기준값이면 결과도 같다.

**`--fail-on` (CI 연동)**: 아래 상태의 결과가 하나라도 있으면 종료 코드 1로 끝난다. 지정하지 않으면 취약 결과가 있어도 0이다.

| 값 | 종료 코드 1이 되는 상태 |
|---|---|
| `fail` | 취약 |
| `error` | 취약, 확인 불가 |
| `review` | 취약, 확인 불가, 검토 필요 |

### 5.3 한 번에 실행 (`scan`)

`collect`와 `evaluate`를 이어서 실행하고, `--report`를 주면 보고서까지 만든다. 옵션은 두 명령의 것을 함께 쓴다. `kompass.yaml` 오류는 AWS를 호출하기 전에 드러난다.

### 5.4 판정 상태

finding(리소스 단위 판정 결과)의 상태다.

| 상태 | 보고서 표기 | 뜻 | 할 일 |
|---|---|---|---|
| `FAIL` | 취약 | 룰 기준을 어김 | 조치 |
| `ERROR` | 확인 불가 | 수집 실패·권한 없음으로 판정하지 못함 | 증적의 오류 코드 확인. `AccessDenied`면 권한·SCP를 보완해 다시 점검 |
| `REVIEW` | 검토 필요 | 수집은 자동, 판단은 사람의 몫으로 룰이 정함 (예: 그룹 경유 관리자, 외부 IdP MFA) | 증적을 보고 판단 |
| `PASS` | 양호 | 룰이 검사한 범위에서 위반 없음 | — |
| `N/A` | 해당 없음 | 점검 대상 리소스가 없음 | — |

`PASS`는 "그 룰이 본 범위에서 위반이 없음"이라는 뜻이다. KISA 항목의 양호 여부는 [6.2](#62-보고서-읽는-법)의 집계 규칙을 따른다.

## 6. 보고서

### 6.1 보고서 만들기 (`report`)

```bash
uv run kompass report [--findings <판정 결과 파일>] [--format md --format xlsx]
```

| 형식 | 파일 | 내용 |
|---|---|---|
| `md` | `<점검 ID>.md` | 사람이 읽는 보고서 |
| `xlsx` | `<점검 ID>.xlsx` | 점검표. 결과별 색상과 필터 |
| `json` | `<점검 ID>.report.json` | 매핑을 붙인 finding과 전체 증적 (다른 도구 연동용) |
| `evidence` | `<점검 ID>.evidence.xlsx` | 담당자 증적 요청서 ([7.1](#71-증적-요청서-evidence)) |

- `--format`을 생략하면 `md`와 `xlsx`를 만든다. 파일은 `reports/<계정 ID>/`에 생긴다.
- 매핑(KISA·ISMS-P)은 판정 때가 아니라 보고서를 만들 때 붙인다. 매핑 데이터가 바뀌어도 다시 판정할 필요 없이 `report`만 다시 실행하면 된다. 보고서에는 매핑 데이터 해시가 남는다.
- 보고서를 만들 때도 스냅샷 해시를 다시 대조한다. 판정 뒤 증적이 바뀌었으면 보고서를 만들지 않는다.
- 같은 판정 결과에 대한 해설·추가 조사·증적 검토 결과가 있으면 "참고" 절로 함께 붙는다. 그 뒤에 다시 판정했으면 붙이지 않고 경고한다.

### 6.2 보고서 읽는 법

**KISA 항목 단위 집계.** 리소스 단위 finding을 항목 단위로 모을 때 다음 우선순위를 따른다.

```
취약 > 확인 불가 > 검토 필요 > 양호 > 해당 없음
```

- 취약 finding이 하나라도 있으면 항목은 취약이다. 확인 불가 리소스 수는 따로 표시된다.
- 확인 불가가 섞인 항목은 절대 양호가 되지 않는다.

**자동화 분류(`full`/`partial`).** 각 KISA 항목은 자동 판정 범위에 따라 분류되어 있다 ([COVERAGE.md](COVERAGE.md)).

| 분류 | 뜻 | 나올 수 있는 항목 결과 |
|---|---|---|
| `full` | 판단 기준 전체를 API로 판정 | 취약, 양호, 확인 불가, 해당 없음 |
| `partial` | 명백한 취약은 자동 판정, 양호 판단에는 사람의 확인 필요 | 취약, 검토 필요, 확인 불가 |

`partial` 항목은 룰이 모두 양호여도 "검토 필요"로 표시된다. "주기적 검토"처럼 API로 볼 수 없는 기준이 남아 있기 때문이며, 증적 요청서로 확인한다.

**그 밖의 항목 결과**

| 표기 | 뜻 |
|---|---|
| 점검하지 않음 | 담당 룰을 실행하지 않음 (`--service`로 해당 서비스를 수집하지 않음) |
| 수동 점검 (미구현) | 담당 룰이 없음. 지금은 KISA 19개 항목 모두 룰이 있다 |
| 점검 범위 밖 (점검 정보) | 접근 거부로 점검 범위에서 뺀 리전 ([5.1](#51-수집-collect)) |

**Markdown 보고서 구성**: 점검 정보(수행 주체, 시각, 적용 기준값, 매핑 데이터 해시, 점검 범위 밖 리전) → 요약 → KISA 항목별 결과 → 조치가 필요한 결과(항목별 핵심 증적) → KISA 대응 항목이 없는 룰 → 증적 요청 목록 → (있을 때) AI 해설, 추가 조사, 증적 검토 → ISMS-P 통제항목(초안) → 건너뛴 룰.

**Excel 점검표 시트**: 요약, KISA 항목, 점검 결과(finding 전체와 증적), ISMS-P (초안), 증적 요청, (있을 때) AI 해설 (참고), AI 종합 평가 (참고), 추가 조사 (참고), 증적 검토 (참고).

### 6.3 ISMS-P 매핑과 검증 여부

KISA 항목과 ISMS-P 통제항목 사이에는 공식 대응표가 없다. kompass의 ISMS-P 매핑은 인증기준(고시 별표 7)과 안내서를 근거로 만든 **초안**이며, 보고서의 ISMS-P 절·시트에 "초안"으로 표시된다.

- ISMS-P 통제항목은 관련 룰이 모두 양호여도 자동으로 양호가 되지 않는다. 통제항목에는 정책·절차 같은 관리 요소가 있기 때문이다.
- KISA 매핑은 원문 근거를 확인했다 (`kisa_verified`). ISMS-P 매핑은 담당자 협의 전까지 확인되지 않은 상태다 (`isms_p_verified: false`). 근거와 협의 쟁점은 [ISMS_P_MAPPING_REVIEW.md](ISMS_P_MAPPING_REVIEW.md).

## 7. 수동 항목: 증적 요청과 검토

### 7.1 증적 요청서 (`evidence`)

```bash
uv run kompass evidence [--findings <판정 결과 파일>]
```

자동 점검만으로 확인할 수 없는 기준(검토 기록, 절차서, 기관 정책 등)을 담당자에게 요청하는 Excel 파일을 만든다. LLM과 AWS를 호출하지 않는다.

- 대상: `partial` 항목은 항상, `full` 항목은 결과가 확정되지 않았거나 검토 필요·확인 불가 finding이 있을 때.
- 요청 문구는 KISA 원문 구절을 근거로 한 고정 목록이다. 매번 같은 요청이 나온다.
- 파일: `reports/<계정 ID>/<점검 ID>.evidence.xlsx`

| 시트 | 내용 |
|---|---|
| 안내 | 계정, 점검 ID, 판정 시각, 요청 범위, 작성 방법 |
| 요청 증적 | 번호(요청 ID, 예: `CA-02-1`), KISA 항목, 항목명, 결과, 요청 증적, 확인 목적, 원문 근거, 그리고 담당자가 채울 담당자·제출일·제출 여부·비고 칸 |
| 확인 대상 | 요청과 관련된 검토 필요·확인 불가 리소스 (KISA 항목, 룰, 결과, 리소스, 리전, 내용) |

담당자에게는 요청 ID별 폴더로 파일을 제출해 달라고 안내한다. [7.2](#72-제출-증적-검토-review-evidence-)의 검토 기능이 이 폴더 구조를 쓴다.

같은 요청 목록은 보고서의 "증적 요청 목록" 절·시트에도 들어간다.

### 7.2 제출 증적 검토 (`review-evidence`) 💲

```bash
uv run kompass review-evidence --dir <증적 폴더> --terms <마스킹 사전> --dry-run   # 미리보기와 비용만
uv run kompass review-evidence --dir <증적 폴더> --terms <마스킹 사전> --report md --report xlsx
```

제출된 문서가 요청의 확인 목적을 충족하는지 LLM이 요청별로 1차 검토한다. 결과는 참고 자료이며 항목 결과와 요청서의 제출 여부를 바꾸지 않는다.

**증적 폴더 구조**

```
<증적 폴더>/
├── CA-02-1/
│   ├── 권한 검토 기록.pdf
│   └── 관리자 목록.xlsx
└── CA-17-1/
    └── 로그 보관 정책.txt
```

- 요청 ID 폴더 아래는 하위 폴더까지 읽는다. 요청 ID가 아닌 폴더, 증적 폴더 바로 아래의 파일, 숨김 파일, Office 잠금 파일(`~$…`), 심볼릭 링크는 읽지 않고 경고한다.
- 증적 폴더는 저장소 밖이나 커밋하지 않는 위치에 둔다. 제출 문서에는 개인정보가 들어 있을 수 있다.

**지원 형식**: PDF, xlsx, txt·md·csv·json (CSV는 UTF-8 또는 CP949). 이미지, 스캔 PDF, docx, hwp, 20MB를 넘는 파일은 "사람이 검토할 파일"로 기록하고 보내지 않는다. 원본 파일은 LLM에 보내지 않고, 로컬에서 뽑은 텍스트만 보낸다.

**마스킹 사전 (`--terms`)**: 직원 이름, 부서명 등 LLM에 보내지 않을 용어를 UTF-8 텍스트 파일에 한 줄에 하나씩 적는다. 빈 줄과 `#`으로 시작하는 줄은 건너뛴다. 사전이 없으면 경고한다. 이메일, 전화번호, 주민등록번호는 패턴으로 자동으로 가린다.

**전송 전 확인**: 보내기 전에 마스킹한 프롬프트 전체를 미리보기 파일(`reports/evidence-reviews/<계정 ID>/<점검 ID>.evidence-preview.md`)로 쓰고, 종류별로 가린 값의 수와 예상 비용을 보여 준다. 미리보기에서 가려지지 않은 이름·연락처가 없는지 확인한 뒤 진행한다. 한글 이름은 패턴으로 모두 잡을 수 없으므로 이 확인이 마지막 안전장치다.

**제한**: 문서 하나에서 50,000자까지, 요청 하나에 문서 10개까지 보낸다. 넘는 부분은 사람이 검토한다.

**검토 결과**: 요청마다 문서에서 확인된 사실(문서 발췌와 함께), 확인 목적 대비 부족한 점, 추가 요청을 낸다. 발췌가 실제 문서에 있는지 코드로 대조해 "발췌 검증됨"/"검증되지 않음"을 표시한다. 결과 파일은 `reports/evidence-reviews/<계정 ID>/<점검 ID>.evidence-review.json`이며 복원된 원문 구절(개인정보 포함)이 들어 있다.

## 8. LLM 해설 (`explain`) 💲

```bash
uv run kompass explain --dry-run                       # 대상과 예상 비용만
uv run kompass explain --report md --report xlsx       # 해설 후 보고서 다시 생성
uv run kompass explain --assessment-only --report md   # 종합 위험 평가만 다시
```

조치가 필요한 결과(취약·확인 불가·검토 필요)를 룰 단위로 묶어 해설한다. 원문 색인과 `ANTHROPIC_API_KEY`가 필요하다 ([2.4](#24-llm-기능-준비-선택)).

**룰별 해설 내용**: KISA·ISMS-P 원문 인용, 위험 설명, 우선순위 의견, 조치 방안(AWS CLI 명령, Terraform 수정안).

- 인용 구절은 원문 색인과 대조해 "검증됨"/"검증되지 않음"을 표시한다. 문제가 있으면 한 번 다시 요청한다.
- 우선순위는 LLM의 의견이며 룰의 심각도나 판정을 바꾸지 않는다.
- 조치 명령은 초안이다. 실행 전에 대상 리소스와 영향을 반드시 확인한다.

**종합 위험 평가**: 룰별 해설 뒤 보고서 전체를 한 번 더 보내, 여러 결과가 겹쳐 생기는 위험 시나리오와 조치 순서를 만든다. `--no-assessment`로 끄고, 실패했을 때는 `--assessment-only`로 룰별 해설을 다시 만들지 않고 종합 평가만 다시 만든다.

**비용 확인**: 요청 전에 대상(룰·finding 수), 입력 토큰(마스킹한 프롬프트 기준), 예상 비용을 보여 주고 확인을 받는다. `--dry-run`은 여기서 끝내고, `--yes`는 확인을 건너뛴다.

**전송 직전 검사**: 마스킹한 뒤에도 원본 리소스 값이나 일부만 가려진 값이 남으면 그 룰은 보내지 않고 경고한다. 짧고 흔한 리소스 이름(예: `logs`)은 다른 단어 속에서도 걸려 정상 요청이 막힐 수 있다. 안전한 쪽(보내지 않음)으로 틀리는 것이다.

- 결과 파일: `reports/explanations/<계정 ID>/<점검 ID>.explanations.json` (마스킹이 복원된 상태)
- 보고서: Markdown "AI 해설 (참고)" 절, Excel "AI 해설 (참고)"·"AI 종합 평가 (참고)" 시트
- 해설 뒤 다시 판정하면 해설이 보고서에 붙지 않는다. 다시 해설해야 한다.
- 모델·effort·최대 출력 토큰·시간 제한은 `kompass.yaml`의 `llm:` ([부록 B](#b-kompassyaml-전체-키)).

## 9. 에이전트 추가 조사 (`investigate`) 💲

```bash
uv run kompass investigate --dry-run                                   # 대상과 최대 비용만
uv run kompass investigate --profile <점검 프로필> --report md --report xlsx
```

취약·검토 필요 결과를 룰 단위로 에이전트가 추가 조사한다. 예를 들어 공개 버킷이면 버킷 정책 전문과 CloudTrail 데이터 이벤트 기록 여부를, 관리자 권한이면 정책 시뮬레이션 결과를 조회한다. 판정은 바꾸지 않는다.

- **조사 도구 12개** (모두 읽기 전용): `s3_bucket_access`, `s3_account_public_access_block`, `cloudtrail_data_events`, `cloudtrail_lookup_events`, `ec2_security_group`, `ec2_interfaces_for_security_group`, `ec2_instance`, `ec2_subnet_routes`, `iam_user_access`, `iam_policy_document`, `iam_inline_policy`, `iam_simulate_principal_policy`. 권한이 없는 조회는 도구 결과에 오류로 남고 조사는 계속한다.
- **세션**: 판정 결과와 같은 계정·리전 범위로 세션을 연다. 프로필의 계정이 다르면 시작하지 않는다. 비용 확인을 받은 뒤에 AWS에 접속한다.
- **상한**: 룰 하나당 도구 호출 `--max-calls`(기본 15회), 토큰 `--max-tokens`(기본 200,000), 반복 12회. 룰 하나에 finding은 20건까지 넘긴다.
- **비용**: 미리 셀 수 없으므로 "룰 수 × 토큰 상한 × 입력 단가"로 계산한 최대 비용을 보여 준다. 실제 비용은 보통 이보다 적다.
- **근거 검증**: 조사 결과의 사실마다 근거가 된 도구 호출 ID를 달고, 실제 호출과 대조해 "근거 검증됨"을 표시한다.
- **마스킹**: 도구 결과도 가린 뒤 LLM에 보낸다. LLM이 자리표시자로 도구를 호출하면 kompass가 로컬에서 원래 값으로 바꿔 조회한다.
- 결과 파일: `reports/investigations/<계정 ID>/<점검 ID>.investigation.json` (도구 호출 기록 포함). 보고서 "추가 조사 (참고)" 절·시트.

## 10. MCP 서버 연동 (`mcp`)

Claude Code 같은 MCP 클라이언트에서 판정 결과를 조회하고 추가 조사를 대화형으로 할 수 있다. 클라이언트가 서버를 실행하므로 직접 실행할 일은 없다.

```bash
# Claude Code에 등록
claude mcp add kompass -- uv --directory <저장소 경로> run kompass mcp --profile <점검 프로필>
```

- 도구: 판정 결과 조회 `kompass_findings`(상태·룰로 거르기, 페이지 단위)와 [9장](#9-에이전트-추가-조사-investigate-)의 조사 도구 12개. 판정을 바꾸는 도구는 없다.
- 노출 대상은 가장 최근 판정 결과다. 다른 결과는 `--findings`, 여러 계정이면 `--account-id`로 고른다. 판정 결과와 다른 계정의 프로필이면 시작하지 않는다.
- 클라이언트 뒤의 LLM에도 가린 값만 보낸다. 세션 동안 같은 리소스는 같은 자리표시자로 보이며, 도구 입력에 자리표시자를 쓰면 서버가 원래 값으로 바꿔 조회한다.
- 세션당 AWS 조회 상한 `--max-calls` (기본 50회).
- 호출 로그: `reports/mcp/<계정 ID>/<점검 ID>.<시작 시각>.mcp.jsonl` (원래 입력값과 마스킹한 결과)

## 11. 보안과 데이터 취급

**대상 계정에 대한 호출**

- 허용: 이름이 `Describe`, `Get`, `List`로 시작하는 작업, `iam:GenerateCredentialReport`, 그리고 서비스까지 일치하는 예외 3개(`sts:AssumeRole` 역할 프로필용, `cloudtrail:LookupEvents`·`iam:SimulatePrincipalPolicy` 추가 조사용).
- 그 밖의 호출은 요청이 나가기 전에 코드가 막고 실행을 멈춘다. `SecurityAudit` 정책 제한과 함께 이중으로 막는다.
- `GenerateCredentialReport`는 IAM 자격증명 보고서 생성을 요청할 뿐 설정을 바꾸지 않는다.

**외부(Anthropic API)로 나가는 데이터** (LLM 기능을 쓸 때만)

| 기능 | 보내는 것 | 가리는 것 |
|---|---|---|
| `explain` | 조치가 필요한 finding의 메시지·증적, 매핑된 원문 | 계정 ID, IP, ARN, 리소스 이름·ID, IAM 고유 ID·액세스 키 ID |
| `investigate`, `mcp` | 위 내용과 조사 도구 결과 | 위와 같음 |
| `review-evidence` | 제출 문서에서 뽑은 텍스트, 요청·확인 대상 | 위 항목 + 이메일·전화번호·주민등록번호·마스킹 사전 용어 |

`0.0.0.0/0`, AWS 관리형 정책 ARN 같은 판정의 의미가 담긴 값은 가리지 않는다.

**로컬 결과물**

- `reports/` 아래의 모든 파일은 실제 계정 데이터다. 저장소 안이면 자동으로 git에서 제외된다(`reports/.gitignore`). 보고서를 외부에 전달할 때는 전달 범위를 확인한다.
- 해설·조사·검토 결과 파일은 마스킹이 복원된 원문이고, 증적 검토 결과에는 개인정보가 들어 있을 수 있다.
- 오래된 점검 결과는 자동으로 지워지지 않는다. 진단이 끝나면 조직의 보관 기준에 따라 보관하거나 폐기한다.
- 점검이 끝나면 점검용 액세스 키나 역할을 회수하도록 담당자에게 요청한다.

## 12. 결과물 구조

저장 위치는 `--store` → 환경 변수 `KOMPASS_STORE` → kompass 저장소 최상위의 `reports/` → (저장소 밖에서 실행하면) 현재 폴더의 `reports/` 순서로 정한다.

```
reports/
├── .gitignore                                       # 자동 생성 ("*")
├── <계정 ID>/
│   ├── <점검 ID>.md                                  # 보고서
│   ├── <점검 ID>.xlsx                                # 점검표
│   ├── <점검 ID>.report.json                         # JSON 보고서
│   └── <점검 ID>.evidence.xlsx                       # 증적 요청서
├── findings/<계정 ID>/<점검 ID>.findings.json         # 판정 결과
├── explanations/<계정 ID>/<점검 ID>.explanations.json # LLM 해설
├── investigations/<계정 ID>/<점검 ID>.investigation.json  # 추가 조사
├── evidence-reviews/<계정 ID>/
│   ├── <점검 ID>.evidence-review.json                # 증적 검토
│   └── <점검 ID>.evidence-preview.md                 # 전송 전 미리보기
├── mcp/<계정 ID>/<점검 ID>.<시작 시각>.mcp.jsonl       # MCP 호출 로그
└── snapshots/<계정 ID>/<점검 ID>/
    ├── iam.json, s3.json, …                         # 서비스별 스냅샷
    └── scan.json                                     # 점검 정보, 파일별 SHA-256
```

- 점검 ID는 UTC 시작 시각과 무작위 접미사다 (예: `20261013T120000Z-a1b2`).
- `scan.json`이 없는 점검 폴더는 중단된 점검이므로 쓰지 않는다.
- 명령에서 판정 결과나 점검을 지정하지 않으면 가장 최근 것을 쓴다. 저장 위치에 여러 계정의 결과가 있으면 `--account-id`로 계정을 지정해야 한다.

## 13. 문제 해결

**종료 코드**

| 코드 | 뜻 |
|---|---|
| 0 | 완료 (취약 결과가 있어도 0) |
| 1 | `--fail-on` 기준에 해당하는 결과가 있음 |
| 2 | 사용법·설정 오류 (`kompass.yaml`, 옵션, 원문 색인 없음, API 키 없음 등) |
| 3 | 세션 오류 (자격증명, 프로필, 리전, 계정 불일치) 또는 조사 중 읽기 전용 가드 차단 |
| 4 | 스냅샷 오류 (점검·판정 결과 없음, 중단된 점검, 해시 불일치) |
| 5 | LLM 해설·추가 조사·증적 검토가 모두 실패, 또는 마스킹 검사를 통과한 대상이 없음 |

**자주 만나는 상황**

| 메시지 | 원인과 대응 |
|---|---|
| `기본 리전을 정할 수 없습니다` | `--region`을 주거나 프로필에 `region`을 설정한다 |
| `AWS 프로필을 찾을 수 없습니다` / `AWS 자격증명을 찾을 수 없습니다` | `--profile` 이름과 `~/.aws/config`·`credentials`를 확인한다 |
| `점검 대상 계정이 예상과 다릅니다` | `--account-id`와 다른 계정의 프로필이다. 프로필을 확인한다 |
| `알 수 없는 리전` / `이 계정에서 활성화되지 않은 리전` | `--regions` 값을 확인한다 |
| `기본 리전 … 에 연결할 수 없습니다` | 리전 이름과 네트워크(프록시, 방화벽)를 확인한다 |
| 결과에 확인 불가가 많음 | 증적의 오류 코드를 본다. `AccessDenied`·`UnauthorizedOperation`이면 점검 주체의 정책·SCP를 확인하고 다시 점검한다 |
| IAM-003·005·006이 사용자별로 확인 불가 | 자격증명 보고서 생성 뒤에 만든 사용자다. AWS는 4시간 안에 만든 보고서를 재사용하므로 나중에 다시 점검한다 |
| `여러 계정의 … 있습니다` | `--account-id`로 계정을 지정한다 |
| `스냅샷 파일이 기록과 다릅니다` | 판정 뒤 스냅샷이 손상되거나 수정되었다. 다시 수집한다 |
| `원문 색인이 없습니다` | [2.4](#24-llm-기능-준비-선택)의 색인 생성을 실행한다 |
| `Claude API 키가 없습니다` | `ANTHROPIC_API_KEY`를 설정한다 |
| `마스킹 검증에 실패해 보내지 않을 룰` | 가리지 못한 값이 남아 그 룰을 보내지 않았다. 짧고 흔한 리소스 이름이 원인인 경우가 많다 |
| 해설·조사가 보고서에 안 붙음 (경고) | 해설·조사 뒤에 다시 판정했다. 해설·조사를 다시 실행한다 |
| `응답이 max_tokens에서 잘림` | `kompass.yaml`의 `llm.max_tokens`를 늘린다 |

## 부록

### A. 명령·옵션 레퍼런스

**공통 옵션**

| 옵션 | 쓰는 명령 | 설명 |
|---|---|---|
| `--profile` | collect, scan, investigate, mcp | AWS CLI 프로필 |
| `--region` | collect, scan, investigate, mcp | 기본 호출 리전. 없으면 프로필의 리전 |
| `--regions` | collect, scan | 리전 리소스를 점검할 리전. 쉼표 구분 또는 여러 번 지정. 없으면 활성 리전 전체 |
| `--account-id` | 전체 | 점검 대상 계정 ID. AWS에 접속하는 명령은 실제 계정이 다르면 중단하고, 그 밖의 명령은 최근 결과를 고를 계정으로 쓴다 |
| `--store` | 전체 | 결과 저장 위치 ([12장](#12-결과물-구조)) |
| `--config` | evaluate, scan, explain, investigate, review-evidence | 기준값·LLM 설정 파일. 없으면 현재 폴더의 `kompass.yaml` |
| `--findings` | report, evidence, explain, investigate, review-evidence, mcp | 판정 결과 파일. 없으면 가장 최근 것 |
| `--report` | scan, explain, investigate, review-evidence | 끝난 뒤 이 형식의 보고서도 만듦 (`md`, `xlsx`, `json`, `evidence`, 여러 번 지정) |
| `--dry-run` | explain, investigate, review-evidence | 요청하지 않고 대상과 비용만 보여 줌 |
| `--yes`, `-y` | explain, investigate, review-evidence | 확인 없이 진행 |

**명령별 옵션**

| 명령 | 옵션 | 설명 |
|---|---|---|
| `collect`, `scan` | `--service` | 수집할 서비스. 여러 번 지정. 없으면 전체 |
| `evaluate` | `--scan` | 판정할 점검 폴더. 없으면 가장 최근의 완료된 점검 |
| `evaluate`, `scan` | `--output` | 판정 결과 파일 경로 |
| `evaluate`, `scan` | `--fail-on` | `fail`, `error`, `review` ([5.2](#52-판정-evaluate)) |
| `report` | `--format` | 보고서 형식. 여러 번 지정. 없으면 `md`, `xlsx` |
| `explain` | `--no-assessment` | 종합 위험 평가를 하지 않음 |
| `explain` | `--assessment-only` | 저장된 룰별 해설을 두고 종합 위험 평가만 다시 만듦 |
| `investigate` | `--max-calls` | 룰 하나의 도구 호출 상한 (기본 15) |
| `investigate` | `--max-tokens` | 룰 하나의 토큰 상한 (기본 200,000, 최소 10,000) |
| `review-evidence` | `--dir` | 증적 폴더 (필수) |
| `review-evidence` | `--terms` | 마스킹 사전 파일 |
| `mcp` | `--max-calls` | 세션 하나의 AWS 조사 도구 호출 상한 (기본 50) |

전체 옵션은 `uv run kompass <명령> --help`로도 볼 수 있다.

### B. `kompass.yaml` 전체 키

| 키 | 기본값 | 쓰는 룰 | 뜻 |
|---|---|---|---|
| `cloudtrail.require_read_events` | `true` | CT-001 | 관리 이벤트를 읽기·쓰기 모두 기록해야 양호. `false`면 쓰기만 기록해도 양호 |
| `ec2.admin_ports` | `[22, 3389]` | SG-001 | 전체 개방되면 안 되는 관리 포트 |
| `ec2.db_ports` | `[3306, 5432, 1433, 1521, 27017, 6379]` | SG-003 | 전체 개방되면 안 되는 데이터베이스 포트 |
| `s3.require_kms` | `false` | S3-004 | `true`면 SSE-KMS일 때만 양호 |
| `s3.exclude_log_target_buckets` | `false` | S3-005 | `true`면 다른 버킷의 로그를 받는 버킷은 해당 없음 |
| `iam.unused_credential_days` | `90` | IAM-005 | 미사용 자격증명 기준 일수 |
| `iam.access_key_rotation_days` | `90` | IAM-006 | 액세스 키 교체 주기 일수 |
| `iam.root_recent_use_days` | `90` | IAM-008 | 루트 계정 최근 사용으로 볼 일수 |
| `iam.password_policy.min_length_two_types` | `10` | IAM-004 | 문자 종류 2종 조합일 때 최소 길이 (KISA CA-04) |
| `iam.password_policy.min_length_three_types` | `8` | IAM-004 | 문자 종류 3종 조합일 때 최소 길이 (KISA CA-04) |
| `iam.instance_actions` | `[9개 작업]` | IAM-010 | 인스턴스 생성·삭제·수정·접속 작업 (`ec2:RunInstances`, `ssm:StartSession` 등). 와일드카드 허용 |
| `iam.network_actions` | `[27개 작업]` | IAM-011 | 보안그룹·네트워크 ACL·VPC·라우팅·ELB·Route 53 변경 작업 |
| `rds.min_backup_retention_days` | `7` | RDS-004 | RDS 자동 백업 최소 보존 일수 (1 이상) |
| `backup.min_retention_days` | `7` | BKP-002 | AWS Backup 규칙 최소 보존 일수 (1 이상) |
| `backup.max_backup_age_days` | `7` | BKP-003 | 마지막 백업 뒤 허용하는 최대 경과 일수 (1 이상) |
| `elb.min_tls_version` | `TLSv1.2` | ELB-002 | 리스너 보안 정책이 허용해도 되는 최소 TLS 버전 (`TLSv1`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`) |
| `logs.min_retention_days` | `365` | LOG-001, CT-002 | 보안 로그 최소 보존 일수 (1 이상) |
| `logs.security_log_group_prefixes` | `["/aws/rds/"]` | LOG-001 | 보안 로그로 보는 로그 그룹 이름 접두사 (추적·흐름 로그 대상 그룹은 항상 포함) |
| `llm.model` | `claude-opus-5-5` | — | LLM 기능에 쓰는 모델 |
| `llm.effort` | `high` | — | 추론 깊이 (`low`, `medium`, `high`, `xhigh`, `max`) |
| `llm.max_tokens` | `16000` | — | 요청 하나의 최대 출력 토큰 (1024 이상) |
| `llm.timeout_s` | `300` | — | 요청 하나의 시간 제한(초). 연결 오류 등은 최대 2회 재시도 |

`iam.instance_actions`와 `iam.network_actions`의 기본 목록은 [kompass/config.py](../kompass/config.py)에 있다. 목록을 지정하면 기본 목록을 대신한다(추가가 아님).

### C. 점검 항목

KISA 클라우드 19개 항목과 담당 룰 요약은 [COVERAGE.md "요약"](COVERAGE.md#요약), 룰별 판정 기준은 [RULES.md](RULES.md).

### D. 실습 환경으로 사용해 보기

실제 고객 계정을 점검하기 전에, 의도적으로 취약하게 만든 실습 환경([lab/README.md](../lab/README.md))에서 결과를 확인해 볼 수 있다. 실습 환경은 Terraform으로 별도 AWS 계정에 직접 배포하며, 일부 리소스는 비용이 발생한다.

### E. 용어

| 용어 | 뜻 |
|---|---|
| 스냅샷 | 서비스별로 수집한 원본 설정 JSON. 판정의 입력이자 증적 |
| 점검 ID | 수집 한 번의 식별자. 결과 파일 이름에 쓴다 |
| finding | 룰이 리소스 하나에 내린 판정 결과 (상태, 메시지, 증적) |
| 증적 (evidence) | finding의 판정 근거가 된 원본 설정 값 |
| KISA 항목 | KISA 클라우드 취약점 점검 항목 CA-01~19 |
| `full` / `partial` | KISA 항목의 자동화 분류 ([6.2](#62-보고서-읽는-법)) |
| 건너뛴 룰 | 해당 서비스를 수집하지 않아 실행하지 않은 룰 |
| 자리표시자 | LLM에 보낼 때 식별정보 대신 쓰는 값 (예: `MASKED_SG_1`) |
| 증적 요청 | 자동 점검으로 확인할 수 없는 기준을 담당자에게 요청하는 항목 (예: `CA-02-1`) |
