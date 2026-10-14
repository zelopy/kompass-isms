# kompass-isms

KISA 클라우드 취약점 점검 가이드와 ISMS-P 인증기준으로 AWS 환경을 자동 진단하는 AI 에이전트.

> 🚧 개발 중 (2단계: 매핑과 보고서). 진행 상황은 [docs/PLAN.md](docs/PLAN.md) 참고.

## 무엇을 하나

- AWS 계정을 **읽기 전용**으로 스캔해서 IAM, S3, EC2(보안그룹·VPC), CloudTrail 설정을 수집합니다.
- 결정론적 룰로 양호/취약을 판정하고, 판정 근거가 된 원본 설정을 증적으로 남깁니다.
- 결과를 KISA 점검 항목과 ISMS-P 통제항목에 매핑해 점검표(Markdown, Excel)로 출력합니다.
- LLM(Claude)이 조치가 필요한 결과를 룰별로 해설합니다: KISA·ISMS-P 원문 인용(원문 대조 검증), 위험, 우선순위 의견, 조치 방안(AWS CLI·Terraform). 식별정보는 가린 뒤 보냅니다.
- (예정) 에이전트가 1차 결과를 바탕으로 추가 조사를 스스로 수행합니다.

## 설계 원칙

- **판정은 코드, 해석은 LLM.** 양호/취약 판정은 재현 가능한 룰이 내리고, LLM은 판정을 바꾸지 않습니다.
- **읽기 전용 이중 보장.** IAM 정책(`SecurityAudit`)과 코드 레벨 가드로 대상 환경 변경을 막습니다.
- **확인하지 못한 것은 양호가 아니다.** 권한 오류나 수집 실패는 `ERROR`로 보고합니다.

자세한 내용은 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DECISIONS.md](docs/DECISIONS.md)를 참고하세요.

## 사용법

점검용 AWS 프로필에는 `SecurityAudit` 관리형 정책만 부여한다. 코드에도 읽기 전용 가드가 있어 조회 외의 호출은 요청 전에 차단된다.

```bash
uv sync

# 수집 + 판정 + 보고서
uv run kompass scan --profile <aws-profile> --regions ap-northeast-2 --report md --report xlsx

# 따로 실행
uv run kompass collect --profile <aws-profile> --account-id <예상 계정 ID>
uv run kompass evaluate --config kompass.yaml --fail-on fail
uv run kompass report --format md --format xlsx

# LLM 해설 (선택, 비용 발생. ANTHROPIC_API_KEY 필요, 원문 색인을 먼저 만든다: knowledge/SOURCES.md)
uv run kompass explain --dry-run          # 대상과 예상 비용만 확인
uv run kompass explain --report md --report xlsx
```

| 옵션 | 설명 |
|---|---|
| `--regions` | EC2·VPC를 점검할 리전 (쉼표 구분). 없으면 활성 리전 전체. S3 버킷·IAM은 항상 전체 |
| `--account-id` | 실제 계정이 다르면 중단 (엉뚱한 프로필로 점검하는 실수 방지) |
| `--service` | 수집할 서비스 (`cloudtrail`, `ec2`, `iam`, `s3`). 없으면 전체 |
| `--config` | 판정 기준값 파일. 없으면 현재 디렉터리의 `kompass.yaml` |
| `--fail-on` | `fail`·`error`·`review` 이상의 결과가 있으면 종료 코드 1 (CI용) |
| `--report` / `--format` | 보고서 형식: `md`(Markdown), `xlsx`(Excel 점검표), `json`(전체 데이터) |

결과는 어느 폴더에서 실행하든 저장소 최상위의 `reports/` 아래에 저장된다. 다른 위치를 쓰려면 `--store` 옵션이나 `KOMPASS_STORE` 환경 변수를 지정한다. 실제 계정 데이터이므로 `reports/`는 `.gitignore` 대상이며, 폴더 안에도 `.gitignore`가 자동으로 만들어진다.
- 보고서: `reports/<계정>/<점검 ID>.md`, `.xlsx`, `.report.json`
- 판정 결과: `reports/findings/<계정>/<점검 ID>.findings.json`
- 해설: `reports/explanations/<계정>/<점검 ID>.explanations.json` (원본 식별정보가 복원된 상태)
- 스냅샷: `reports/snapshots/<계정>/<점검 ID>/` (파일별 SHA-256 기록)

종료 코드: 0 완료(취약 결과가 있어도 0), 1 `--fail-on` 해당, 2 사용법·설정 오류, 3 세션 오류, 4 스냅샷 오류, 5 LLM 해설 전부 실패.

보고서는 판정 결과에 KISA·ISMS-P 매핑을 붙여 만든다. 매핑을 고쳐도 다시 판정할 필요 없이 `kompass report`만 다시 실행하면 된다. 보고서를 만들 때 스냅샷 해시를 다시 대조하므로, 판정 후 증적이 바뀌었으면 보고서를 만들지 않는다.

`kompass explain`은 판정을 바꾸지 않는 참고 해설이다. LLM에는 계정 ID·IP·ARN·리소스 이름을 자리표시자로 바꾼 값만 보내고, 응답을 받은 뒤 로컬에서 되돌린다. 인용 구절은 원문 색인과 대조해 "검증됨"/"검증되지 않음"을 표시한다. 해설은 같은 판정 결과에만 붙으며, 다시 판정하면 해설을 다시 만들어야 보고서에 들어간다. 모델·effort는 `kompass.yaml`의 `llm:` 섹션에서 바꾼다.

## 출력 예시

[실습 환경](lab/README.md)을 점검한 Markdown 보고서의 일부다. 결과는 KISA 항목 단위로 집계한다. `partial` 항목은 API로 확인할 수 없는 조건(주기적 검토 등)이 있어 자동 점검만으로는 "양호"가 되지 않는다.

| 코드 | 항목 | 중요도 | 분류 | 결과 | 룰 | finding |
|---|---|---|---|---|---|---|
| CA-01 | 사용자 계정 관리 | 상 | partial | 검토 필요 | IAM-005 | PASS 3 |
| CA-03 | MFA(Multi-Factor Authentication) 설정 | 상 | full | 취약 | IAM-001, IAM-003, IAM-009 | FAIL 1, PASS 1, REVIEW 1 |
| CA-05 | 인스턴스 서비스 정책 관리 | 상 | partial | 수동 점검 (미구현) | - | - |
| CA-09 | 접근 제어 설정 관리 | 상 | partial | 취약 | SG-001, SG-002, SG-003 | FAIL 5, PASS 19 |
| CA-13 | 클라우드 서비스 사용자 계정 로깅 설정 | 상 | full | 양호 | CT-001 | PASS 1 |

보고서 구성:
- **Markdown**: 점검 정보(수행 주체, 시각, 적용 기준값, 매핑 데이터 해시), KISA 19개 항목 결과, 조치가 필요한 결과(항목별 핵심 증적), ISMS-P 통제항목(초안), 건너뛴 룰
- **Excel 점검표**: 요약 / KISA 항목 / 점검 결과(finding 전체, 증적) / ISMS-P (초안) 시트. 결과별 색상과 필터
- **JSON**: 매핑을 붙인 finding과 전체 증적

## 점검 항목

[docs/RULES.md](docs/RULES.md) 참고.

## 주의

이 도구의 결과는 점검 보조 자료이며, ISMS-P 인증 심사 결과를 보장하지 않습니다. 매핑 정보는 원문 검증 여부(`verified`)를 함께 확인하세요.
