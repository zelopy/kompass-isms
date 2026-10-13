# kompass-isms

KISA 클라우드 취약점 점검 가이드와 ISMS-P 인증기준으로 AWS 환경을 자동 진단하는 AI 에이전트.

> 🚧 개발 중 (1단계 완료: 수집과 판정). 진행 상황은 [docs/PLAN.md](docs/PLAN.md) 참고.

## 무엇을 하나

- AWS 계정을 **읽기 전용**으로 스캔해서 IAM, S3, EC2(보안그룹·VPC), CloudTrail 설정을 수집합니다.
- 결정론적 룰로 양호/취약을 판정하고, 판정 근거가 된 원본 설정을 증적으로 남깁니다.
- 결과를 KISA 점검 항목과 ISMS-P 통제항목에 매핑해 점검표(Markdown, Excel)로 출력합니다.
- (예정) LLM과 RAG로 항목 근거를 인용한 해설, 위험 우선순위, 조치 방안을 생성합니다.
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

# 수집 + 판정
uv run kompass scan --profile <aws-profile> --regions ap-northeast-2

# 따로 실행
uv run kompass collect --profile <aws-profile> --account-id <예상 계정 ID>
uv run kompass evaluate --config kompass.yaml --fail-on fail
```

| 옵션 | 설명 |
|---|---|
| `--regions` | EC2·VPC를 점검할 리전 (쉼표 구분). 없으면 활성 리전 전체. S3 버킷·IAM은 항상 전체 |
| `--account-id` | 실제 계정이 다르면 중단 (엉뚱한 프로필로 점검하는 실수 방지) |
| `--service` | 수집할 서비스 (`cloudtrail`, `ec2`, `iam`, `s3`). 없으면 전체 |
| `--config` | 판정 기준값 파일. 없으면 현재 디렉터리의 `kompass.yaml` |
| `--fail-on` | `fail`·`error`·`review` 이상의 결과가 있으면 종료 코드 1 (CI용) |

결과는 `.kompass/` 아래에 저장된다. 실제 계정 데이터이므로 `.kompass/.gitignore`가 자동으로 만들어진다.
- 스냅샷: `.kompass/snapshots/<계정>/<점검 ID>/` (파일별 SHA-256 기록)
- 판정 결과: `.kompass/findings/<계정>/<점검 ID>.findings.json`

종료 코드: 0 완료(취약 결과가 있어도 0), 1 `--fail-on` 해당, 2 사용법·설정 오류, 3 세션 오류, 4 스냅샷 오류.

보고서(Markdown, Excel)와 KISA·ISMS-P 항목 매핑은 2단계에서 추가한다.

## 점검 항목

[docs/RULES.md](docs/RULES.md) 참고.

## 주의

이 도구의 결과는 점검 보조 자료이며, ISMS-P 인증 심사 결과를 보장하지 않습니다. 매핑 정보는 원문 검증 여부(`verified`)를 함께 확인하세요.
