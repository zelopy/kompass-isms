# kompass-isms

KISA 클라우드 취약점 점검 가이드와 ISMS-P 인증기준으로 AWS 환경을 자동 진단하는 AI 에이전트.

> 🚧 개발 중 (5단계: 확장). 진행 상황은 [docs/PLAN.md](docs/PLAN.md) 참고.

## 무엇을 하나

- AWS 계정을 **읽기 전용**으로 스캔해서 IAM, S3, EC2(보안그룹·VPC), CloudTrail, CloudWatch Logs, RDS, ELB, GuardDuty, AWS Backup 설정을 수집한다.
- 결정론적 룰로 양호/취약을 판정하고, 판정 근거가 된 원본 설정을 증적으로 남긴다.
- 결과를 KISA 점검 항목과 ISMS-P 통제항목에 매핑해 점검표(Markdown, Excel)로 출력한다.
- LLM(Claude)이 조치가 필요한 결과를 룰별로 해설한다: KISA·ISMS-P 원문 인용(원문 대조 검증), 위험, 우선순위 의견, 조치 방안(AWS CLI·Terraform). 식별정보는 가린 뒤 보낸다. 룰을 엮은 종합 위험 평가(위험 시나리오, 조치 순서)도 만든다.
- 에이전트가 취약·검토 필요 결과를 읽기 전용 도구로 추가 조사한다. 같은 도구를 MCP 서버로도 제공한다.
- 자동 점검으로 확인할 수 없는 항목은 담당자 증적 요청서를 만들고, 제출된 증적 문서를 LLM이 검토한다.

## 설계 원칙

- **판정은 코드, 해석은 LLM.** 양호/취약 판정은 재현 가능한 룰이 내리고, LLM은 판정을 바꾸지 않는다.
- **읽기 전용 이중 보장.** IAM 정책(`SecurityAudit`)과 코드 레벨 가드로 대상 환경 변경을 막는다.
- **확인하지 못한 것은 양호가 아니다.** 권한 오류나 수집 실패는 `ERROR`로 보고한다.

## 빠른 시작

점검용 AWS 프로필에는 `SecurityAudit` 관리형 정책만 부여한다.

```bash
uv sync
uv run kompass scan --profile <점검 프로필> --account-id <대상 계정 ID> --report md --report xlsx
```

보고서는 `reports/<계정 ID>/`에 생긴다. 설치, 자격증명, 명령별 사용법, 결과물 구조, 문제 해결은 **[사용 매뉴얼](docs/MANUAL.md)**에 있다.

## 출력 예시

[실습 환경](lab/README.md)을 점검한 Markdown 보고서의 일부다. 결과는 KISA 항목 단위로 집계한다. `partial` 항목은 API로 확인할 수 없는 조건(주기적 검토 등)이 있어 자동 점검만으로는 "양호"가 되지 않는다.

| 코드 | 항목 | 중요도 | 분류 | 결과 | 룰 | finding |
|---|---|---|---|---|---|---|
| CA-01 | 사용자 계정 관리 | 상 | partial | 검토 필요 | IAM-005 | PASS 3 |
| CA-03 | MFA(Multi-Factor Authentication) 설정 | 상 | full | 취약 | IAM-001, IAM-003, IAM-009 | FAIL 1, PASS 1, REVIEW 1 |
| CA-05 | 인스턴스 서비스 정책 관리 | 상 | partial | 검토 필요 | IAM-010 | REVIEW 5 |
| CA-09 | 접근 제어 설정 관리 | 상 | partial | 취약 | SG-001, SG-002, SG-003 | FAIL 5, PASS 19 |
| CA-13 | 클라우드 서비스 사용자 계정 로깅 설정 | 상 | full | 양호 | CT-001 | PASS 1 |

보고서 구성은 [매뉴얼 6.2](docs/MANUAL.md#62-보고서-읽는-법)에 있다.

## 문서

| 문서 | 내용 |
|---|---|
| [docs/MANUAL.md](docs/MANUAL.md) | 사용 매뉴얼 |
| [docs/RULES.md](docs/RULES.md) | 점검 룰 41개의 판정 기준과 KISA·ISMS-P 매핑 |
| [docs/COVERAGE.md](docs/COVERAGE.md) | KISA 19개 항목별 자동화 범위 |
| [docs/ISMS_P_MAPPING_REVIEW.md](docs/ISMS_P_MAPPING_REVIEW.md) | ISMS-P 매핑 근거와 협의용 검토표 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 내부 구조 |
| [docs/DECISIONS.md](docs/DECISIONS.md) | 설계 결정 기록 |
| [docs/PLAN.md](docs/PLAN.md) | 진행 상황 |
| [lab/README.md](lab/README.md) | 취약 실습 환경 |
| [evals/README.md](evals/README.md) | LLM 평가셋 |

## 개발

개발 규칙은 [CLAUDE.md](CLAUDE.md)에 있다.

```bash
uv run pytest                                  # 테스트
uv run pytest -m lab                           # 실습 계정 통합 테스트 (실제 AWS, 읽기 전용)
uv run ruff check . && uv run ruff format .    # 린트·포맷
uv run mypy kompass                            # 타입 검사
```

평가셋 실행 방법은 [evals/README.md](evals/README.md)에 있다.

## 주의

이 도구의 결과는 점검 보조 자료이며, ISMS-P 인증 심사 결과를 보장하지 않는다. ISMS-P 매핑은 담당자 협의 전의 초안이므로 원문 검증 여부(`verified`)를 함께 확인한다.
