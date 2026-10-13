# kompass-isms

KISA 클라우드 취약점 점검 가이드와 ISMS-P 인증기준으로 AWS 환경을 자동 진단하는 AI 에이전트.

> 🚧 개발 중 (0단계). 진행 상황은 [docs/PLAN.md](docs/PLAN.md) 참고.

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

## 사용법 (예정)

```bash
uv sync
uv run kompass scan --profile <aws-profile> --regions ap-northeast-2
uv run kompass report --format xlsx
```

## 점검 항목

[docs/RULES.md](docs/RULES.md) 참고.

## 주의

이 도구의 결과는 점검 보조 자료이며, ISMS-P 인증 심사 결과를 보장하지 않습니다. 매핑 정보는 원문 검증 여부(`verified`)를 함께 확인하세요.
