# CLAUDE.md

이 파일은 Claude Code가 kompass-isms 저장소에서 작업할 때 따르는 기준이다. 작업을 시작하기 전에 반드시 읽고, 세부 설계는 `docs/` 아래 문서를 참고한다.

## 프로젝트 한 줄 요약

AWS 계정을 **읽기 전용**으로 스캔해서 KISA 클라우드 취약점 점검 가이드와 ISMS-P 통제항목 기준으로 양호/취약을 판정하고, 근거·조치 방안·증적이 담긴 점검 보고서를 만드는 AI 에이전트.

## 먼저 읽을 문서

- `docs/PLAN.md` — 단계별 계획과 현재 진행 단계. **작업 전에 현재 단계를 확인하고, 끝난 항목은 체크한다.**
- `docs/ARCHITECTURE.md` — 계층 구조, 데이터 스키마, 인터페이스
- `docs/RULES.md` — 점검 룰 카탈로그 (룰 ID, 호출 API, 판정 로직, 매핑)
- `docs/DECISIONS.md` — 설계 결정 기록. 이 결정을 뒤집는 변경은 사용자에게 먼저 묻는다.

## 절대 원칙 (위반 금지)

1. **판정은 코드가 한다.** PASS/FAIL 판정은 `kompass/rules/`의 결정론적 로직만 내린다. LLM은 판정된 결과를 해석·우선순위화·설명·조치안 작성만 한다. LLM 출력으로 `status`를 바꾸는 코드를 만들지 않는다.
2. **AWS는 읽기 전용.** collector와 에이전트 도구는 `Describe*`, `Get*`, `List*`, `GenerateCredentialReport`만 호출한다. 예외는 역할 기반 점검 세션을 위한 `sts:AssumeRole`(ADR-020)과 에이전트 조사용 `cloudtrail:LookupEvents`·`iam:SimulatePrincipalPolicy`(ADR-036)뿐이다. 그 외 API는 `kompass/aws/guard.py`의 읽기 전용 가드가 차단해야 하며, 가드를 우회하거나 끄는 코드를 만들지 않는다. 허용 목록을 늘리는 변경은 사용자 확인 후 ADR로 기록한다.
3. **권한 오류는 PASS가 아니다.** 수집 실패나 AccessDenied는 `ERROR` 상태로 기록한다. 데이터가 없다고 양호로 처리하지 않는다.
4. **실제 계정 데이터는 커밋하지 않는다.** 스냅샷, findings, 보고서 출력물(`reports/`, 이전 위치 `.kompass/`, `output/`)은 `.gitignore` 대상이다. 테스트 픽스처는 moto 또는 가공된 가짜 데이터만 쓴다.
5. **LLM에 원본 식별정보를 보내지 않는다.** 계정 ID, IP, ARN, 리소스명은 `interpreter/masking.py`를 거친 뒤에만 LLM으로 전달한다.
6. **Terraform 실행 금지.** `lab/`의 Terraform은 사용자가 직접 실행한다. Claude Code는 코드 작성·수정만 하고 `terraform apply/destroy`를 실행하지 않는다.
7. **매핑은 추측하지 않는다.** KISA 항목코드와 ISMS-P 매핑은 원문 근거가 있을 때만 확정한다. 근거가 불확실하면 `verified: false`로 두고 사용자에게 알린다.

## 기술 스택

- Python 3.12, 패키지 관리 `uv`
- boto3, pydantic v2, typer, PyYAML
- 테스트: pytest, moto
- 린트/포맷/타입: ruff, mypy (strict)
- LLM: anthropic (Claude API, 공급자 인터페이스 뒤. 로컬 LLM은 자리만 둠), MCP: mcp
- 보고서·문서: openpyxl (Excel), pypdf (원문 색인, 증적 문서 추출)

## 자주 쓰는 명령

```bash
uv sync                          # 의존성 설치
uv run pytest                    # 전체 테스트
uv run pytest tests/rules -k S3  # 일부 테스트
uv run pytest -m lab             # 실습 계정 통합 테스트 (실제 AWS, 읽기 전용, 기본 실행에서 제외)
uv run pytest -m llm             # 실제 Claude API 확인 (비용 발생, ANTHROPIC_API_KEY 필요, 기본 실행에서 제외)
uv run ruff check . && uv run ruff format .
uv run mypy kompass
uv run kompass scan --profile kompass-lab-audit --regions ap-northeast-2
```

## 코드 규칙

- 식별자·파일명은 영어, docstring·주석·문서는 한국어.
- 보고서에 들어가는 문장(finding 메시지, 리포터 문구, 해설 검증 문제, LLM 해설)은 개조식 명사형으로 끝맺는다: `설정되지 않음`, `확인해야 함`, `초안임`, `검토 필요`. `~다`, `~습니다`로 끝내지 않는다. 단, KISA·ISMS-P 원문 인용은 원문 그대로 둔다.
- 문서(README, `docs/`, `lab/`·`evals/`·`knowledge/`의 README·안내 문서)와 docstring·주석은 평서체(`~다`)로 쓴다. 정중체(`~습니다`, `~하세요`)를 섞지 않는다. 표 칸·목록 항목은 명사형으로 끝내도 된다. 담당자에게 그대로 전달하는 양식(`docs/ISMS_P_MAPPING_REVIEW.md`)은 보고서 규칙(개조식)을 따르고, 문서에 인용한 CLI 메시지는 원래 문구 그대로 둔다.
- CLI 출력·도움말과 사용자에게 보이는 오류 메시지(예외 메시지, 스크립트 오류)는 정중체로 끝맺는다: `해설할 것이 없습니다.`, `해설을 요청하시겠습니까?`, `--account-id로 계정을 지정해 주십시오`. "이름: 값" 형식은 그대로 둔다. 보고서에도 기록되는 메시지(LLM 호출 실패·거부, 마스킹 차단, 해설 검증 문제)는 보고서 규칙(개조식)을 따른다.
- 룰 하나 = 파일 하나 (`kompass/rules/s3/s3_001_account_public_access_block.py`). 룰 ID는 `docs/RULES.md`와 일치해야 한다.
- 새 룰을 추가할 때는 **테스트를 먼저** 작성한다. 최소한 PASS 케이스, FAIL 케이스, ERROR(권한 없음) 케이스 3개.
- 모든 모델은 pydantic으로 정의하고 `kompass/models.py`에 모은다.
- 외부 호출(AWS, LLM)은 인터페이스 뒤에 두고, 테스트에서 교체 가능하게 만든다.
- 커밋 메시지는 Conventional Commits (`feat(rules): add S3-001 ...`).

## 작업 방식

- 한 번에 하나의 작은 단위(룰 하나, collector 하나)만 구현하고, 테스트·린트·타입체크를 통과시킨 뒤 다음으로 넘어간다.
- 작업을 마치면 `docs/PLAN.md` 체크박스를 갱신하고, 설계에 영향이 있는 결정을 했다면 `docs/DECISIONS.md`에 기록한다.
- 계획에 없는 큰 변경(새 의존성, 디렉터리 구조 변경, 스키마 변경)은 구현 전에 사용자에게 제안하고 확인받는다.
