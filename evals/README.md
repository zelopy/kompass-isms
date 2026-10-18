# 평가셋

LLM 출력의 품질을 측정하는 평가셋이다. 지금은 두 흐름을 측정한다.

- **해설**: `kompass explain`의 룰별 해설
- **증적 검토**: `kompass review-evidence`의 요청별 검토

채점은 코드로만 한다. LLM 판정자는 쓰지 않는다. 그래서 같은 응답이면 언제 채점해도 결과가 같고, 기록된 응답으로 비용 없이 다시 채점할 수 있다. 두 평가셋 모두 지표가 거의 만점에 가까워(아래 [실행 기록](#실행-기록)) 품질 개선 측정보다 **회귀 검출용**으로 쓴다. 프롬프트·모델·마스킹·룰을 바꿨을 때 점수가 떨어지는지 확인한다.

설계 이유는 [ADR-033](../docs/DECISIONS.md#adr-033-해설-평가셋-설계)(해설)과 [ADR-049](../docs/DECISIONS.md#adr-049-제출된-증적-문서-검토-범위)(증적 검토)에 있다.

## 구성

| | 해설 | 증적 검토 |
|---|---|---|
| 케이스 | [explain/cases/](explain/cases/) `<id>.json` (목록: [explain/cases.md](explain/cases.md)) | [evidence/cases/](evidence/cases/) `<id>.yaml` |
| 정답 | [explain/golden.yaml](explain/golden.yaml) | 케이스 파일 안 (`expected_gaps`, `max_gaps`, `sensitive`) |
| 채점기 | [kompass/evals/grader.py](../kompass/evals/grader.py) | [kompass/evals/evidence.py](../kompass/evals/evidence.py) |
| 실행기 | [scripts/run_explain_eval.py](../scripts/run_explain_eval.py) | [scripts/run_evidence_eval.py](../scripts/run_evidence_eval.py) |
| 케이스 생성 | [scripts/make_eval_cases.py](../scripts/make_eval_cases.py) | 직접 작성 |
| 결과 | `.claude/hillclimb/explain/<variant>/` | `.claude/hillclimb/evidence/<variant>/` |
| 테스트 | [tests/evals/](../tests/evals/) | [tests/evals/test_evidence_eval.py](../tests/evals/test_evidence_eval.py) |

케이스는 모두 가공한 가짜 데이터다 (CLAUDE.md 원칙 4).

## 해설 평가셋

### 케이스

케이스 하나는 룰 하나의 finding 묶음이다. 실제 해설도 룰 단위로 요청하므로 LLM 호출 하나와 같다. 해설 대상은 FAIL·ERROR·REVIEW finding이며, 같은 룰의 PASS·N/A finding도 함께 담는다.

| 종류 | ID | 만드는 방법 |
|---|---|---|
| 실습 가공 | `lab-<룰>` | `reports/`의 최근 실습 판정 결과에서 조치가 필요한 룰을 골라 식별자를 무작위 가짜 값으로 바꾼다. 원본 값이 하나라도 남으면 만들지 않고 멈춘다 |
| 보강 | `syn-<룰>-<상황>` | `make_eval_cases.py`의 가짜 스냅샷에 실제 룰 코드를 돌려 finding을 얻는다. 실습에서 나오지 않는 상황(ERROR, REVIEW, 상태 혼합, 많은 finding, 까다로운 식별자)을 채운다 |

케이스 수와 목록은 생성기가 만드는 [explain/cases.md](explain/cases.md)를 본다. `cases.md`는 직접 고치지 않는다.

### 정답

[golden.yaml](explain/golden.yaml)에는 룰·상태별로 finding을 해소하거나 확인하는 API 작업(`서비스:작업`)과 예시 명령을 둔다. ERROR finding은 룰과 관계없이 점검 권한 부여(`error_actions`)나 거부된 조회의 재실행이면 정답이다. 인용 정답은 두지 않는다. 채점기가 매핑된 KISA 항목의 판단 기준·조치 방법·점검 및 조치 사례 구간(매핑이 없으면 ISMS-P 통제 본문)을 원문 색인에서 꺼내 대조한다.

테스트가 모든 룰에 정답이 있는지, 작업 이름이 botocore에 있는지, 예시 명령이 채점기에서 유효한지 검사한다.

### 지표

| 지표 | 결과 표기 | 뜻 |
|---|---|---|
| `verified` | 검증 통과 | 최종 해설이 인용 검증을 통과 (헤드라인) |
| `first_try` | 첫 응답 통과 | 재시도 없이 첫 응답이 통과 |
| `cite_precision` | 인용 정밀도 | 첫 응답의 인용 중 매핑된 코드이고 원문에 있으며 형식 문구가 아닌 비율 |
| `core_basis` | 핵심 근거 | 핵심 근거 구간을 인용 |
| `cli_valid` | CLI 유효 | AWS CLI 명령 중 botocore 모델에 서비스·작업·옵션이 모두 있는 비율 |
| `action_cover` | 조치 작업 | 해설 대상 상태마다 정답 작업이 명령에 하나라도 있는 비율 |
| `target_match` | 대상 일치 | 변경 명령 중 케이스의 대상 리소스를 가리키는 비율 (변경 명령이 없으면 제외) |
| `leak_free` | 노출 없음 | LLM에 보낸 프롬프트에 원본 식별정보가 없음 |
| `no_invented` | 지어냄 없음 | 복원 뒤 남은(지어낸) 자리표시자가 없음 |
| `style_ok` | 문체 준수 | 보고서 문장이 개조식 명사형으로 끝남 |

Terraform 수정안은 실행하지 않으므로 채점하지 않는다. 종합 위험 평가(ADR-034)는 실행기에서 끄며 아직 평가하지 않는다.

## 증적 검토 평가셋

### 케이스

케이스 하나는 증적 요청 하나에 제출된 가짜 문서 묶음이다. 실행기는 케이스 문서를 임시 증적 폴더에 쓰고 실제 흐름(문서 읽기 → 마스킹 → 검토)을 그대로 거친다.

| 필드 | 뜻 |
|---|---|
| `files` | 요청 ID 폴더 아래 경로와 문서 내용 |
| `terms` | 마스킹 사전 (이름 등) |
| `sensitive` | 프롬프트에 나오면 안 되는 값 (이름·연락처·주민등록번호·리소스 ID·IP 등) |
| `expected_gaps` | 검토가 지적해야 할 부족한 점 (키워드 묶음) |
| `max_gaps` | 부족한 점 수 상한 (충분한 문서에 과한 지적을 하지 않는지) |

8개 케이스가 다루는 상황: 재직 대조표 개인정보, 스캔 승인서(텍스트 추출 불가), 확인 대상 finding, 관계없는 문서, 프롬프트 주입, 주민등록번호·DB 이름, 충분한 문서, 복구 절차 누락.

### 지표

| 지표 | 뜻 |
|---|---|
| `verified` | 모든 검토가 발췌 대조 검증을 통과 (헤드라인) |
| `first_try` | 모든 검토가 첫 응답에 통과 |
| `leak_free` | 프롬프트에 `sensitive` 값이 없음 |
| `no_invented` | 복원한 결과에 지어낸 자리표시자가 없음 |
| `style_ok` | 개조식 명사형 문체 |
| `no_verdict` | 양호·취약·충족 같은 판정어를 쓰지 않음 (원칙 1. 발췌는 문서 원문이라 제외) |
| `expected_gaps` | `expected_gaps` 중 부족한 점·추가 요청에서 찾은 비율 |
| `gap_budget` | 부족한 점 수가 `max_gaps` 이하 |
| `no_field_names` | 입력 필드 이름(`targets` 등)을 문장에 쓰지 않음 |

## 실행

### 준비

- 원문 색인 `knowledge/index.json`이 있어야 한다 ([knowledge/SOURCES.md](../knowledge/SOURCES.md)). 없으면 오라클·널 테스트가 건너뛰어진다.
- 실제 모델 실행과 `--dry-run`에는 `ANTHROPIC_API_KEY`가 필요하다. 모델·effort·시간 제한은 `kompass.yaml`의 `llm:`을 따른다 (`--config`로 다른 파일 지정).

### 순서

비용이 드는 실행 전에 무료 단계를 먼저 통과시킨다. 증적 검토도 같은 순서이며 스크립트만 `run_evidence_eval.py`로 바꾼다.

```bash
# 1. 채점기 점검 (무료): 오라클(정답) ≈ 100%, 널(오답) ≈ 0%
uv run pytest tests/evals

# 2. 배선 점검 (무료): 오라클 공급자로 실제 실행 흐름과 결과 파일 확인
uv run python scripts/run_explain_eval.py --provider oracle --variant <이름>-oracle --reps 1

# 3. 예상 비용 확인
uv run python scripts/run_explain_eval.py --dry-run

# 4. 파일럿 (비용 발생): 일부 케이스로 채점 결과를 먼저 확인
uv run python scripts/run_explain_eval.py --variant <이름> --cases <id>,<id> --reps 1

# 5. 실행 (비용 발생). 기본 반복 2회
uv run python scripts/run_explain_eval.py --variant <이름> --cases <id>,...

# 6. 채점기를 고친 뒤 기록된 응답으로 다시 채점 (무료, API 호출 없음)
uv run python scripts/run_explain_eval.py --variant <이름> --regrade
```

| 옵션 | 뜻 |
|---|---|
| `--variant` | 결과 폴더 이름. 해설 기본값 `baseline` |
| `--cases` | 쉼표로 구분한 케이스 ID. 없으면 전체 |
| `--reps` | 케이스당 반복 수 |
| `--provider` | `claude`(기본), `oracle`, `null` |
| `--concurrency`, `--timeout-s` | 해설만. 동시 실행 수, 요청 하나의 시간 제한 |
| `--dry-run` | 요청하지 않고 입력 토큰과 예상 비용만 계산 |
| `--regrade` | 기록된 응답을 재생해 다시 채점 |

다시 실행할 때 동작이 다르다.
- 해설: 이미 채점한 (케이스, 반복)은 건너뛴다. 실패한 시도만 다시 돈다. 처음부터 다시 하려면 variant 폴더를 지운다.
- 증적 검토: 그 variant의 결과를 덮어쓴다.

### 결과 폴더

| 파일 | 내용 | 커밋 |
|---|---|---|
| `metrics.md` | 지표 요약, 비용, 만점이 아닌 시도 | 함 |
| `results.jsonl` | (케이스, 반복)마다 지표 한 줄 | 함 |
| `errors.jsonl` | 해설만, 실패가 있을 때만 생김. 채점할 수 없는 실패(거부, API 오류, 마스킹 차단, 시간 초과)이며 0점이 아니라 따로 센다 | 함 |
| `traces/` | 마스킹된 프롬프트와 응답 원문. `--regrade`가 이것을 재생한다 | 안 함 |

`explain/_state.json`은 지표 정의와 실행기 파일 해시(`harness_sha`)를 기록한다. 실행기·채점기·케이스가 바뀌면 해시가 달라져 이전 결과와 직접 비교할 수 없음을 알 수 있다.

## 새 룰의 케이스 추가

룰을 추가할 때마다 해설 케이스를 함께 더한다.

1. [golden.yaml](explain/golden.yaml)에 룰의 `fail`·`review` 작업과 `example`을 더한다. 빠뜨리면 `test_golden_covers_every_rule`이 실패한다.
2. 보강 케이스를 [make_eval_cases.py](../scripts/make_eval_cases.py)의 보강 목록에 더하고 생성한다. 기존 보강 케이스는 기준선 비교를 위해 다시 만들지 않는다 (`--rewrite-synthetic`을 줄 때만 다시 만든다).
   ```bash
   uv run python scripts/make_eval_cases.py --no-lab
   ```
3. 실습 계정에서 그 룰의 결과를 판정한 뒤 실습 가공 케이스를 만든다. 다른 실습 케이스는 그대로 둔다.
   ```bash
   uv run python scripts/make_eval_cases.py --lab-rules <룰>,<룰>
   ```
4. `uv run pytest tests/evals`와 오라클 실행(`--variant <이름>-oracle --cases <새 케이스>`)으로 정답·채점기가 새 케이스를 만점 처리하는지 확인한다. 만점이 아니면 증적·마스킹·채점기 중 어디가 문제인지 먼저 고친다.
5. 새 케이스만 실제 모델로 실행한다 (`--variant <이름> --cases <새 케이스>`).
6. 채점기 오판을 고쳤으면 기존 variant를 `--regrade`해 점수가 그대로인지 확인한다.
7. 아래 실행 기록에 한 줄을 더한다.

## 실행 기록

모델은 모두 `claude-opus-5-5`, effort `high`다. "케이스 × 반복"은 실행한 시도 수이며, 오라클 실행은 비용이 없다. 비용은 `metrics.md`의 값으로, 결과에 남은 시도만 센다. 케이스를 고쳐 다시 돌린 시도는 빠지므로 실제 지출은 이보다 클 수 있다 (예: `baseline`은 보강 케이스 2개를 다시 돌려 약 $5.2).

### 해설

기준선(`baseline`) 뒤의 실행은 새로 더한 케이스만 돌린 것이다. 지금 있는 77개 케이스는 모두 실제 모델로 한 번 이상 실행했다.

| 날짜 | variant | 대상 | 케이스 × 반복 | 비용 | 결과 |
|---|---|---|---|---|---|
| 2026-10-14 | [baseline](../.claude/hillclimb/explain/baseline/metrics.md) | 1~4단계 룰 (실습 가공 16, 보강 24) | 40 × 2 | $4.98 | 조치 작업 99.4%(조회 권한이 없던 리전의 조치 누락 1건), 나머지 100% |
| 2026-10-16 | [stage5-oracle](../.claude/hillclimb/explain/stage5-oracle/metrics.md) | 5단계 룰 | 20 × 1 | — | 100% |
| 2026-10-16 | [stage5](../.claude/hillclimb/explain/stage5/metrics.md) | 5단계 룰 (실습 가공 10, 보강 10) | 20 × 2 | $2.55 | 100% (채점기 오판 2종 수정 후) |
| 2026-10-17 | [rds005-oracle](../.claude/hillclimb/explain/rds005-oracle/metrics.md) | RDS-005 보강 | 2 × 1 | — | 100% |
| 2026-10-17 | [rds005](../.claude/hillclimb/explain/rds005/metrics.md) | RDS-005 보강 | 2 × 2 | $0.33 | 대상 일치 91.7%, 나머지 100% (채점기 오판 2종 수정 후) |
| 2026-10-17 | [elb-oracle](../.claude/hillclimb/explain/elb-oracle/metrics.md) | 당시 전체 | 68 × 1 | — | 100% (ELB ARN 마스킹 수정 후) |
| 2026-10-17 | [elb-rds005](../.claude/hillclimb/explain/elb-rds005/metrics.md) | `lab-rds-005`, `lab-elb-001~002`, ELB 보강 3 | 6 × 2 | $0.82 | 100% (채점기 오판 2종 수정 후) |
| 2026-10-17 | [rds006-oracle](../.claude/hillclimb/explain/rds006-oracle/metrics.md) | RDS-006 | 3 × 1 | — | 100% |
| 2026-10-18 | [rds006](../.claude/hillclimb/explain/rds006/metrics.md) | RDS-006 (실습 가공 1, 보강 2) | 3 × 2 | $0.40 | 100% (채점기 오판 1종 수정 후) |
| 2026-10-18 | [bkp-oracle](../.claude/hillclimb/explain/bkp-oracle/metrics.md) | BKP-001~003 | 6 × 1 | — | 100% (BKP-002 증적에 계획 ID 추가 후) |
| 2026-10-18 | [bkp](../.claude/hillclimb/explain/bkp/metrics.md) | BKP-001~003 (실습 가공 1, 보강 5) | 6 × 2 | $0.80 | 100% |

`rds005`의 남은 1건은 기본 파라미터 그룹(`default.mysql8.0`)을 직접 수정하는 명령이다. 그룹 이름이 마스킹되어 모델이 기본 그룹인지 알 수 없었다. AWS 고정 이름의 마스킹 제외는 따로 검토할 과제다.

평가셋이 찾은 결함(채점기 오판 외)은 다음과 같다. 자세한 내용은 ADR-033에 있다.
- 자리표시자 번호 10 이상을 "일부만 가려짐"으로 오판해 요청을 모두 막던 마스킹 버그
- ELB ARN의 로드 밸런서 종류 구간(`app`·`net`·`gwy`)을 이름으로 가리던 마스킹
- BKP-002 증적에 조치 명령이 받는 계획 ID가 없던 문제

### 증적 검토

| 날짜 | variant | 케이스 × 반복 | 비용 | 결과 |
|---|---|---|---|---|
| 2026-10-17 | [baseline](../.claude/hillclimb/evidence/baseline/metrics.md) | 8 × 2 | $0.72 | 실행 당시 지표 모두 100% (판정어 채점기 오판 수정 후). v1에서 더한 지표로 다시 채점하면 `gap_budget` 87.5%, `no_field_names` 68.8% |
| 2026-10-17 | [v1-prompt](../.claude/hillclimb/evidence/v1-prompt/metrics.md) | 8 × 1 | $0.34 | 100%. 현재 기준선 |

v1 프롬프트는 기준선에서 관찰한 세 가지를 고쳤다. 충분한 문서에도 부족한 점을 많이 적는 경향(충분한 문서의 지적 6개 → 0개), 입력 필드 이름 노출, 자리표시자 바로 뒤의 조사다.

## 알려진 제약

- `traces/`는 커밋하지 않으므로 `--regrade`는 그 실행을 한 PC에서만 된다.
- `stage5`는 `--regrade`가 "기록된 응답보다 많은 요청"으로 실패한다. 실행한 뒤 해설 흐름이 바뀌었기 때문이다.
- 실습 가공 케이스를 다시 만들려면 실습 계정의 판정 결과가 `reports/`에 있어야 한다. 실습 리소스를 지운 뒤에는 `--no-lab`만 쓸 수 있다.
- 지표가 포화되어 있어 개선은 측정하기 어렵다. 개선 측정이 필요해지면 더 어려운 케이스(다중 리전 ERROR, 정책 해석이 필요한 IAM 등)나 LLM 판정자 지표를 더한다 (PLAN 후보).
