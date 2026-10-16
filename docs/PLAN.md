# 구현 계획

> **현재 단계: 4단계 — 에이전트화** (3단계 완료 2026-10-14. 2단계는 사용자 검토·공개 결정만 남음)
> 단계를 마치면 이 줄을 갱신한다.

## 목표

1차 목표: AWS 계정 하나를 읽기 전용으로 스캔해서 IAM, S3, EC2(보안그룹·VPC), CloudTrail을 대상으로 KISA 클라우드 취약점 점검 가이드와 ISMS-P 기준 양호/취약을 판정하고, 근거와 조치 방안이 담긴 점검 보고서를 생성한다.

작업량 기준: 주당 8~10시간. 3단계까지 약 2~2.5개월, 4단계까지 약 3개월.

---

## 0단계 — 준비 (1주)

- [x] 저장소 초기화: `uv init`, `pyproject.toml`, ruff/mypy/pytest 설정, `.gitignore`
- [x] 디렉터리 골격 생성 (`docs/ARCHITECTURE.md`의 구조 참고)
- [x] KISA 클라우드 취약점 점검 가이드 원문 확보 → `knowledge/kisa/` (2026 주통 상세가이드 XII. 클라우드)
- [x] ISMS-P 인증기준 원문 확보 → `knowledge/isms_p/`
- [x] 항목 분류표 작성 → `docs/COVERAGE.md`
  - 각 항목을 `full`(API로 자동 판정) / `partial`(증적 수집만 자동) / `manual`(사람이 확인)로 분류
- [x] `docs/RULES.md`의 KISA 항목코드 칸 채우기 (원문 근거 확인 후 `verified: true`) — KISA 매핑 사용자 확인 (2026-10-13), ISMS-P는 초안
- [x] AWS 점검 전용 IAM 역할 생성 (`SecurityAudit` 관리형 정책만 부여) — 사용자가 직접. IAM 사용자 `security_manager`로 생성
- [x] `lab/` 취약 실습 환경 Terraform 작성 — `terraform validate` 통과 (Terraform 1.16.5, AWS provider 6.68.0)
  - 퍼블릭 S3 버킷(정책, ACL), 0.0.0.0/0 SSH 허용 SG, 사용 중인 기본 SG, MFA 없는 콘솔 IAM 사용자, 직접 연결된 관리자 권한, 오래된 액세스 키, 퍼블릭 서브넷만 있는 VPC, 공인 IP가 붙은 ENI, CloudTrail, OIDC 공급자 등
  - 양호 케이스 리소스도 함께 구성 (PASS 검증용)
- [x] 실습 환경 배포 — 사용자가 직접 `terraform apply` (실습 전용 계정, 리소스 60개, 2026-10-13)

**완료 기준:** 분류표가 있고, 실습 환경이 떠 있으며, 빈 CLI가 `uv run kompass --help`로 실행된다.

## 1단계 — 수집과 판정 (2~3주)

- [x] `models.py`: `Snapshot`, `Finding`, `Status`, `Severity` (+ `CollectError`, `Mappings`, `Automation`, 항목 집계 `aggregate_status`)
- [x] `aws/session.py`: 프로필·역할 기반 세션(`sts:AssumeRole`, ADR-020), 활성 리전 조회 (ADR-021)
- [x] `aws/guard.py`: 읽기 전용 가드 (botocore `before-call` 이벤트 훅) + 테스트
- [x] `collectors/base.py`: `Collector` 인터페이스, `CallRecorder`(호출 결과를 정상·설정 없음·실패로 구분), `CollectError.resource` 추가
- [x] collector: `iam.py` (계정 요약, 비밀번호 정책, 자격증명 보고서, 권한 정보, 외부 IdP, Identity Center)
- [x] collector: `s3.py` (계정/버킷 퍼블릭 액세스 차단, 정책 상태, 암호화, 로깅, 객체 소유권, ACL)
- [x] collector: `ec2.py` (리전별 보안그룹, VPC, 서브넷, 라우팅 테이블, 네트워크 인터페이스)
- [x] collector: `cloudtrail.py` (추적 목록, 추적 상태, 이벤트 선택기)
- [x] 스냅샷 저장/로드: `reports/snapshots/<account_id>/<scan_id>/<service>.json` + `scan.json` (ADR-022, ADR-027)
- [x] 룰 엔진: 룰 레지스트리, 실행기, 판정 기준값 설정(`config.py`) (ADR-023)
- [x] `docs/RULES.md`의 초기 룰 구현 (룰마다 PASS/FAIL/ERROR 테스트) — 22개 룰 모두 실습 계정 기대값 일치
- [x] CLI: `kompass collect`, `kompass evaluate`, `kompass scan` (종료 코드 0/1/2/3/4, `--fail-on`, `--account-id`, `--config`, 결과 파일 `reports/findings/`)
- [x] 실습 환경 통합 테스트: 기대 결과표와 실제 결과 비교 (`lab/expected.yaml`, `pytest -m lab`, 62개 항목 일치)

**완료 기준:** `kompass scan`이 실습 환경에서 기대한 FAIL/PASS를 모두 맞히고 `findings.json`을 출력한다.

## 2단계 — 매핑과 보고서 (1~2주)

- [x] 매핑 데이터: `kisa_items.yaml`, `rules.yaml`, `isms_p_controls.yaml` + 문서·레지스트리 대조 테스트 (ADR-025)
- [x] 매퍼: finding에 매핑 정보 부착, 매핑 누락 검증 테스트, KISA 항목 집계 (ADR-026)
- [x] ISMS-P 커버리지 리포트 (자동 점검 / 부분 / 수동 항목 현황) — 보고서의 ISMS-P 절·시트
- [x] 리포터: JSON, Markdown (UTC로 저장된 시각은 KST로 표시, ADR-019)
- [x] 리포터: 엑셀 점검표 (항목별 결과, 대상 리소스, 증적 요약, 수식 삽입 방지)
- [x] CLI: `kompass report --format md|xlsx|json`, `kompass scan --report ...`
- [x] README에 사용법과 출력 예시 추가

**완료 기준:** LLM 없이도 실무에서 쓸 수 있는 점검표가 나온다. 이 시점에 README와 데모를 정리해서 공개 가능한 상태로 만든다.

## 3단계 — LLM 해석 (2주)

- [x] finding 식별자 정의: `Finding.key` = `룰:리전:리소스` (전역은 리전 `-`), 점검 안에서 유일성 검사. 해설·인용을 finding에 연결하는 데 필요
- [x] LLM 공급자 인터페이스 (Claude API 구현체 + 로컬 LLM 구현체 자리) — `interpreter/llm.py`, 구조화 출력·대체 모델·비용 계산 (ADR-030)
- [x] 마스킹 레이어: 계정 ID, IP, ARN, 리소스명 치환 및 복원 + 테스트 (`interpreter/masking.py`, 종류 보존 자리표시자 `MASKED_<종류>_n`)
- [x] RAG: KISA 가이드·ISMS-P 원문을 항목 코드 단위로 색인 (`scripts/build_source_index.py` → `knowledge/index.json`, KISA 19 · ISMS-P 별표 7 101개) (Chroma 벡터 검색은 4단계로, ADR-029)
- [x] 룰별 해설: 항목 근거 인용, 위험 설명 (조치 필요 finding을 룰 단위로 묶음, ADR-029) — `interpreter/explainer.py`
- [x] 인용 검증: LLM이 인용한 항목코드가 실제 매핑/원문에 존재하는지 확인 (+ 모르는 finding_key, 지어낸 자리표시자 검사, 1회 재시도 후 "검증되지 않음")
- [x] 위험 우선순위: 여러 finding을 엮은 종합 평가 — 룰별 우선순위 의견 + 종합 위험 평가(시나리오·조치 순서, `--assessment-only`로 재실행, ADR-034)
- [x] 조치 방안: AWS CLI 명령 + Terraform 수정안 (룰별 해설 스키마에 포함. 유효성은 평가셋에서 측정)
- [x] 평가셋: 실습 환경 결과 기반 골든셋, 인용 정확도·조치 유효성 측정 (ADR-033)
  - [x] 케이스 스키마·실습 결과 가공·보강 케이스 → `cases.md` 사용자 승인 (40개: 실습 가공 16, 보강 24)
  - [x] 정답(핵심 근거 구간·해소 작업)·채점기·오라클/널 테스트 (오라클 40/40 만점, 널 0점)
  - [x] 기록용 공급자 래퍼·실행기 (재개·동시 실행·오류 분류·dry-run) — `scripts/run_explain_eval.py`, 오라클 실행으로 형식·보고서 빌더 확인
  - [x] 파일럿 5개 실행 → 채점 결과 사용자 승인 ($0.36, 채점기 오판 2종 수정)
  - [x] 전체 기준선 실행 → `report.html`·`metrics.md` (40개 × 2회, 약 $5.2, 검증 통과 100%, 조치 작업 99.4%)
- [x] CLI: `kompass explain` (--dry-run 예상 비용, 비용 확인, --report로 보고서 반영. ADR-031)

**완료 기준:** 평가셋에서 인용 정확도와 조치 유효성 수치를 보고서로 낼 수 있다.

## 4단계 — 에이전트화 (2~3주)

- [x] collector 기능을 에이전트 도구로 노출 (읽기 전용 가드 유지) — 목적별 읽기 도구 12개(`agent/tools.py`), 결과에 새 이름 목록 첨부, 허용 목록 확대(ADR-035·036)
- [x] 에이전트 루프: 도구 러너 + 공급자 인터페이스, 마스킹 다리, 예산(호출·반복·토큰), 조사 로그 — `agent/llm.py`·`agent/toolbox.py`, 실제 API로 러너+구조화 출력 확인
- [x] 추가 조사 루프: 예) 퍼블릭 S3 발견 → 버킷 정책·ACL·CloudTrail 데이터 이벤트 추가 조회 — 사실마다 도구 호출 참조 검증(`agent/investigator.py`), `kompass investigate`(최대 비용 확인, `--dry-run`), 보고서 "추가 조사 (참고)" 절·시트
- [x] 수동 항목 인터뷰: 담당자에게 증적 요청 (업로드 문서 RAG 검토는 5단계로, ADR-035) — 고정 카탈로그 `mappings/evidence_requests.yaml`(근거 구절 원문 대조), 보고서 "증적 요청 목록" 절·시트, `kompass evidence` 요청서(ADR-037)
  - [ ] 사용자 확인: 요청 문구 원문 대조 후 `verified: true`
- [ ] MCP 서버로 도구 노출
- [x] 에이전트가 status를 변경할 수 없음을 보장하는 테스트 — 응답 스키마에 status·severity 없음, 조사 전후 finding 불변, Finding 동결 (`tests/agent/test_investigator.py`)

**완료 기준:** 에이전트가 1차 결과를 근거로 추가 조사를 스스로 수행하고, 그 과정이 로그로 남는다.

## 5단계 — 확장 (이후)

- [ ] Prowler OCSF 출력 어댑터 (`rule_id` 형식에 출처 접두사 허용 여부 결정, ADR-019)
- [ ] 서비스 추가: CloudTrail, KMS, RDS, VPC Flow Logs
- [ ] Azure 지원
- [ ] 다른 기준 추가 (CSAP 등)
