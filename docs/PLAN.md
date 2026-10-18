# 구현 계획

> **현재 단계: 5단계 — 확장** (4단계 완료 2026-10-16). 남은 사용자 확인 없음. ISMS-P 매핑 담당자 협의는 실제 진단 프로젝트를 할 때 검토표를 전달해 진행 (2026-10-17). 저장소 공개는 마무리 시점에 검토
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
- [x] ISMS-P 매핑 1차 검토: 별표 7·안내서 대조, 2.10.2를 19개 항목 전체로, CA-05·06 권한 항목 수정, 근거 쪽수 기록 (ADR-046, 2026-10-16)
- [x] 담당자 협의용 검토표 작성: `docs/ISMS_P_MAPPING_REVIEW.md` (문서는 로컬·GitHub에서만 관리)
- [ ] (실제 진단 프로젝트 진행 시) ISMS-P 매핑 확정: 검토표 파일을 담당자에게 전달하고 회신받아 반영 (`isms_p_verified: true`, 매핑 YAML·COVERAGE.md·검토표). 쟁점 5건과 Prowler 비교의 반복되는 차이
  - 검토표는 바로 전달할 수 있는 양식으로 유지한다. 매핑과 어긋나면 테스트가 실패한다 (`test_review_*`). 전달 전에 기준일만 고친다
- [ ] 저장소 공개 여부 결정 (현재 GitHub 비공개. 프로젝트 마무리 시점에 검토)

**완료 기준:** LLM 없이도 실무에서 쓸 수 있는 점검표가 나온다. 이 시점에 README와 데모를 정리해서 공개 가능한 상태로 만든다.

## 3단계 — LLM 해석 (2주)

- [x] finding 식별자 정의: `Finding.key` = `룰:리전:리소스` (전역은 리전 `-`), 점검 안에서 유일성 검사. 해설·인용을 finding에 연결하는 데 필요
- [x] LLM 공급자 인터페이스 (Claude API 구현체 + 로컬 LLM 구현체 자리) — `interpreter/llm.py`, 구조화 출력·대체 모델·비용 계산 (ADR-030)
- [x] 마스킹 레이어: 계정 ID, IP, ARN, 리소스명 치환 및 복원 + 테스트 (`interpreter/masking.py`, 종류 보존 자리표시자 `MASKED_<종류>_n`)
- [x] RAG: KISA 가이드·ISMS-P 원문을 항목 코드 단위로 색인 (`scripts/build_source_index.py` → `knowledge/index.json`, KISA 19 · ISMS-P 별표 7 101개) (Chroma 벡터 검색은 4단계로 미뤘으나 4단계에서 쓰지 않음 → 5단계 증적 문서 검토에서 필요 여부 결정, ADR-029·035)
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
  - [x] 사용자 확인: 요청 문구 원문 대조 후 `verified: true` — 19개 항목 확인, CA-12-2·CA-17-2 문구 수정 (2026-10-16). 대조 중 발견한 CA-11 요청 누락으로 CA-11을 `partial`로 재분류 (ADR-047)
- [x] MCP 서버로 도구 노출 — `kompass mcp`(stdio), 판정 결과 조회 + 조사 도구 12개, 세션 단위 마스킹 다리·호출 상한·호출 로그, 가드 위반 시 세션 중단 (ADR-038)
- [x] 에이전트가 status를 변경할 수 없음을 보장하는 테스트 — 응답 스키마에 status·severity 없음, 조사 전후 finding 불변, Finding 동결 (`tests/agent/test_investigator.py`)

- [x] 실습 계정 실행: 추가 조사 16개 룰 근거 검증 16/16, 약 $2.24, 식별정보 노출 없음. 증적 요청서·MCP 연결 확인 (ADR-035 실행 기록)

**완료 기준:** 에이전트가 1차 결과를 근거로 추가 조사를 스스로 수행하고, 그 과정이 로그로 남는다.

## 5단계 — 확장 (이후)

### 서비스 추가·수동 항목 자동화 (완료)

- [x] 서비스 추가: CloudTrail(CT-002), RDS, VPC 흐름 로그, GuardDuty, CloudWatch Logs. KMS는 KISA 대응 항목이 없어 후보로 내림 (2026-10-16 사용자 결정)
  - [x] RDS collector + RDS-001~004 (CA-11·CA-08·CA-15·CA-18, ADR-039). 실습 환경 `enable_public_rds`로 인스턴스 2개
  - [x] RDS 실습 계정 확인: RDS-001~004 기대값 일치, 로그 내보내기가 없으면 `EnabledCloudwatchLogsExports` 키 생략, VPC-002가 공개 RDS 인터페이스를 REVIEW로 냄 (2026-10-16)
  - [x] VPC 흐름 로그: VPC-003 (CA-14, ADR-040). 실습 `mixed` VPC에 흐름 로그
  - [x] GuardDuty: GD-001~002 (CA-19, ADR-041). 기본값(`enable_guardduty = false`) 결과도 실습 계정에서 확인
  - [x] S3 HTTPS 강제: S3-007 (CA-12, ADR-042). 실습 `private` 버킷에 HTTP 거부 정책
  - [x] 로그 보관 기간: CT-002·LOG-001 (CA-17, ADR-043). 실습 추적 버킷 30일 삭제 규칙, 로그 그룹 2개
  - [x] 권한 보유 주체 현황: IAM-010~011 (CA-05·CA-06, ADR-044). KISA 19개 항목 모두 자동 점검 룰 보유
  - [x] 실습 계정 확인 (2026-10-16, `enable_public_rds`·`enable_guardduty` 켬): VPC-003·S3-007·CT-002·LOG-001·IAM-010~011·GD-001~002·RDS-001~004 기대값 일치. `expected.yaml`에 선택 변수별 기대값(`when`)
  - [x] 발견한 결함 수정: 자격증명 보고서 재사용으로 새 사용자가 빠지던 문제 → ERROR (ADR-045)
  - [x] 평가 케이스 추가: 5단계 룰 20개(실습 가공 10, 보강 10). 20×2회 약 $2.55, 채점기 오판 2종 수정 후 모든 지표 100% (ADR-033 기록)

### 남은 확인

- [x] 사용자 확인: 5단계 룰 12개 KISA 매핑 원문 근거 (`kisa_verified`) — RDS-001~004, VPC-003, GD-001~002, S3-007, CT-002, LOG-001, IAM-010~011. S3-007 근거 구절을 판단 기준으로 교체 (2026-10-17, ADR-048)
- [x] 재실습 통합 테스트 재실행 (2026-10-17, `enable_public_rds`·`enable_elb` 켬): `pytest -m lab` 통과
  - [x] IAM-003·005: 자격증명 보고서(09:50Z)가 `console-no-mfa` 생성(09:35Z) 뒤에 새로 만들어져 IAM-003 FAIL·IAM-005 PASS로 판정됨 (ERROR 아님, ADR-045)
  - [x] RDS-005: 기본 그룹 `default.postgres18`이 `rds.force_ssl` 값 `1`(`Source: system`)을 돌려줌 → `private` PASS, `public` FAIL (ADR-051)
  - [x] ELB-001~002: `weak` FAIL·FAIL, `strict` PASS·PASS (ADR-052)
  - [x] 실습 가공 평가 케이스 생성: `make_eval_cases.py --lab-rules RDS-005,ELB-001,ELB-002`
- [x] 사용자 확인: RDS-005 KISA 매핑 원문 근거 (`kisa_verified`, CA-12 판단 기준 구절, 근거 수준 직접) (2026-10-17, ADR-051)

### 다음 작업 (규모가 커서 진행할 때 범위부터 정함)

- [x] 제출된 증적 문서 검토 — 범위 결정 (2026-10-17, ADR-049). Chroma 벡터 검색은 쓰지 않음
  - [x] 증적 폴더 읽기·텍스트 추출 (요청 ID 폴더, PDF·xlsx·텍스트류, `pypdf` 런타임 의존성) — `interpreter/documents.py`
  - [x] 개인정보 마스킹: 이메일·전화번호·주민등록번호 패턴, 사용자 사전(이름 등, 2자부터) — `Masker(personal=True, terms=…)`, `load_terms`. 해설·조사에는 켜지 않음
  - [x] 검토기: 요청별 사실(문서 발췌 대조 검증)·부족한 점·추가 요청. status 없음 — `interpreter/evidence_reviewer.py`, 문서 안의 지시는 따르지 않도록 프롬프트에 명시
  - [x] `kompass review-evidence` (마스킹 결과 미리보기·확인, 비용 확인, `--dry-run`, 검토 결과 파일) — `reports/evidence-reviews/<계정>/<점검 ID>.evidence-review.json`, 미리보기 `.evidence-preview.md`
  - [x] 보고서 "증적 검토 (참고)" 절 (md·xlsx·json) — `AuditReport.with_evidence_reviews`, 같은 판정 결과의 검토만 붙음. `review-evidence --report`
  - [x] 평가 케이스와 실제 호출 확인 (가공 증적 문서) — 8개 × 2회 모든 지표 100% (채점기 오판 수정 후), 약 $0.72. `scripts/run_evidence_eval.py`
  - [x] 프롬프트 다듬기: 요청 범위 밖 지적·빈 확인 대상 언급·필드 이름·자리표시자 뒤 조사 — 지표 `gap_budget`·`no_field_names` 추가, v1 8개 × 1회 모든 지표 100% (약 $0.34)
- [x] 룰: RDS SSL 연결 강제 RDS-005 (CA-12, ADR-051) — 파라미터 그룹 SSL 강제 파라미터 수집, 실습 `public`에 `rds.force_ssl=0` 그룹 (실습 계정 확인 2026-10-17)
  - [x] 평가 케이스 추가 (실습 가공·보강, ADR-033)
    - [x] 보강 2개: 엔진 기본값·`rds.force_ssl=0` 클러스터 FAIL, 클러스터 파라미터 조회 거부 ERROR·Oracle REVIEW. 오라클 모든 지표 100%. 정답에 RDS-005 `review` 작업 추가
    - [x] 실제 모델 실행 (2개 × 2회, $0.33): 대상 일치 외 100%, 채점기 오판 2종 수정 후 대상 일치 91.7%. 남은 1건은 기본 파라미터 그룹 이름 마스킹 영향 (ADR-033 기록)
    - [x] 실습 가공 1개 생성 (2026-10-17, `lab-rds-005`)
    - [x] 실제 모델 실행 (`lab-rds-005`, ELB 케이스와 함께): 모든 지표 100%
- [x] 룰: 로드 밸런서 평문 리스너·TLS 정책 ELB-001~002 (CA-12, ADR-052) — ALB·NLB·Classic, TCP 리스너 REVIEW, 기준 `elb.min_tls_version`. 실습 `enable_elb`로 internal ALB 2개
  - [x] 사용자 확인: KISA 매핑 원문 근거 (`kisa_verified`). ELB-001 판단 기준 구절(직접), ELB-002 판단 기준 + 조치 사례의 "TLS v1.2 이상" 예시(해석) (2026-10-17)
  - [x] 실습 계정 확인 (2026-10-17): 기대값 일치
  - [x] 평가 케이스 추가 (실습 가공·보강, ADR-033)
    - [x] 실습 가공 2개 생성 (`lab-elb-001`·`lab-elb-002`)
    - [x] 보강 3개: Classic HTTP FAIL·NLB TCP REVIEW, 규칙·리스너 조회 거부 ERROR, Classic 구형 협상 정책 FAIL·NLB 정책 조회 거부 ERROR. 오라클 68개 모든 지표 100% (ELB ARN 종류 구간 마스킹 수정 후)
    - [x] 실제 모델 실행 (실습 가공 2개 + 보강 3개, `lab-rds-005`와 함께 6개 × 2회, $0.82): 채점기 오판 2종 수정 후 모든 지표 100% (ADR-033 기록)
- [x] 룰: RDS 공개 스냅샷 RDS-006 (CA-10, ADR-053) — 수동 스냅샷·공유 속성 수집, 실습 `public` 스냅샷 공개 (실습 계정 확인 2026-10-17)
  - [x] 룰·collector·테스트, 매핑 `kisa_verified: false`, 실습 Terraform·기대값
  - [x] 사용자 확인: KISA CA-10 매핑 원문 근거 (근거 수준 해석) (2026-10-18)
  - [x] 실습 계정 확인 (2026-10-17, `enable_public_rds = true`): `pytest -m lab` 통과. 공개 스냅샷 FAIL, 비공유 스냅샷 PASS. 공유하지 않은 스냅샷도 `restore` 속성을 빈 목록으로 돌려줌
  - [x] 평가 케이스 추가 (실습 가공·보강, ADR-033)
    - [x] 실습 가공 1개(`lab-rds-006`), 보강 2개: Aurora 클러스터 스냅샷 공개 FAIL·특정 계정 공유 PASS, 공개 MySQL 스냅샷 FAIL·공유 속성 조회 거부 ERROR. 오라클 3개 모든 지표 100%
    - [x] 실제 모델 실행 (3개 × 2회, $0.40): 채점기 오판 1종 수정 후 모든 지표 100% (ADR-033 기록)
- [x] 룰: AWS Backup 계획·보존 기간·최근 백업 BKP-001~003 (CA-18, ADR-054) — 새 collector `backup`, 계획 없음은 REVIEW. 실습 `enable_backup`으로 계획 2개·빈 DynamoDB 테이블
  - [x] 룰·collector·테스트, 매핑 `kisa_verified: false`, 실습 Terraform·기대값, ISMS-P 검토표·Prowler 비교(`backup_plans_exist` 2.9.3·2.12.1)
  - [x] 실습 통합 테스트 결함 수정: `LAB_FLAGS`에 `enable_elb`가 없어 ELB 기대값 6개가 대조에서 빠지던 문제 (기본 실행 검사 `tests/test_lab_expected.py` 추가)
  - [x] 사용자 확인: KISA CA-18 매핑 원문 근거 (BKP-001·003 직접, BKP-002 해석) (2026-10-18). RDS-004에 7일 기준은 해석이라는 비고 추가
  - [x] 실습 계정 확인 (2026-10-18, `enable_backup`·`enable_elb` 켬, 첫 백업 뒤): `pytest -m lab` 통과. `SecurityAudit`으로 backup 조회 실패 없음, BKP-001 PASS·BKP-002 `daily` PASS·`short` FAIL·BKP-003 PASS. ELB 기대값 6개 처음으로 실제 대조해 일치. 백업 서비스 역할이 IAM-010 REVIEW(`ssm:SendCommand`)라 기대값에 추가. 끈 뒤(`enable_backup`·`enable_elb` false)에도 통과: BKP-001 REVIEW, BKP-002·003 N/A
  - [x] 평가 케이스 추가 (실습 가공·보강, ADR-033)
    - [x] 실습 가공 1개 생성 (2026-10-18, `lab-bkp-002`: `short` FAIL·`daily` PASS). BKP-001·003은 실습에서 PASS라 실습 케이스 없음
    - [x] 보강 5개: BKP-001 REVIEW(계획 없음)·FAIL·ERROR, BKP-002 REVIEW(복사 뒤 삭제)·ERROR, BKP-003 FAIL(오래된 백업·백업 미수행)·ERROR. 오라클 6개 모든 지표 100% (2026-10-18)
    - [x] 오라클이 찾은 결함 수정: BKP-002 증적에 계획 ID(`backup_plan_id`)가 없어 조치 명령 대상 일치 0% → 증적·마스킹·채점기 수정, `lab-bkp-002` 재생성 (ADR-033 기록)
    - [x] 실제 모델 실행 (2026-10-18, 6개 × 2회, $0.80): 모든 지표 100%. BKP-002 조치 명령이 증적의 계획 ID를 씀
- [x] Prowler OCSF 출력 어댑터 필요성 검토 — 보류, 후보로 내림 (2026-10-17, ADR-050). 대신 Prowler ISMS-P 대응표를 매핑 협의 참고 자료로 비교
  - [x] Prowler `kisa_isms_p_2023_aws` 대응표와 ISMS-P 매핑 초안 비교표 (`docs/ISMS_P_MAPPING_REVIEW.md` 참고 절) — 같음 10·다름 21·대응 없음 4, 협의 쟁점 4건에 참고 의견. RDS-005 추가 후 같음 11 (Prowler `rds_instance_transport_encrypted`도 2.7.1·2.10.2)
- [ ] Azure 지원
- [ ] 다른 기준 추가 (CSAP 등)

### 후보 (결정 기록에서 미룬 것, 우선순위 미정)

- 룰: S3 최소 TLS 버전 (CA-12, ADR-042·051. 2026-10-18 재검토 후 보류 유지, ADR-054), CloudWatch 경보 (CA-19, ADR-041), KMS 고객 관리형 키 자동 교체 (KISA 대응 항목 없음, ISMS-P 2.7.2 후보)
- 연동: Prowler OCSF 출력 어댑터 (ADR-050에서 보류. KISA 축 밖의 점검이 필요해지거나 다른 기준을 더할 때 다시 검토)
- LLM: 로컬 LLM 공급자 구현체 (ADR-007·029에서 자리만 둠), 종합 위험 평가의 평가 (ADR-034), 평가셋 난이도 보강과 LLM 판정자 지표 (ADR-033)
