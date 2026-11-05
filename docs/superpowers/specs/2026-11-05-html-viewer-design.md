# HTML 결과 뷰어 설계

- 작성일: 2026-11-05
- 상태: 사용자 검토 대기
- 관련 결정: ADR-055 (구현 시 `docs/DECISIONS.md`에 기록)

## 1. 목적과 범위

### 목적

- 점검 결과(판정, 매핑, 해설, 추가 조사, 증적)를 브라우저에서 필터·검색·상세 보기로 탐색하게 한다. 지금은 md·xlsx를 열어 찾아야 한다.
- 가공 데이터로 만든 공개 데모로, AWS 자격증명이 없는 사람(면접관 등)도 링크 하나로 결과 화면을 보게 한다.

### 범위

- 포함: HTML 리포터(`--format html`), `kompass report --open`, 공개 데모 생성 스크립트와 커밋된 데모 파일, 테스트, ADR·PLAN 갱신
- 제외(이후 고도화): 로컬 웹 서버, 화면에서 점검·해설 실행(실행 마법사), 점검 이력 목록, 다크 모드, 인쇄용 레이아웃, 차트
- 이후 단계에서 로컬 서버를 붙일 때 `viewer.js`를 그대로 재사용할 수 있게 만든다. 서버는 이번에 만들지 않는다.

### 지키는 원칙 (CLAUDE.md)

- 원칙 1: 뷰어는 보고서에 있는 판정을 표시만 한다. 화면에서 `status`를 바꾸는 기능은 없다. LLM 산출물은 "(참고)"로 판정 영역과 구분한다.
- 원칙 3: 오류(`확인 불가`), 건너뛴 룰, 점검 범위에서 뺀 리전을 경고 띠로 드러낸다.
- 원칙 4: 실제 계정 HTML은 `reports/` 아래(`.gitignore` 대상)에만 생긴다. 커밋하는 데모는 가공 데이터로만 만든다.
- 새 런타임 의존성은 없다. 표준 라이브러리 `webbrowser`, `importlib.resources`, `hashlib`만 쓴다.

## 2. 구조

### 파일

```
kompass/reporters/html_reporter.py     # AuditReport → HTML 문자열 (조립·JSON 이스케이프·CSP 해시)
kompass/reporters/html/template.html   # 뼈대 + CSP 메타 + <noscript>
kompass/reporters/html/viewer.js       # 탭·필터·검색·상세 보기
kompass/reporters/html/viewer.css
scripts/build_demo.py                  # 가공 보고서 → docs/demo/index.html
docs/demo/index.html                   # 커밋하는 공개 데모 (생성물)
tests/reporters/test_html.py
```

- `html/` 아래 파일은 패키지 데이터로 포함하고 `importlib.resources`로 읽는다.
- 출력은 CSS·JS·데이터를 모두 담은 HTML 파일 하나다. 외부 요청 없이 오프라인으로 열린다.

### 데이터 흐름

1. `AuditReport`를 기존 JSON 리포터와 같은 방식으로 직렬화한다.
2. 화면 표기용 부가 정보를 함께 넣는다: `_format.py`의 `OUTCOME_LABELS`·`STATUS_LABELS`·`DISCLAIMER`, 룰 제목(`RULES` 레지스트리), KST로 바꾼 표시용 시각. 라벨을 JS에 따로 적지 않아 md·xlsx와 표기가 어긋나지 않는다.
3. 페이로드는 `{"report": <AuditReport JSON>, "labels": {...}, "rules": {...}, "display": {...}}` 형태다. `report`는 JSON 리포터 출력과 같아야 한다(테스트로 확인).
4. 이스케이프한 JSON을 `<script type="application/json" id="kompass-data">`에 넣는다.
5. `viewer.js`가 이 블록을 읽어 화면을 만든다. 집계·정렬 같은 화면용 계산만 하고, 판정 관련 값은 그대로 표시한다.

### CLI

- `ReportFormat`에 `html`을 추가한다. `kompass report --format html`과 `scan`·`explain`·`investigate`·`review-evidence`의 `--report html`에서 쓸 수 있다.
- 출력 경로는 다른 형식과 같은 규칙(`default_reports_dir`)을 따르고 확장자만 `.html`이다.
- `kompass report --open`은 이번에 만든 HTML을 기본 브라우저로 연다. HTML을 만들지 않은 실행에서는 안내만 출력한다. 브라우저 호출은 테스트에서 교체할 수 있게 함수 인자나 모듈 속성으로 둔다.
- 기본 형식은 지금처럼 md와 xlsx로 둔다.

## 3. 화면

화면 문구는 보고서 규칙(개조식 명사형)을 따른다.

### 상단 (항상 표시)

- 점검 정보: 점검 ID, 계정, 리전, 수행 주체, 시작·종료 시각(KST), kompass 버전, 매핑 해시, 면책 문구(`DISCLAIMER`)
- 요약 카드: KISA 항목 결과별 개수, finding 상태별 개수
- 경고 띠(해당할 때만): 점검 범위에서 뺀 리전과 거부 메시지, 건너뛴 룰, `확인 불가` finding 개수

### 탭

1. 개요: 조치가 필요한 KISA 항목(결과 취약·확인 불가·검토 필요)을 중요도·결과 순으로 표시한다. 해설에 종합 위험 평가가 있으면 시나리오와 조치 순서를 "(참고)"로 표시한다.
2. KISA 항목: 항목 표(코드, 항목, 중요도, 분류, 결과, 룰, finding 개수). 행을 펼치면 그 항목의 finding 목록이 나온다. 아래에 "KISA 대응 항목이 없는 룰"과 "건너뛴 룰"을 둔다.
3. Finding: 전체 finding 표. 필터는 상태, 중요도, 서비스(룰 ID 접두어), 리전, KISA 코드이고, 리소스·메시지 문자열로 검색한다.
4. ISMS-P (초안): 통제항목 표(코드, 이름, 영역, 결과, KISA 항목, 룰). "매핑 초안, 담당자 확인 전" 안내 띠를 고정으로 표시한다.
5. 증적: 증적 요청 목록(항목별 요청 문구, `verified`, 확인 대상 리소스)과 증적 검토(검토한 문서, 사실, 부족한 점, 추가 요청, 검토하지 못한 요청, 사람이 검토할 파일)

### Finding 상세 (오른쪽 패널)

- 판정: 상태, 중요도, 룰 ID와 제목, 리소스, 리전, 수집 시각(KST), 메시지
- 매핑: KISA·ISMS-P 코드와 `verified` 여부
- 증적: `evidence` JSON. 기본은 접힌 상태로 두고 펼칠 수 있다.
- AI 해설 (참고): 같은 룰의 해설. 위험 설명, 우선순위, 인용 구절과 검증 여부, 이 리소스의 리소스별 설명, 조치 절차·AWS CLI·Terraform 예시. "명령 실행은 사람이 판단" 안내를 붙인다.
- 추가 조사 (참고): 같은 룰의 조사 사실과 근거 도구 호출, 메모
- LLM 산출물 영역은 배경색과 "(참고)" 표시로 판정 영역과 구분한다.

### 기타 동작

- 주소 해시: `#tab=<탭>`, `#finding=<Finding.key>`로 특정 탭이나 finding을 바로 연다. 해시는 문자열 비교로만 쓰고 DOM에 HTML로 넣지 않는다.
- 해설·조사·증적 검토가 없는 보고서에서는 해당 영역에 "해설 없음" 같은 안내만 표시한다.

## 4. 보안

입력 문자열(리소스 이름, 태그, 메시지, 증적, LLM 해설, 증적 문서 발췌)은 모두 신뢰할 수 없는 값으로 다룬다.

- DOM 생성: `viewer.js`는 `document.createElement`와 `textContent`만 쓴다. `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, 문자열 인자 `setTimeout`/`setInterval`은 쓰지 않는다. `href`는 `#`로 시작하는 문서 안 주소만 넣는다.
- 데이터 삽입: `json.dumps(..., ensure_ascii=False)` 결과에서 `<`·`>`·`&`·U+2028·U+2029를 `\uXXXX`로 바꾼다. 데이터 블록은 `type="application/json"`이라 실행되지 않는다.
- CSP 메타: `default-src 'none'; script-src 'sha256-<viewer.js>'; style-src 'sha256-<viewer.css>'; img-src data:; base-uri 'none'; form-action 'none'`. 해시는 리포터가 인라인 내용으로 계산한다. `'unsafe-inline'`과 외부 출처는 넣지 않는다. 메타 CSP에서 쓸 수 없는 `frame-ancestors`는 넣지 않는다.
- 실제 계정 HTML은 md·xlsx와 같은 보관 규칙을 따른다. 마스킹하지 않은 원본이므로 외부 전달은 사람이 판단한다(매뉴얼에 기록).

## 5. 공개 데모

- `scripts/build_demo.py`는 전부 가공한 시나리오로 `AuditReport`를 만들고 HTML 리포터로 `docs/demo/index.html`을 쓴다.
  - 계정 ID는 예시 값(`123456789012`), ARN·IP·리소스명은 가공 값을 쓴다.
  - 시나리오에 취약·검토 필요·확인 불가·양호·해당 없음, 건너뛴 룰, 점검 범위에서 뺀 리전, 해설(종합 위험 평가 포함), 추가 조사, 증적 요청·검토를 모두 넣는다.
  - 원문 인용은 짧은 구절만 넣는다. 원문 색인(`knowledge/index.json`)은 읽지 않는다.
  - 시각은 고정값을 써서 실행할 때마다 같은 출력이 나오게 한다.
- `tests/reporters/sample.py`의 도우미를 재사용할 수 있으면 재사용하고, 데모 시나리오 데이터는 스크립트 쪽에 둔다.
- GitHub Pages는 사용자가 저장소 설정에서 직접 켠다(`main` 브랜치 `/docs`). 주소는 `https://zelopy.github.io/kompass-isms/demo/`이다. README와 `docs/PORTFOLIO.md`에서 이 주소로 링크하고, Pages를 켜기 전까지는 저장소 안 파일 경로를 함께 적는다.

## 6. 오류 처리

- JS가 꺼져 있으면 `<noscript>`로 JavaScript가 필요하다는 안내와 md·xlsx 보고서를 보라는 안내를 표시한다.
- 데이터 블록을 해석하지 못하거나 `report.format_version`이 1이 아니면 화면 대신 오류 안내를 표시한다.
- `--open`에서 브라우저를 열지 못하면 경고와 파일 경로를 출력한다. 종료 코드는 바꾸지 않는다.

## 7. 테스트

기본 실행(`uv run pytest`)에 포함한다.

- 데이터 왕복: HTML에서 데이터 블록을 꺼내 파싱한 `report`가 JSON 리포터 출력과 같다.
- 탈출 방지: 리소스 이름·메시지·해설·증적 발췌에 `</script><img src=x onerror=alert(1)>`, `<!--`, U+2028을 넣은 보고서에서 `<script` 태그 수가 고정값과 같고, 데이터가 원문 그대로 복원된다.
- CSP: 메타 태그가 있고, `script-src`·`style-src` 해시가 실제 인라인 내용의 SHA-256과 같으며, `unsafe-inline`·`http:`·`https:`가 없다.
- 금지 API: `viewer.js`에 4절의 금지 목록이 없다(정적 검사).
- 선택 영역: 해설·조사·증적 검토가 없는 보고서도 만들어진다.
- CLI: `--format html`이 파일을 만들고, `--open`이 교체한 브라우저 함수를 그 경로로 호출한다. HTML이 없는 실행에서 `--open`은 호출하지 않는다.
- 데모 동기화: 커밋된 `docs/demo/index.html`이 `build_demo.py` 출력과 같다. 다르면 데모를 다시 만들라는 메시지로 실패한다.
- 패키지 데이터: 템플릿 파일 세 개를 `importlib.resources`로 읽을 수 있다.

브라우저 동작은 개발 중에 Playwright로 데모를 열어 수동으로 확인한다. 확인 항목은 탭 전환, 필터·검색, 상세 패널, 주소 해시, 콘솔 오류와 CSP 위반이 없는지다. JS 단위 테스트 도구(Node)는 들이지 않는다. 확인할 때 찍은 화면은 README·포트폴리오 이미지로 쓴다.

## 8. 문서 갱신

- `docs/DECISIONS.md` ADR-055: HTML 리포터 도입, 의존성 없는 순수 JS 방식, 신뢰할 수 없는 문자열 처리와 CSP, 공개 데모는 가공 데이터만 쓴다는 원칙, 로컬 서버·실행 마법사는 이후로 미룸
- `docs/PLAN.md` 5단계: HTML 결과 뷰어 항목과 하위 체크박스
- `docs/MANUAL.md`: `--format html`, `--open`, HTML 파일 전달 시 주의
- `docs/ARCHITECTURE.md`: 리포터 목록에 HTML 추가
- `README.md`·`docs/PORTFOLIO.md`: 데모 링크와 화면 이미지
