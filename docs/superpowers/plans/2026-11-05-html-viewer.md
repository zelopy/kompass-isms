# HTML 결과 뷰어 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `AuditReport`를 파일 하나짜리 오프라인 HTML 뷰어로 내보내는 리포터(`--format html`, `report --open`)와, 가공 데이터로 만든 공개 데모(`docs/demo/index.html`)를 만든다.

**Architecture:** `html_reporter.py`가 패키지 데이터(`template.html`·`viewer.js`·`viewer.css`)와 이스케이프한 JSON 페이로드를 하나의 HTML로 합치고, CSP 해시를 계산한다. 화면은 순수 JS(`viewer.js`)가 `createElement`·`textContent`로만 그린다. 데모는 `kompass/demo.py`의 가공 시나리오를 `scripts/build_demo.py`가 렌더링하고, 테스트가 커밋된 파일과 동기화를 확인한다.

**Tech Stack:** Python 3.12 표준 라이브러리(`json`, `hashlib`, `base64`, `importlib.resources`, `webbrowser`), pydantic v2, typer, pytest. 새 의존성 없음.

**Spec:** [docs/superpowers/specs/2026-11-05-html-viewer-design.md](../specs/2026-11-05-html-viewer-design.md)

## Global Constraints

- 새 런타임·개발 의존성 추가 금지. Node·JS 테스트 도구 도입 금지.
- 뷰어는 판정을 표시만 함. `status`·`severity`를 바꾸는 코드·UI 금지 (원칙 1).
- `viewer.js` 금지 API: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, 문자열 인자 `setTimeout`/`setInterval`. `href`는 `#`로 시작하는 값만.
- CSP: `default-src 'none'; script-src 'sha256-…'; style-src 'sha256-…'; img-src data:; base-uri 'none'; form-action 'none'`. `'unsafe-inline'`·외부 출처 금지.
- 데이터 블록: `<script type="application/json" id="kompass-data">`. JSON의 `<`·`>`·`&`·U+2028·U+2029는 `\uXXXX`.
- 표시 라벨은 `kompass/reporters/_format.py` 상수에서만 가져옴(JS에 상태 라벨 하드코딩 금지).
- 화면·보고서 문구는 개조식 명사형(`~함`, `~임`, `없음`). 문서·docstring·주석은 평서체(`~다`). CLI 출력은 정중체(`~습니다`).
- 기본 보고서 형식은 md·xlsx 그대로.
- 공개 데모는 가공 데이터만. 계정 `123456789012`, 고정 시각, `knowledge/index.json` 읽지 않음, 인용은 짧은 구절.
- 커밋: Conventional Commits, 끝에 `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. 브랜치 `feat/html-viewer`.
- 태스크마다 `uv run pytest`, `uv run ruff check . && uv run ruff format --check .`, `uv run mypy kompass` 통과 후 커밋.

## Review Focus

1. 증적(`evidence`)에 중첩 깊은 객체·큰 배열·`null`·숫자 키가 있는 finding — 상세 패널이 예외 없이 JSON을 보여 줘야 함 → Task 3 `test_payload_keeps_nested_evidence`, Task 5 브라우저 확인 항목.
2. 리소스 이름이 매우 길거나(ARN 2,000자) 공백·탭·개행이 섞인 경우 — 표가 깨지지 않고 원문 그대로 표시 → Task 3 악성·특수 문자열 왕복 테스트에 포함, Task 5 CSS `overflow-wrap:anywhere` 확인.
3. finding 0건 보고서(모든 룰 건너뜀) — 빈 표 대신 "결과 없음" 안내 → Task 3 `test_renders_report_without_findings`, Task 5 확인.
4. 해시 주소에 없는 finding key나 이상한 문자열(`#finding=<img>`) — 무시하고 기본 탭 표시 → Task 5 브라우저 확인 항목(JS는 key 일치 비교만).
5. 매핑 YAML을 바꾸면 `mapping_digest`가 바뀌어 데모 동기화 테스트가 실패함 — 실패 메시지가 재생성 명령을 알려야 함 → Task 5 `test_demo_is_up_to_date` 메시지 확인.

---

### Task 1: HTML 조립·이스케이프·CSP (`render_html`)

뷰어 JS는 아직 최소한(데이터를 읽어 점검 ID만 표시)으로 두고, 조립과 보안 경계를 먼저 고정한다.

**Files:**
- Create: `kompass/reporters/html_reporter.py`
- Create: `kompass/reporters/html/template.html`, `kompass/reporters/html/viewer.js`, `kompass/reporters/html/viewer.css`
- Test: `tests/reporters/test_html.py`

**Interfaces:**
- Produces:
  - `render_html(report: AuditReport) -> str`
  - `build_payload(report: AuditReport) -> dict[str, Any]` — `{"report": json.loads(render_json(report)), "labels": {...}, "rules": RULE_TITLES, "display": {...}}`
  - `extract_payload(html: str) -> dict[str, Any]` — 테스트·데모 검사용. `id="kompass-data"` 블록을 찾아 `json.loads`.
  - 상수 `DATA_ELEMENT_ID = "kompass-data"`
- `labels` 키: `outcome`(OUTCOME_LABELS, 키는 `.value`), `status`(STATUS_LABELS), `priority`(PRIORITY_LABELS), `scheme`(SCHEME_LABELS), `notices`(`disclaimer`=DISCLAIMER, `explanation`=EXPLANATION_NOTICE, `investigation`=INVESTIGATION_NOTICE, `evidence_review`=EVIDENCE_REVIEW_NOTICE, `evidence`=EVIDENCE_NOTICE, `evidence_unverified`=EVIDENCE_UNVERIFIED)
- `display` 키: `started_at`·`finished_at`·`generated_at`(각각 `kst(...)` 문자열), 해설·조사·증적 검토가 있으면 `explanations_at`·`investigations_at`·`evidence_reviews_at`
- 템플릿 자리표시자: `{{CSP}}`, `{{STYLE}}`, `{{DATA}}`, `{{SCRIPT}}`. `str.replace`로 채운다. `{{DATA}}`는 마지막에 채워 데이터 안의 `{{SCRIPT}}` 같은 문자열이 치환되지 않게 한다.

- [ ] **Step 1: 실패하는 테스트 작성**

```python
HOSTILE = "</script><img src=x onerror=alert(1)><!--    {{SCRIPT}} &amp;"

def test_payload_round_trips_report() -> None:
    payload = extract_payload(render_html(DEFAULT))
    assert payload["report"] == json.loads(render_json(DEFAULT))

def test_labels_come_from_format_constants() -> None:
    labels = extract_payload(render_html(DEFAULT))["labels"]
    assert labels["status"]["ERROR"] == "확인 불가"
    assert labels["outcome"]["NOT_IMPLEMENTED"] == "수동 점검 (미구현)"
    assert labels["notices"]["disclaimer"] == DISCLAIMER

def test_display_times_in_kst() -> None:
    assert extract_payload(render_html(DEFAULT))["display"]["started_at"] == "2026-10-14 08:07:54 KST"

def test_hostile_strings_cannot_break_out() -> None:
    report = sample_report(finding("S3-004", Status.FAIL, HOSTILE, "ap-northeast-2", HOSTILE, {"k": HOSTILE}))
    html = render_html(report)
    assert html.count("<script") == 2          # 데이터 블록 1 + 뷰어 1
    assert "</script><img" not in html
    assert " " not in html
    [f] = extract_payload(html)["report"]["findings"]
    assert f["resource"] == HOSTILE and f["evidence"]["k"] == HOSTILE

def test_csp_hashes_match_inline_code() -> None:
    html = render_html(DEFAULT)
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1)
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
    style = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
    assert f"'sha256-{_b64sha(script)}'" in csp and f"'sha256-{_b64sha(style)}'" in csp
    assert "default-src 'none'" in csp
    assert "unsafe-inline" not in csp and "http" not in csp

def test_no_external_urls() -> None:
    assert not re.search(r"(src|href)=\"(https?:)?//", render_html(DEFAULT))

def test_viewer_js_avoids_unsafe_apis() -> None:
    js = (files("kompass.reporters") / "html" / "viewer.js").read_text(encoding="utf-8")
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert banned not in js
    assert not re.search(r"set(Timeout|Interval)\(\s*['\"`]", js)

def test_noscript_notice() -> None:
    assert "<noscript>" in render_html(DEFAULT)
```

`_b64sha(text)`는 테스트 안 도우미: `base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()`.

- [ ] **Step 2: 실패 확인** — `uv run pytest tests/reporters/test_html.py -v` → `ModuleNotFoundError: kompass.reporters.html_reporter`

- [ ] **Step 3: 구현**
  - 이스케이프: `json.dumps(payload, ensure_ascii=False, separators=(",", ":"))` 뒤 `<`→`<`, `>`→`>`, `&`→`&`, U+2028→` `, U+2029→` `.
  - CSP 해시는 템플릿에 실제로 들어가는 `viewer.js`·`viewer.css` 문자열 그대로(개행 포함)의 SHA-256 base64.
  - `template.html`: `<!DOCTYPE html>`, `<html lang="ko">`, `<meta charset="utf-8">`, CSP 메타, `<meta name="viewport" ...>`, `<title>kompass 점검 결과</title>`, `<style>{{STYLE}}</style>`, `<noscript>` 안내("JavaScript가 필요함. md·xlsx 보고서 참고"), `<div id="app"></div>`, 데이터 블록, `<script>{{SCRIPT}}</script>`. 인라인 이벤트 속성 없음.
  - `viewer.js` 이 태스크 범위: 데이터 블록을 `JSON.parse(textContent)`로 읽고 `report.format_version !== 1`이거나 파싱 실패면 "보고서 데이터를 읽지 못함" 안내, 아니면 `#app`에 점검 ID를 `textContent`로 표시. `"use strict"`, IIFE.

- [ ] **Step 4: 통과 확인** — `uv run pytest tests/reporters/test_html.py -v` → 전부 PASS. 린트·mypy 통과.

- [ ] **Step 5: 커밋** — `feat(reporters): add self-contained HTML report renderer`

---

### Task 2: CLI 연결 (`--format html`, `report --open`)

**Files:**
- Modify: `kompass/pipeline.py` (`REPORT_FORMATS`에 `"html": (".html", render_html)`)
- Modify: `kompass/cli.py` (`ReportFormat.HTML = "html"`, `--format`/`--report` 도움말의 형식 목록에 `html`, `report_command`에 `--open`)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `render_html` (Task 1)
- Produces:
  - `_reports(...)`가 `list[Path]`를 반환하도록 변경(기존 호출부는 반환값 무시)
  - `kompass.cli.open_in_browser(path: Path) -> bool` — `webbrowser.open(path.resolve().as_uri())` 결과. 테스트는 `monkeypatch.setattr(cli, "open_in_browser", ...)`로 교체.
- `--open` 옵션: `typer.Option(False, "--open", help="만든 HTML 보고서를 기본 브라우저로 엽니다.")`
- CLI 문구(정중체):
  - HTML 없음: `"--open은 HTML 보고서를 만들 때만 동작합니다 (--format html)."`
  - 열기 실패: stderr `"경고: 브라우저를 열지 못했습니다. 파일을 직접 여십시오: <경로>"`, 종료 코드 0

- [ ] **Step 1: 실패하는 테스트 작성** (`test_cli.py`의 `_scanned`/`_scan_args` 픽스처 재사용)

```python
def test_report_html_format(aws: None, store: Path) -> None:
    _scanned(store)
    result = runner.invoke(app, ["report", "--store", str(store), "--format", "html"])
    assert result.exit_code == 0, result.output
    [path] = (store / "123456789012").glob("*.html")
    assert extract_payload(path.read_text(encoding="utf-8"))["report"]["scan"]["account_id"] == "123456789012"

def test_report_open_calls_browser(aws: None, store: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[Path] = []
    monkeypatch.setattr(cli, "open_in_browser", lambda p: opened.append(p) or True)
    _scanned(store)
    assert runner.invoke(app, ["report", "--store", str(store), "--format", "html", "--open"]).exit_code == 0
    assert [p.suffix for p in opened] == [".html"]

def test_report_open_without_html_does_not_open(...) -> None:
    # --format md --open → open_in_browser 호출 0회, 출력에 "--open은 HTML 보고서를 만들 때만" 포함, exit 0

def test_report_open_failure_warns(...) -> None:
    # open_in_browser가 False → exit 0, stderr에 "브라우저를 열지 못했습니다"와 경로

def test_default_report_formats_unchanged(...) -> None:
    # 기존 test_report_default_formats가 계속 [".md", ".xlsx"]인지 — 기존 테스트로 충분하면 추가하지 않는다
```

- [ ] **Step 2: 실패 확인** — `uv run pytest tests/test_cli.py -k "html or open" -v` → FAIL (`html`은 잘못된 선택지)
- [ ] **Step 3: 구현** — 위 Interfaces대로. `scan`·`explain`·`investigate`·`review-evidence`의 `--report`는 `ReportFormat`을 공유하므로 자동으로 `html`을 받는다. 도움말 문자열 네 곳의 형식 목록만 고친다.
- [ ] **Step 4: 통과 확인** — `uv run pytest` 전체 PASS, 린트·mypy 통과
- [ ] **Step 5: 커밋** — `feat(cli): add html report format and report --open`

---

### Task 3: 화면 — 상단·탭·KISA·Finding 표

**Files:**
- Modify: `kompass/reporters/html/viewer.js`, `kompass/reporters/html/viewer.css`
- Test: `tests/reporters/test_html.py`

**Interfaces:**
- Consumes: 페이로드 구조 (Task 1). JS는 `payload.report`·`payload.labels`·`payload.rules`·`payload.display`만 읽는다.
- Produces (JS 내부, Task 4가 사용): `el(tag, attrs, ...children)` DOM 도우미(문자열 자식은 `document.createTextNode`), `openFinding(key)` 상세 패널 열기, `findingsByRule` 맵(`rule_id → Finding[]`), 탭 등록 `registerTab(id, title, render)`.
- 탭 id: `overview`, `kisa`, `findings`, `isms`, `evidence`. 해시 형식 `#tab=<id>`, `#finding=<encodeURIComponent(key)>`. key는 `${rule_id}:${region ?? "-"}:${resource}`(Python `Finding.key`와 같은 규칙).

이 태스크의 화면 범위 (스펙 3절):
- 상단 점검 정보·면책 문구, 요약 카드(KISA 항목 결과별·finding 상태별 개수), 경고 띠(`excluded_regions`, `skipped_rules`, ERROR 개수 — 해당할 때만)
- 탭 머리와 해시 연동. 알 수 없는 탭 id·finding key는 무시하고 `overview`.
- 개요: 결과가 FAIL·ERROR·REVIEW인 KISA 항목을 중요도(상>중>하)·결과(FAIL>ERROR>REVIEW) 순으로
- KISA 항목: 표 + 행 펼치면 finding 목록, 아래 "KISA 대응 항목이 없는 룰"(finding 중 `mappings.kisa` 빈 룰)·"건너뛴 룰"
- Finding: 표 + 필터(상태·중요도·서비스=룰 ID의 `-` 앞·리전·KISA 코드) + 검색(리소스·메시지 부분 일치, 대소문자 무시). 결과 0건이면 "조건에 맞는 결과 없음".
- finding 0건 보고서: 표 대신 "결과 없음"
- CSS: 상태별 색 배지, 긴 문자열 `overflow-wrap:anywhere`, 표 가로 스크롤

- [ ] **Step 1: Python 테스트 추가**

```python
def test_renders_report_without_findings() -> None:
    html = render_html(sample_report(skipped=("IAM-001",)))
    assert extract_payload(html)["report"]["findings"] == []

def test_payload_keeps_nested_evidence() -> None:
    deep = {"a": [{"b": [None, 1, {"2": "x" * 5000}]}]}
    report = sample_report(finding("S3-004", Status.FAIL, "b", "ap-northeast-2", "m", deep))
    assert extract_payload(render_html(report))["report"]["findings"][0]["evidence"] == deep
```

- [ ] **Step 2: 실행** — 새 테스트는 Task 1 구현으로 이미 통과할 수 있다. 통과하면 그대로 두고(회귀 방지) 다음 단계로 간다.
- [ ] **Step 3: `viewer.js`·`viewer.css` 구현** — 위 범위. 금지 API 테스트(Task 1)가 계속 통과해야 한다.
- [ ] **Step 4: 브라우저 확인** — `uv run python -c "from tests.reporters.sample import DEFAULT; from kompass.reporters.html_reporter import render_html; open(r'<scratchpad>/t3.html','w',encoding='utf-8').write(render_html(DEFAULT))"` 후 Playwright로 열어 확인: 탭 전환, 필터·검색, `#tab=kisa` 직접 열기, `#finding=<img>` 무시, 콘솔 오류·CSP 위반 0건.
- [ ] **Step 5: 전체 검사 후 커밋** — `feat(reporters): add HTML viewer summary, KISA and finding views`

---

### Task 4: 화면 — Finding 상세·해설·조사·ISMS-P·증적

**Files:**
- Modify: `kompass/reporters/html/viewer.js`, `kompass/reporters/html/viewer.css`
- Test: `tests/reporters/test_html.py`

**Interfaces:**
- Consumes: Task 3의 `el`, `openFinding`, `findingsByRule`, `registerTab`
- 해설 연결: `report.explanations.explanations[]` 중 `finding_keys`에 그 finding key가 있는 것. 리소스별 설명은 `explanation.resource_notes[].finding_key === key`. 조사: `report.investigations.investigations[]`의 `rule_id`가 같은 것.

이 태스크의 화면 범위 (스펙 3절):
- 상세 패널: 판정(상태·중요도·룰 ID와 제목·리소스·리전·수집 시각·메시지), 매핑(코드와 `kisa_verified`·`isms_p_verified`), 증적 JSON(`<details>` 안 `<pre>`에 `JSON.stringify(v, null, 2)`를 `textContent`로)
- AI 해설 (참고): 요약·위험·우선순위(라벨)·인용(scheme 라벨, 코드, 구절, 해설 `verified`·`problems`)·리소스별 설명·조치 절차·AWS CLI·Terraform(`<pre>`) + 안내 `labels.notices.explanation`과 "명령 실행은 사람이 판단"
- 추가 조사 (참고): 사실·근거 도구 호출 번호·메모 + `labels.notices.investigation`
- 개요 탭에 종합 위험 평가(있을 때): 시나리오(제목·영향 라벨)·조치 순서 + 검증 여부
- ISMS-P (초안) 탭: 고정 안내 띠 "ISMS-P 매핑은 원문 검증 전 초안임" + 표
- 증적 탭: 요청 목록(`labels.notices.evidence`, 미확인 그룹엔 `evidence_unverified`, 확인 대상 리소스는 `openFinding` 링크), 증적 검토(검토 문서·사실·부족한 점·추가 요청·실패·사람이 검토할 파일 + `labels.notices.evidence_review`)
- 해설·조사·증적 검토가 `null`이면 각 영역에 "해설 없음"·"추가 조사 없음"·"증적 검토 없음"
- LLM 영역 CSS: 별도 배경색 + "(참고)" 머리표

- [ ] **Step 1: Python 테스트 추가** — `tests/reporters/sample.py`의 해설·조사·증적 검토가 모두 붙은 샘플(이미 있는 `EXPLAINED` 등에서 세 가지를 붙인 것)로:

```python
def test_renders_full_report_with_llm_sections() -> None:
    payload = extract_payload(render_html(FULL))
    assert payload["report"]["explanations"] is not None
    assert payload["report"]["investigations"] is not None
    assert payload["report"]["evidence_reviews"] is not None
    assert "explanations_at" in payload["display"]
```

`FULL`이 sample.py에 없으면 sample.py에 `FULL = EXPLAINED.with_investigations(...).with_evidence_reviews(...)`로 추가한다(기존 도우미 사용).

- [ ] **Step 2: 실행** — 통과 확인
- [ ] **Step 3: `viewer.js`·`viewer.css` 구현** — 위 범위
- [ ] **Step 4: 브라우저 확인** — `FULL`로 HTML을 만들어 Playwright로 열기: 상세 패널의 해설·조사, 증적 탭 링크로 상세 열기, ISMS-P 안내 띠, `DEFAULT`(LLM 결과 없음)에서 "해설 없음" 표시, 콘솔 오류·CSP 위반 0건
- [ ] **Step 5: 전체 검사 후 커밋** — `feat(reporters): add HTML finding detail, LLM, ISMS-P and evidence views`

---

### Task 5: 공개 데모 시나리오와 생성 스크립트

**Files:**
- Create: `kompass/demo.py`
- Create: `scripts/build_demo.py`
- Create: `docs/demo/index.html` (생성물)
- Test: `tests/test_demo.py`

**Interfaces:**
- Consumes: `render_html`, `extract_payload` (Task 1), `build_report`, `load_mappings`
- Produces:
  - `kompass.demo.demo_report() -> AuditReport` — 결정적(같은 입력이면 같은 결과)
  - `kompass.demo.DEMO_PATH = Path("docs/demo/index.html")` (저장소 루트 기준, `project_root()`와 함께 사용)
  - `scripts/build_demo.py` — `render_html(demo_report())`를 `DEMO_PATH`에 쓰고 경로를 출력. 인자 없음.

시나리오 (스펙 5절):
- 계정 `123456789012`, 리전 `ap-northeast-2`·`us-east-1`, `excluded_regions={"ap-southeast-1": "가공: 리전 접근 거부"}`, 시각 `2026-11-01T01:00:00Z` 고정. `build_report` 결과의 `generated_at`을 `model_copy(update=...)`로 같은 고정 시각으로 바꾼다.
- finding: 서비스 IAM·S3·SG·VPC·CT·RDS·ELB에 걸쳐 FAIL·REVIEW·ERROR·PASS·N/A가 각각 1건 이상. 리소스는 `arn:aws:s3:::demo-public-assets`, `sg-0demo0000000001` 같은 가공 값. 증적은 실제 collector 키 모양을 흉내 낸 가공 dict.
- `skipped_rules`에 1개 이상
- 해설: FAIL 룰 2개 이상(1개는 `verified: false`와 `problems` 포함), 종합 위험 평가 포함. 인용 `quote`는 20자 이하의 짧은 구절.
- 추가 조사 1건 이상(도구 호출 2개 이상), 증적 검토 1건 이상(사람이 검토할 파일 1건 포함)
- 모델 이름 필드는 실제 값 형식(`claude-opus-5-5`)을 쓰되, `usage`는 가공 값

- [ ] **Step 1: 실패하는 테스트 작성**

```python
def test_demo_report_is_deterministic() -> None:
    assert render_html(demo_report()) == render_html(demo_report())

def test_demo_uses_example_account_only() -> None:
    report = demo_report()
    assert report.scan.account_id == "123456789012"
    assert {f.status for f in report.findings} >= set(Status)
    assert report.scan.excluded_regions and report.evaluation.skipped_rules
    assert report.explanations and report.explanations.assessment
    assert report.investigations and report.evidence_reviews

def test_demo_citations_are_short() -> None:
    for e in demo_report().explanations.explanations:
        assert all(len(c.quote) <= 20 for c in e.explanation.citations)

def test_demo_is_up_to_date() -> None:
    path = project_root() / DEMO_PATH
    assert path.read_text(encoding="utf-8") == render_html(demo_report()), (
        "docs/demo/index.html이 현재 리포터 출력과 다름. "
        "`uv run python scripts/build_demo.py`로 다시 생성 필요"
    )
```

- [ ] **Step 2: 실패 확인** — `uv run pytest tests/test_demo.py -v` → `ModuleNotFoundError: kompass.demo`
- [ ] **Step 3: `kompass/demo.py`·`scripts/build_demo.py` 구현** — 모듈 docstring에 "공개 데모용 가공 데이터, 실제 계정 데이터 아님"을 적는다. 파일은 `newline="\n"`으로 써서 Windows·CI에서 같은 바이트가 되게 하고, `.gitattributes`에 `docs/demo/index.html -text`를 추가해 줄바꿈 변환을 막는다.
- [ ] **Step 4: 생성·통과 확인** — `uv run python scripts/build_demo.py` 후 `uv run pytest` 전체 PASS
- [ ] **Step 5: 브라우저 확인과 화면 캡처** — Playwright로 `docs/demo/index.html`을 열어 Task 3·4 확인 항목 전체, Review Focus 1~4 확인. 개요·KISA·Finding 상세 화면을 `docs/images/viewer-*.png`로 저장
- [ ] **Step 6: 커밋** — `feat(demo): add synthetic public demo of the HTML viewer`

---

### Task 6: 문서 갱신

**Files:**
- Modify: `docs/DECISIONS.md` (ADR-055 추가)
- Modify: `docs/PLAN.md` (5단계 "다음 작업"에 항목과 하위 체크박스, 완료 표시)
- Modify: `docs/MANUAL.md` (보고서 형식 절에 `html`, `--open`, "HTML에는 마스킹하지 않은 원본이 들어 있어 외부 전달은 사람이 판단")
- Modify: `docs/ARCHITECTURE.md` (리포터 목록에 HTML, `kompass/demo.py`)
- Modify: `README.md` (출력 예시 아래 데모 링크 `https://zelopy.github.io/kompass-isms/demo/`와 저장소 경로 `docs/demo/index.html`, 화면 이미지 1장, 문서 표는 그대로)
- Modify: `docs/PORTFOLIO.md` (데모 링크 한 줄. 문체는 개조식). `docs/PORTFOLIO.pdf` 재생성은 하지 않고 사용자에게 알린다.

ADR-055 내용: 맥락(사용 편의·시연), 결정(파일 하나 HTML, 순수 JS, 새 의존성 없음, `textContent`만·JSON 이스케이프·해시 CSP, 라벨은 `_format.py` 공유, 공개 데모는 가공 데이터만·동기화 테스트), 미룬 것(로컬 서버, 실행 마법사, 점검 이력 목록, 다크 모드·인쇄·차트), 결과(GitHub Pages는 사용자가 `/docs`로 켬).

- [ ] **Step 1: 문서 수정** — 문체 규칙(Global Constraints) 준수. 기존 문서의 표·절 형식을 따른다.
- [ ] **Step 2: 확인** — `uv run pytest` (문서 대조 테스트 포함) 전체 PASS, 링크한 이미지 파일 존재
- [ ] **Step 3: 커밋** — `docs: record ADR-055 and document the HTML viewer`
