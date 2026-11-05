"""공개 데모 HTML을 만든다 (ADR-055). 결과: docs/demo/index.html

    uv run python scripts/build_demo.py

가공 시나리오(`kompass/demo.py`)만 쓰며 AWS·LLM·원문 색인을 읽지 않는다. 리포터나 매핑 데이터를
바꾸면 다시 실행해 커밋한다. 다르면 `tests/test_demo.py`가 실패한다.
"""

from pathlib import Path

from kompass.demo import DEMO_PATH, demo_report
from kompass.reporters.html_reporter import render_html

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    path = ROOT / DEMO_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    # 운영체제와 관계없이 같은 바이트가 되도록 LF로 쓴다 (.gitattributes도 eol=lf)
    with path.open("w", encoding="utf-8", newline="\n") as file:
        file.write(render_html(demo_report()))
    print(f"데모: {path}")


if __name__ == "__main__":
    main()
