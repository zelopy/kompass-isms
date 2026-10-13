"""kompass 명령줄 진입점.

0단계에서는 하위 명령 없이 골격만 둔다. `collect`, `evaluate`, `scan`은 1단계에서 추가한다.
"""

from importlib.metadata import version

import typer

app = typer.Typer(
    name="kompass",
    help="AWS 계정을 읽기 전용으로 점검해 KISA·ISMS-P 기준 보고서를 만든다.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"kompass {version('kompass-isms')}")
        raise typer.Exit()


@app.callback()
def main(
    show_version: bool = typer.Option(
        False,
        "--version",
        help="버전을 출력하고 종료한다.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """AWS 계정을 읽기 전용으로 점검해 KISA·ISMS-P 기준 보고서를 만든다."""
