"""읽기 전용 가드 (CLAUDE.md 원칙 2, ADR-004).

boto3 세션에 botocore `before-call` 이벤트 훅을 등록해, 허용 목록에 없는 오퍼레이션은
요청이 나가기 전에 `ReadOnlyViolation`으로 막는다. paginator, waiter, resource API도
모두 같은 경로를 거치므로 함께 막힌다.

botocore client는 생성 시점의 이벤트 훅만 복사해 간다. 이미 있는 세션에 나중에 가드를
걸면 그 전에 만든 client는 보호되지 않는다. 그래서 가드를 "설치"하는 함수는 두지 않고,
세션 생성과 가드 등록을 한 번에 하는 `read_only_session()`만 제공한다.
"""

from typing import Any

import boto3

_ALLOWED_PREFIXES = ("Describe", "Get", "List")
_ALLOWED_OPERATIONS = frozenset({"GenerateCredentialReport"})
_HANDLER_ID = "kompass-read-only-guard"


class ReadOnlyViolation(Exception):
    """읽기 전용이 아닌 AWS 오퍼레이션 호출.

    botocore의 ClientError·BotoCoreError를 상속하지 않는다. collector가 수집 실패를 잡아
    ERROR로 기록할 때 가드 위반까지 함께 삼키지 않도록 하기 위해서다.
    """

    def __init__(self, service: str, operation: str) -> None:
        self.service = service
        self.operation = operation
        super().__init__(f"읽기 전용 가드가 {service}:{operation} 호출을 차단했다")


def is_read_only_operation(operation: str) -> bool:
    """오퍼레이션 이름이 허용 목록에 있는지 판별한다. 대소문자를 구분한다."""
    return operation.startswith(_ALLOWED_PREFIXES) or operation in _ALLOWED_OPERATIONS


def _block_non_read_only(model: Any, **_: Any) -> None:
    if not is_read_only_operation(model.name):
        raise ReadOnlyViolation(model.service_model.service_name, model.name)


def read_only_session(**session_kwargs: Any) -> Any:
    """가드가 걸린 boto3 세션을 만든다. 인자는 `boto3.Session`과 같다.

    collector와 에이전트 도구는 이 함수로 만든 세션만 쓴다.
    """
    session = boto3.Session(**session_kwargs)
    session.events.register("before-call", _block_non_read_only, unique_id=_HANDLER_ID)
    return session
