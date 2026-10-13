"""collector 공용 부품.

`CallRecorder`는 AWS 호출을 감싸서 결과를 세 가지로 나눈다.
- 정상 응답: 응답 dict
- 설정 없음(collector가 지정한 오류 코드, 예: `NoSuchBucketPolicy`): `Absent`.
  오류가 아니라 데이터다
- 그 외 실패(권한 오류, 연결 실패, 호출 제한 등): `CollectError`로 기록하고 `None`.
  룰은 이 기록을 보고 ERROR finding을 낸다 (ADR-005)

다음은 잡지 않고 실행을 중단시킨다. 수집 실패가 아니라 kompass 코드 버그이기 때문이다.
- `ReadOnlyViolation`: 가드 위반 (botocore 예외가 아니라서 여기서 잡히지 않는다)
- `ParamValidationError`: 잘못된 호출 파라미터
"""

from collections.abc import Collection
from dataclasses import dataclass
from typing import Any, Protocol

from botocore.exceptions import BotoCoreError, ClientError, ParamValidationError

from kompass.aws.session import ScanContext
from kompass.models import CollectError, Snapshot

_GLOBAL_REGION = "aws-global"


class Collector(Protocol):
    """서비스 하나의 설정을 수집해 스냅샷을 만든다."""

    service: str

    def collect(self, scan: ScanContext) -> Snapshot: ...


@dataclass(frozen=True)
class Absent:
    """ "설정 없음"을 뜻하는 오류 응답. 예: 비밀번호 정책 `NoSuchEntity`."""

    error_code: str


class CallRecorder:
    """collector 실행 한 번 동안의 AWS 호출과 수집 실패를 기록한다."""

    def __init__(self) -> None:
        self._errors: list[CollectError] = []

    @property
    def errors(self) -> list[CollectError]:
        return list(self._errors)

    def call(
        self,
        client: Any,
        method: str,
        *,
        resource: str | None = None,
        absent_codes: Collection[str] = frozenset(),
        **params: Any,
    ) -> dict[str, Any] | Absent | None:
        """API를 한 번 호출한다. 실패하면 기록하고 None을 돌려준다."""
        try:
            response: dict[str, Any] = getattr(client, method)(**params)
        except ClientError as exc:
            code = _error_code(exc)
            if code in absent_codes:
                return Absent(code)
            self._record(client, method, resource, code, str(exc))
            return None
        except ParamValidationError:
            raise
        except BotoCoreError as exc:
            self._record(client, method, resource, type(exc).__name__, str(exc))
            return None
        return response

    def paginate(
        self,
        client: Any,
        method: str,
        result_key: str,
        *,
        resource: str | None = None,
        **params: Any,
    ) -> list[Any] | None:
        """모든 페이지의 `result_key` 항목을 모은다.

        중간 페이지에서 실패하면 이미 받은 페이지도 버리고 None을 돌려준다. 목록 일부만 보고
        "해당 리소스 없음"으로 판정하는 일을 막기 위해서다.
        """
        items: list[Any] = []
        try:
            for page in client.get_paginator(method).paginate(**params):
                items.extend(page.get(result_key, []))
        except ClientError as exc:
            self._record(client, method, resource, _error_code(exc), str(exc))
            return None
        except ParamValidationError:
            raise
        except BotoCoreError as exc:
            self._record(client, method, resource, type(exc).__name__, str(exc))
            return None
        return items

    def _record(
        self, client: Any, method: str, resource: str | None, error_code: str, message: str
    ) -> None:
        meta = client.meta
        region = meta.region_name
        self._errors.append(
            CollectError(
                operation=f"{meta.service_model.service_name}:{meta.method_to_api_mapping[method]}",
                region=None if region == _GLOBAL_REGION else region,
                error_code=error_code,
                message=message,
                resource=resource,
            )
        )


def _error_code(exc: ClientError) -> str:
    code: str = exc.response.get("Error", {}).get("Code", "Unknown")
    return code
