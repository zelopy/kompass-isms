"""collector 공용 부품.

`CallRecorder`는 AWS 호출을 감싸서 결과를 세 가지로 나눈다.
- 정상 응답: 응답 dict (`ResponseMetadata` 제외)
- 설정 없음(collector가 지정한 오류 코드, 예: `NoSuchBucketPolicy`): `Absent`.
  오류가 아니라 데이터다
- 그 외 실패(권한 오류, 연결 실패, 호출 제한 등): `CollectError`로 기록하고 `None`.
  룰은 이 기록을 보고 ERROR finding을 낸다 (ADR-005)

다음은 리소스 단위 실패가 아니므로 기록하지 않는다.
- 세션 전체 실패(자격증명 만료·무효, 자격증명 없음): `SessionError`로 실행을 중단한다 (ADR-021).
  호출마다 ERROR로 쌓으면 보고서 전체가 "확인 불가"로 채워질 뿐이다
- kompass 코드 버그: 잡지 않고 그대로 실행을 중단시킨다
  - `ReadOnlyViolation`: 가드 위반 (botocore 예외가 아니라서 여기서 잡히지 않는다)
  - `ParamValidationError`: 잘못된 호출 파라미터
  - `OperationNotPageableError`, 응답 형식에 없는 `result_key`: 잘못된 paginate 사용

`absent_codes` 주의: 같은 오류 코드가 다른 상황에서도 나올 수 있다. 예를 들어
`iam:GetLoginProfile`의 `NoSuchEntity`는 "콘솔 비밀번호 없음"과 "사용자 자체가 없음"
(목록 조회 직후 삭제) 모두에서 나온다. collector는 호출마다 이 코드가 정말 "설정 없음"만
뜻하는지 확인하고 지정한다.
"""

from collections.abc import Collection
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ParamValidationError

from kompass.aws.session import ScanContext, SessionError
from kompass.models import CollectError, Snapshot

_GLOBAL_REGION = "aws-global"
_RESPONSE_METADATA = "ResponseMetadata"

# 리소스가 아니라 세션 전체가 쓸 수 없게 된 상태를 뜻하는 오류 코드
SESSION_WIDE_ERROR_CODES = frozenset(
    {
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidClientTokenId",
        "UnrecognizedClientException",
        "SignatureDoesNotMatch",
    }
)


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
            self._handle_client_error(client, method, resource, code, exc)
            return None
        except ParamValidationError:
            raise
        except BotoCoreError as exc:
            self._handle_botocore_error(client, method, resource, exc)
            return None
        return {k: v for k, v in response.items() if k != _RESPONSE_METADATA}

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
        # 호출 전에 사용법을 검증한다. 페이지 조회가 안 되는 API면 여기서 예외가 나고,
        # result_key 오타는 빈 목록("리소스 없음")으로 둔갑하므로 응답 형식과 대조한다
        paginator = client.get_paginator(method)
        _require_output_member(client, method, result_key)

        items: list[Any] = []
        try:
            for page in paginator.paginate(**params):
                items.extend(page.get(result_key, []))
        except ClientError as exc:
            self._handle_client_error(client, method, resource, _error_code(exc), exc)
            return None
        except ParamValidationError:
            raise
        except BotoCoreError as exc:
            self._handle_botocore_error(client, method, resource, exc)
            return None
        return items

    def _handle_client_error(
        self, client: Any, method: str, resource: str | None, code: str, exc: ClientError
    ) -> None:
        if code in SESSION_WIDE_ERROR_CODES:
            _abort(client, method, code, exc)
        self._record(client, method, resource, code, str(exc))

    def _handle_botocore_error(
        self, client: Any, method: str, resource: str | None, exc: BotoCoreError
    ) -> None:
        if isinstance(exc, NoCredentialsError):
            _abort(client, method, type(exc).__name__, exc)
        self._record(client, method, resource, type(exc).__name__, str(exc))

    def _record(
        self, client: Any, method: str, resource: str | None, error_code: str, message: str
    ) -> None:
        region = client.meta.region_name
        self._errors.append(
            CollectError(
                operation=_operation_name(client, method),
                region=None if region == _GLOBAL_REGION else region,
                error_code=error_code,
                message=message,
                resource=resource,
            )
        )


def _operation_name(client: Any, method: str) -> str:
    meta = client.meta
    return f"{meta.service_model.service_name}:{meta.method_to_api_mapping[method]}"


def _require_output_member(client: Any, method: str, result_key: str) -> None:
    meta = client.meta
    operation = meta.service_model.operation_model(meta.method_to_api_mapping[method])
    members = operation.output_shape.members if operation.output_shape else {}
    if result_key not in members:
        raise ValueError(
            f"{_operation_name(client, method)} 응답에 {result_key!r} 필드가 없다. "
            f"가능한 필드: {', '.join(sorted(members))}"
        )


def _abort(client: Any, method: str, code: str, exc: Exception) -> NoReturn:
    raise SessionError(
        f"점검 중 자격증명을 쓸 수 없게 되었다 ({code}, {_operation_name(client, method)}). "
        "자격증명을 갱신한 뒤 다시 실행해야 한다"
    ) from exc


def _error_code(exc: ClientError) -> str:
    code: str = exc.response.get("Error", {}).get("Code", "Unknown")
    return code
