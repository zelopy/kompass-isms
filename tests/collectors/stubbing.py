"""collector 테스트 도구: 특정 client만 Stubber를 붙인 것으로 바꿔치기한다."""

from typing import Any


class StubbingSession:
    """지정한 (서비스, 리전)만 미리 만든 client를 돌려주고 나머지는 실제 세션에 맡긴다."""

    def __init__(self, session: Any, overrides: dict[tuple[str, str | None], Any]):
        self._session = session
        self._overrides = overrides

    def client(self, service: str, region_name: str | None = None, **kwargs: Any) -> Any:
        override = self._overrides.get((service, region_name))
        if override is not None:
            return override
        return self._session.client(service, region_name=region_name, **kwargs)
