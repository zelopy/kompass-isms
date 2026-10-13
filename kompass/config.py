"""판정 기준값 설정 (`kompass.yaml`).

기본값은 일반적인 권고 수준이다. 조직 기준이 다르면 `kompass.yaml`로 바꾼다 (ADR-017).
보고서에는 적용한 기준값을 함께 표시한다. 항목은 그 값을 쓰는 룰을 구현할 때 추가한다.
"""

from pydantic import BaseModel, ConfigDict


class _Section(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CloudTrailSettings(_Section):
    # true면 관리 이벤트를 읽기·쓰기 모두 기록해야 CT-001 PASS
    require_read_events: bool = True


class Settings(_Section):
    cloudtrail: CloudTrailSettings = CloudTrailSettings()
