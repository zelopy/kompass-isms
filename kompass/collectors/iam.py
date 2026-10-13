"""IAM collector (IAM-001~009).

수집 데이터 (`Snapshot.data`). 값이 None이면 "설정 없음", 키가 없으면 "수집 실패"다.
- `account_summary`: `GetAccountSummary`의 `SummaryMap`
- `password_policy`: 비밀번호 정책. 정책이 없으면(`NoSuchEntity`) None
- `credential_report`: `generated_time`과 `rows`(CSV 행을 문자열 그대로 담은 dict 목록)
- `authorization_details`: `users`, `groups`, `roles`, `policies`. 관리형 정책은 기본 버전
  본문(`Document`)만 남긴다. 정책은 ARN으로 찾는다 (moto는 `PolicyName`을 주지 않는다)
- `saml_providers`, `oidc_providers`: 외부 자격증명 공급자
- `identity_center_instances.<리전>`: Identity Center 인스턴스. 인스턴스는 한 리전에만 있으므로
  `--regions`가 아니라 활성 리전 전체에서 조회한다

자격증명 보고서는 생성이 끝날 때까지 기다린다(기본 최대 60초). 시간 안에 끝나지 않으면
`ReportGenerationTimeout`으로 기록한다.
"""

import csv
import io
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from kompass.aws.session import ScanContext
from kompass.collectors.base import Absent, CallRecorder
from kompass.models import Snapshot

_REPORT_COMPLETE = "COMPLETE"
_AUTH_KEYS = {
    "UserDetailList": "users",
    "GroupDetailList": "groups",
    "RoleDetailList": "roles",
    "Policies": "policies",
}


def _slim_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """관리형 정책에서 기본 버전 본문만 남긴다."""
    default = next(
        (v for v in policy.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None
    )
    slim = {k: v for k, v in policy.items() if k != "PolicyVersionList"}
    slim["Document"] = None if default is None else default.get("Document")
    return slim


class IamCollector:
    service = "iam"

    def __init__(
        self,
        sleep: Callable[[float], None] = time.sleep,
        report_timeout: float = 60.0,
        poll_interval: float = 2.0,
    ):
        self._sleep = sleep
        self._report_timeout = report_timeout
        self._poll_interval = poll_interval

    def collect(self, scan: ScanContext) -> Snapshot:
        collected_at = datetime.now(UTC)
        recorder = CallRecorder()
        iam = scan.session.client("iam")
        data: dict[str, Any] = {}

        summary = recorder.call(iam, "get_account_summary")
        if isinstance(summary, dict):
            data["account_summary"] = summary["SummaryMap"]

        policy = recorder.call(iam, "get_account_password_policy", absent_codes={"NoSuchEntity"})
        if isinstance(policy, Absent):
            data["password_policy"] = None
        elif policy is not None:
            data["password_policy"] = policy["PasswordPolicy"]

        report = self._credential_report(recorder, iam)
        if report is not None:
            data["credential_report"] = report

        details = recorder.paginate_keys(
            iam, "get_account_authorization_details", tuple(_AUTH_KEYS)
        )
        if details is not None:
            authorization = {name: details[key] for key, name in _AUTH_KEYS.items()}
            authorization["policies"] = [_slim_policy(p) for p in authorization["policies"]]
            data["authorization_details"] = authorization

        saml = recorder.call(iam, "list_saml_providers")
        if isinstance(saml, dict):
            data["saml_providers"] = saml["SAMLProviderList"]
        oidc = recorder.call(iam, "list_open_id_connect_providers")
        if isinstance(oidc, dict):
            data["oidc_providers"] = oidc["OpenIDConnectProviderList"]

        instances: dict[str, Any] = {}
        for region in scan.enabled_regions or scan.regions:
            client = scan.session.client("sso-admin", region_name=region)
            found = recorder.paginate(client, "list_instances", "Instances")
            if found is not None:
                instances[region] = found
        data["identity_center_instances"] = instances

        return Snapshot(
            service=self.service,
            account_id=scan.account_id,
            regions=scan.enabled_regions or scan.regions,
            collected_at=collected_at,
            data=data,
            errors=tuple(recorder.errors),
        )

    def _credential_report(self, recorder: CallRecorder, iam: Any) -> dict[str, Any] | None:
        attempts = max(1, int(self._report_timeout / self._poll_interval))
        for attempt in range(attempts):
            generated = recorder.call(iam, "generate_credential_report")
            if not isinstance(generated, dict):
                return None
            if generated.get("State") == _REPORT_COMPLETE:
                break
            if attempt < attempts - 1:
                self._sleep(self._poll_interval)
        else:
            recorder.record_failure(
                iam,
                "generate_credential_report",
                "ReportGenerationTimeout",
                f"자격증명 보고서가 {self._report_timeout:.0f}초 안에 생성되지 않았다",
            )
            return None

        fetched = recorder.call(iam, "get_credential_report")
        if not isinstance(fetched, dict):
            return None
        content = fetched["Content"].decode("utf-8")
        return {
            "generated_time": fetched["GeneratedTime"],
            "rows": list(csv.DictReader(io.StringIO(content))),
        }
