"""IAM collector 테스트.

moto 특성: 자격증명 보고서에 루트 행이 없고, 정책 항목에 `PolicyName`이 없으며, 리전마다
Identity Center 인스턴스를 하나씩 기본으로 만든다.
"""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from kompass.aws.guard import read_only_session
from kompass.aws.session import ScanContext
from kompass.collectors.base import CallRecorder
from kompass.collectors.iam import IamCollector
from kompass.snapshots import SnapshotStore, load_scan
from tests.collectors.stubbing import StubbingSession

ACCOUNT = "123456789012"
HOME = "ap-northeast-2"
ADMIN = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
)
DENY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
)


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


@pytest.fixture
def setup(aws: None) -> Any:
    """테스트 데이터 준비용 IAM client. 가드가 없다."""
    return boto3.client("iam")


def _scan(session: Any = None, enabled: tuple[str, ...] = (HOME,)) -> ScanContext:
    return ScanContext(
        session=session or read_only_session(),
        account_id=ACCOUNT,
        partition="aws",
        caller_arn=f"arn:aws:iam::{ACCOUNT}:user/security_manager",
        home_region=HOME,
        regions=(HOME,),
        enabled_regions=enabled,
    )


def _no_sleep(_: float) -> None:
    pass


def _collect(scan: ScanContext | None = None) -> Any:
    return IamCollector(sleep=_no_sleep).collect(scan or _scan())


# --- 정상 경로 ---


def test_collects_all_sections(setup: Any) -> None:
    setup.create_user(UserName="console")
    setup.create_login_profile(UserName="console", Password="Passw0rd!long")
    setup.create_open_id_connect_provider(
        Url="https://token.actions.githubusercontent.com", ClientIDList=["sts.amazonaws.com"]
    )
    snapshot = _collect()

    assert snapshot.service == "iam"
    assert snapshot.errors == ()
    data = snapshot.data
    assert "AccountMFAEnabled" in data["account_summary"]
    assert data["password_policy"] is None  # NoSuchEntity → 설정 없음
    rows = data["credential_report"]["rows"]
    assert [r["user"] for r in rows] == ["console"]
    assert rows[0]["password_enabled"] == "true"
    assert data["credential_report"]["generated_time"].endswith("Z")
    assert [u["UserName"] for u in data["authorization_details"]["users"]] == ["console"]
    assert data["saml_providers"] == []
    assert len(data["oidc_providers"]) == 1
    assert set(data["identity_center_instances"]) == {HOME}


def test_password_policy_present(setup: Any) -> None:
    setup.update_account_password_policy(MinimumPasswordLength=12, RequireSymbols=True)
    policy = _collect().data["password_policy"]
    assert policy["MinimumPasswordLength"] == 12
    assert policy["RequireSymbols"] is True


def test_managed_policies_keep_only_default_version(setup: Any) -> None:
    arn = setup.create_policy(PolicyName="p", PolicyDocument=ADMIN)["Policy"]["Arn"]
    setup.create_policy_version(PolicyArn=arn, PolicyDocument=DENY, SetAsDefault=True)
    setup.create_user(UserName="u")
    setup.attach_user_policy(UserName="u", PolicyArn=arn)

    [policy] = [p for p in _collect().data["authorization_details"]["policies"] if p["Arn"] == arn]
    assert policy["DefaultVersionId"] == "v2"
    assert policy["Document"]["Statement"][0]["Effect"] == "Deny"
    assert "PolicyVersionList" not in policy


def test_identity_center_queried_in_all_enabled_regions(setup: Any) -> None:
    # 점검 리전(--regions)이 아니라 활성 리전 전체에서 조회한다 (Identity Center는 한 리전에만 있다)
    snapshot = _collect(_scan(enabled=(HOME, "us-east-1")))
    assert set(snapshot.data["identity_center_instances"]) == {HOME, "us-east-1"}


def test_snapshot_round_trips_through_store(setup: Any, tmp_path: Path) -> None:
    setup.create_user(UserName="u")
    scan = _scan()
    snapshot = _collect(scan)
    writer = SnapshotStore(tmp_path / ".kompass").begin(scan)
    writer.write(snapshot)
    assert load_scan(writer.finish())[1]["iam"] == snapshot


# --- 자격증명 보고서 ---


def _report_stub(client: Any, states: list[str], *, report: bool = True) -> Stubber:
    stub = Stubber(client)
    for state in states:
        stub.add_response("generate_credential_report", {"State": state})
    if report:
        stub.add_response(
            "get_credential_report",
            {
                "Content": (
                    b"user,arn,password_enabled\n"
                    b"<root_account>,arn:aws:iam::123456789012:root,not_supported\n"
                ),
                "ReportFormat": "text/csv",
                "GeneratedTime": "2026-10-13T12:00:00Z",
            },
        )
    return stub


class _ReportOnlyCollector(IamCollector):
    """보고서 수집만 따로 검증한다."""

    def collect_report(self, client: Any) -> tuple[Any, Any]:
        recorder = CallRecorder()
        return self._credential_report(recorder, client), recorder.errors


def test_report_waits_until_complete(aws: None) -> None:
    client = read_only_session().client("iam")
    sleeps: list[float] = []
    collector = _ReportOnlyCollector(sleep=sleeps.append, poll_interval=2.0)
    with _report_stub(client, ["STARTED", "INPROGRESS", "COMPLETE"]):
        report, errors = collector.collect_report(client)
    assert errors == []
    assert sleeps == [2.0, 2.0]
    assert report["rows"][0]["user"] == "<root_account>"
    assert report["generated_time"] == "2026-10-13T12:00:00Z"


def test_report_timeout_is_recorded(aws: None) -> None:
    client = read_only_session().client("iam")
    collector = _ReportOnlyCollector(sleep=_no_sleep, report_timeout=6.0, poll_interval=2.0)
    with _report_stub(client, ["STARTED", "STARTED", "STARTED"], report=False):
        report, errors = collector.collect_report(client)
    assert report is None
    [error] = errors
    assert error.error_code == "ReportGenerationTimeout"
    assert error.operation == "iam:GenerateCredentialReport"


def test_report_failure_leaves_section_missing(aws: None) -> None:
    session = read_only_session()
    client = session.client("iam")
    real = session.client("iam")
    with Stubber(client) as stub:
        stub.add_response(
            "get_account_summary", {"SummaryMap": real.get_account_summary()["SummaryMap"]}
        )
        stub.add_client_error("get_account_password_policy", service_error_code="NoSuchEntity")
        stub.add_client_error("generate_credential_report", service_error_code="AccessDenied")
        stub.add_response(
            "get_account_authorization_details",
            {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []},
        )
        stub.add_response("list_saml_providers", {"SAMLProviderList": []})
        stub.add_response("list_open_id_connect_providers", {"OpenIDConnectProviderList": []})
        snapshot = _collect(_scan(StubbingSession(session, {("iam", None): client})))

    assert "credential_report" not in snapshot.data
    assert snapshot.data["password_policy"] is None
    [error] = snapshot.errors
    assert error.operation == "iam:GenerateCredentialReport"


# --- 오류 경로 ---


def test_identity_center_region_failure_is_missing(setup: Any) -> None:
    session = read_only_session()
    client = session.client("sso-admin", region_name="us-east-1")
    with Stubber(client) as stub:
        stub.add_client_error("list_instances", service_error_code="AccessDeniedException")
        snapshot = _collect(
            _scan(
                StubbingSession(session, {("sso-admin", "us-east-1"): client}),
                enabled=(HOME, "us-east-1"),
            )
        )
    assert set(snapshot.data["identity_center_instances"]) == {HOME}
    [error] = snapshot.errors
    assert error.operation == "sso-admin:ListInstances"
    assert error.region == "us-east-1"
