"""실습 환경 통합 테스트: 실제 실습 계정을 스캔해 lab/expected.yaml과 대조한다.

기본 `pytest` 실행에서는 제외된다(`lab` 마커). 실행: `uv run pytest -m lab`
- 실습 전용 계정에 `lab/` Terraform이 배포되어 있어야 한다.
- 점검 프로필(기본 `kompass-lab-audit`, `KOMPASS_LAB_PROFILE`로 변경)이 필요하다.
- 호출은 읽기 전용 가드를 거친다. 스냅샷과 결과는 임시 디렉터리에만 남는다.
- `when`이 있는 기대값은 `lab/terraform.tfvars`(없으면 변수 기본값)의 선택 변수가 맞을 때만 대조한다.
"""

import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from kompass.aws.session import open_scan
from kompass.config import Settings
from kompass.models import Finding, Snapshot
from kompass.pipeline import collect, evaluate_scan
from kompass.snapshots import SnapshotStore, load_scan

LAB = Path(__file__).parents[2] / "lab"
EXPECTED = LAB / "expected.yaml"
# expected.yaml의 when에 쓰는 선택 변수와 기본값 (lab/variables.tf)
LAB_FLAGS = {"enable_public_rds": False, "enable_guardduty": False}
_TFVAR = re.compile(r"^\s*(\w+)\s*=\s*(true|false)\b", re.M)
_BUCKET_SUFFIX = re.compile(r"-[0-9a-f]{8}$")
NONE = "NONE"

pytestmark = pytest.mark.lab


def _tag_name(item: dict[str, Any]) -> str | None:
    return next((t["Value"] for t in item.get("Tags", []) if t["Key"] == "Name"), None)


class _Labeler:
    """배포마다 바뀌는 리소스 ID를 expected.yaml의 이름표로 바꾼다."""

    def __init__(self, snapshots: dict[str, Snapshot]):
        self._ec2: dict[str, str] = {}
        ec2 = snapshots.get("ec2")
        for region in (ec2.data["regions"].values() if ec2 else []):
            vpc_names = {
                v["VpcId"]: _tag_name(v) or "default-vpc" for v in region.get("vpcs", [])
            }
            self._ec2.update(vpc_names)
            for group in region.get("security_groups", []):
                name = group["GroupName"]
                if name == "default":
                    name = f"default@{vpc_names.get(group['VpcId'], group['VpcId'])}"
                self._ec2[group["GroupId"]] = name
            for interface in region.get("network_interfaces", []):
                self._ec2[interface["NetworkInterfaceId"]] = interface.get("Description", "")

    def __call__(self, finding: Finding) -> str:
        resource = finding.resource
        if resource == "account":
            return resource
        if finding.rule_id.startswith(("SG-", "VPC-")):
            return self._ec2.get(resource, resource)
        if finding.rule_id.startswith("S3-") or finding.rule_id == "CT-002":
            return _BUCKET_SUFFIX.sub("", resource)
        if resource.startswith("arn:"):
            label = resource.split(":", 5)[5]
            return label.removeprefix("user/")
        return resource


def _compare(findings: tuple[Finding, ...], labeler: _Labeler, expected: list[dict[str, str]]) -> list[str]:
    actual: dict[tuple[str, str], list[str]] = {}
    for finding in findings:
        actual.setdefault((finding.rule_id, labeler(finding)), []).append(finding.status.value)
    problems: list[str] = []
    for item in expected:
        key = (item["rule"], item["resource"])
        got = actual.get(key, [])
        want = item["status"]
        if want == NONE:
            if got:
                problems.append(f"{key}: finding이 없어야 하는데 {got}")
        elif got != [want]:
            problems.append(f"{key}: 기대 {want}, 실제 {got or '없음'}")
    return problems


def lab_flags(tfvars: Path = LAB / "terraform.tfvars") -> dict[str, bool]:
    """배포에 쓴 선택 변수 값. 파일이 없거나 값이 없으면 기본값."""
    flags = dict(LAB_FLAGS)
    if tfvars.is_file():
        for name, value in _TFVAR.findall(tfvars.read_text(encoding="utf-8")):
            if name in flags:
                flags[name] = value == "true"
    return flags


def applicable(items: list[dict[str, Any]], flags: dict[str, bool]) -> list[dict[str, Any]]:
    return [i for i in items if all(flags.get(k) == v for k, v in i.get("when", {}).items())]


@pytest.fixture(scope="module")
def expected() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(EXPECTED.read_text(encoding="utf-8"))
    return data


def test_lab_scan_matches_expected(expected: dict[str, Any], tmp_path: Path) -> None:
    profile = os.environ.get("KOMPASS_LAB_PROFILE", expected["profile"])
    scan = open_scan(profile=profile, regions=expected["regions"])
    store = SnapshotStore(tmp_path / "reports")

    result = collect(scan, store)
    _, snapshots = load_scan(result.scan_path)
    _, report = evaluate_scan(result.scan_path, Settings())

    collect_errors = {s: [e.operation for e in snap.errors] for s, snap in snapshots.items()}
    assert all(not ops for ops in collect_errors.values()), f"수집 실패: {collect_errors}"
    assert report.skipped_rules == ()

    items = applicable(expected["expectations"], lab_flags())
    problems = _compare(report.findings, _Labeler(snapshots), items)
    assert not problems, "기대 결과와 다르다:\n" + "\n".join(problems)
