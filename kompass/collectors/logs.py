"""CloudWatch Logs collector: 로그 그룹 보존 기간과 보안 로그 대상 그룹 (LOG-001, ADR-043).

수집 데이터 (`Snapshot.data`):
- `regions.<리전>.log_groups`: `DescribeLogGroups` 결과. 보존 기간이 없으면(영구 보관)
  `retentionInDays` 키가 없다.
- `regions.<리전>.flow_log_groups`: 그 리전의 VPC 흐름 로그 중 CloudWatch Logs로 보내는 것의
  `{"flow_log_id", "log_group"}` 목록.
- `trail_log_groups`: CloudTrail 추적(섀도 추적 포함) 중 CloudWatch Logs로 보내는 것의
  `{"trail", "log_group_arn"}` 목록. 계정 단위로 기본 리전에서 한 번 조회한다.
수집에 실패한 종류는 키가 없다. 어떤 로그 그룹이 보안 로그인지 알려면 다른 서비스 설정이
필요하지만 룰은 스냅샷 하나만 보므로(ADR-015) 이 스냅샷에 함께 담는다.
"""

from datetime import UTC, datetime
from typing import Any

from kompass.aws.session import ScanContext
from kompass.collectors.base import CallRecorder
from kompass.models import Snapshot

_CLOUDWATCH_LOGS = "cloud-watch-logs"


class LogsCollector:
    service = "logs"

    def collect(self, scan: ScanContext) -> Snapshot:
        collected_at = datetime.now(UTC)
        recorder = CallRecorder()
        data: dict[str, Any] = {}

        cloudtrail = scan.session.client("cloudtrail", region_name=scan.home_region)
        described = recorder.call(cloudtrail, "describe_trails", includeShadowTrails=True)
        if isinstance(described, dict):
            data["trail_log_groups"] = [
                {"trail": t.get("Name"), "log_group_arn": t["CloudWatchLogsLogGroupArn"]}
                for t in described.get("trailList", [])
                if t.get("CloudWatchLogsLogGroupArn")
            ]

        regions: dict[str, dict[str, Any]] = {}
        for region in scan.regions:
            collected: dict[str, Any] = {}
            logs = scan.session.client("logs", region_name=region)
            groups = recorder.paginate(logs, "describe_log_groups", "logGroups")
            if groups is not None:
                collected["log_groups"] = groups
            ec2 = scan.session.client("ec2", region_name=region)
            flow_logs = recorder.paginate(ec2, "describe_flow_logs", "FlowLogs")
            if flow_logs is not None:
                collected["flow_log_groups"] = [
                    {"flow_log_id": f.get("FlowLogId"), "log_group": f["LogGroupName"]}
                    for f in flow_logs
                    if f.get("LogDestinationType", _CLOUDWATCH_LOGS) == _CLOUDWATCH_LOGS
                    and f.get("LogGroupName")
                ]
            regions[region] = collected
        data["regions"] = regions

        return Snapshot(
            service=self.service,
            account_id=scan.account_id,
            regions=scan.regions,
            collected_at=collected_at,
            data=data,
            errors=tuple(recorder.errors),
        )
