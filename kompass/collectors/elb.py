"""ELB collector: ALB·NLB와 Classic Load Balancer의 리스너·보안 정책 (ELB-001~002, ADR-052).

수집 데이터 (`Snapshot.data`):
- `regions.<리전>.load_balancers`: `elbv2:DescribeLoadBalancers` 항목. Gateway Load Balancer가
  아니면 `Listeners`(`DescribeListeners`)를 더하고, HTTP 리스너에는 `Rules`(`DescribeRules`, 기본
  규칙 포함)를 더한다. 리스너·규칙 조회에 실패하면 그 키가 없다 (오류의 resource=로드 밸런서
  ARN·리스너 ARN).
- `regions.<리전>.ssl_policies`: HTTPS·TLS 리스너가 쓰는 보안 정책 이름 → `DescribeSSLPolicies`
  항목. 조회에 실패한 정책은 이름이 없다 (오류의 resource=정책 이름). 로드 밸런서 목록을 수집하지
  못했으면 이 사전도 없다.
- `regions.<리전>.classic_load_balancers`: `elb:DescribeLoadBalancers` 항목(리스너 포함).
  HTTPS·SSL 리스너가 있으면 `Policies`(`DescribeLoadBalancerPolicies`)를 더하며, 실패하면 키가
  없다 (오류의 resource=로드 밸런서 이름).
목록 조회에 실패한 종류는 키가 없다. 대상 서버 쪽 구간(대상 그룹 프로토콜)은 판정하지 않으므로
수집하지 않는다.
"""

from datetime import UTC, datetime
from typing import Any

from kompass.aws.session import ScanContext
from kompass.collectors.base import CallRecorder
from kompass.models import Snapshot

TLS_PROTOCOLS = frozenset({"HTTPS", "TLS", "SSL"})
_HTTP = "HTTP"
_GATEWAY = "gateway"


class ElbCollector:
    service = "elb"

    def collect(self, scan: ScanContext) -> Snapshot:
        collected_at = datetime.now(UTC)
        recorder = CallRecorder()
        regions: dict[str, dict[str, Any]] = {}
        for region in scan.regions:
            collected: dict[str, Any] = {}
            elbv2 = scan.session.client("elbv2", region_name=region)
            load_balancers = recorder.paginate(elbv2, "describe_load_balancers", "LoadBalancers")
            if load_balancers is not None:
                collected["load_balancers"] = [
                    self._with_listeners(recorder, elbv2, lb) for lb in load_balancers
                ]
                collected["ssl_policies"] = self._ssl_policies(
                    recorder, elbv2, collected["load_balancers"]
                )
            elb = scan.session.client("elb", region_name=region)
            classic = recorder.paginate(elb, "describe_load_balancers", "LoadBalancerDescriptions")
            if classic is not None:
                collected["classic_load_balancers"] = [
                    self._with_policies(recorder, elb, lb) for lb in classic
                ]
            regions[region] = collected

        return Snapshot(
            service=self.service,
            account_id=scan.account_id,
            regions=scan.regions,
            collected_at=collected_at,
            data={"regions": regions},
            errors=tuple(recorder.errors),
        )

    @staticmethod
    def _with_listeners(recorder: CallRecorder, client: Any, lb: dict[str, Any]) -> dict[str, Any]:
        if lb.get("Type") == _GATEWAY:
            return lb
        arn = lb["LoadBalancerArn"]
        listeners = recorder.paginate(
            client, "describe_listeners", "Listeners", resource=arn, LoadBalancerArn=arn
        )
        if listeners is None:
            return lb
        for listener in listeners:
            if listener.get("Protocol") != _HTTP:
                continue
            listener_arn = listener["ListenerArn"]
            rules = recorder.paginate(
                client, "describe_rules", "Rules", resource=listener_arn, ListenerArn=listener_arn
            )
            if rules is not None:
                listener["Rules"] = rules
        return {**lb, "Listeners": listeners}

    @staticmethod
    def _ssl_policies(
        recorder: CallRecorder, client: Any, load_balancers: list[dict[str, Any]]
    ) -> dict[str, Any]:
        names = {
            listener["SslPolicy"]
            for lb in load_balancers
            for listener in lb.get("Listeners", [])
            if listener.get("Protocol") in TLS_PROTOCOLS and listener.get("SslPolicy")
        }
        policies: dict[str, Any] = {}
        for name in sorted(names):
            items = recorder.paginate(
                client, "describe_ssl_policies", "SslPolicies", resource=name, Names=[name]
            )
            if items:
                policies[name] = items[0]
        return policies

    @staticmethod
    def _with_policies(recorder: CallRecorder, client: Any, lb: dict[str, Any]) -> dict[str, Any]:
        protocols = {
            desc.get("Listener", {}).get("Protocol") for desc in lb.get("ListenerDescriptions", [])
        }
        if not protocols & TLS_PROTOCOLS:
            return lb
        name = lb["LoadBalancerName"]
        response = recorder.call(
            client, "describe_load_balancer_policies", resource=name, LoadBalancerName=name
        )
        if not isinstance(response, dict):
            return lb
        return {**lb, "Policies": response.get("PolicyDescriptions", [])}
