"""룰 레지스트리와 실행기."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from kompass.config import Settings
from kompass.models import Finding, Snapshot
from kompass.rules.base import BaseRule
from kompass.rules.cloudtrail.ct_001_multi_region_trail import Ct001MultiRegionTrail
from kompass.rules.ec2.sg_001_admin_port_open import Sg001AdminPortOpen
from kompass.rules.ec2.sg_002_all_ports_open import Sg002AllPortsOpen
from kompass.rules.ec2.sg_003_db_port_open import Sg003DbPortOpen
from kompass.rules.ec2.sg_004_default_group_in_use import Sg004DefaultGroupInUse
from kompass.rules.ec2.vpc_001_subnet_separation import Vpc001SubnetSeparation
from kompass.rules.ec2.vpc_002_public_ip_interface import Vpc002PublicIpInterface

RULES: tuple[BaseRule, ...] = (
    Ct001MultiRegionTrail(),
    Sg001AdminPortOpen(),
    Sg002AllPortsOpen(),
    Sg003DbPortOpen(),
    Sg004DefaultGroupInUse(),
    Vpc001SubnetSeparation(),
    Vpc002PublicIpInterface(),
)


@dataclass(frozen=True)
class Evaluation:
    findings: tuple[Finding, ...]
    # 스냅샷이 없어서 실행하지 않은 룰. PASS가 아니며, 해당 항목은 "점검하지 않음"이다
    skipped: tuple[str, ...]


def evaluate(
    snapshots: Mapping[str, Snapshot],
    settings: Settings,
    rules: Sequence[BaseRule] = RULES,
) -> Evaluation:
    """룰을 실행한다. 룰 코드의 예외는 잡지 않는다 (버그를 ERROR로 숨기지 않는다)."""
    _require_unique_ids(rules)
    findings: list[Finding] = []
    skipped: list[str] = []
    for rule in rules:
        snapshot = snapshots.get(rule.service)
        if snapshot is None:
            skipped.append(rule.id)
            continue
        produced = rule.evaluate(snapshot, settings)
        if not produced:
            raise RuntimeError(f"{rule.id}가 finding을 내지 않았다. 룰은 항상 하나 이상 내야 한다")
        foreign = {f.rule_id for f in produced} - {rule.id}
        if foreign:
            raise RuntimeError(f"{rule.id}가 다른 룰 ID의 finding을 냈다: {sorted(foreign)}")
        findings.extend(produced)
    return Evaluation(findings=tuple(findings), skipped=tuple(skipped))


def _require_unique_ids(rules: Sequence[BaseRule]) -> None:
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise ValueError(f"룰 ID가 중복된다: {rule.id}")
        seen.add(rule.id)
