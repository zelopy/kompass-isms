"""해설 평가 채점기: 결정론 지표만 쓴다 (ADR-033). LLM 판정자는 없다.

지표 (값은 0~1, 해당 없으면 None):
- verified: 최종 해설이 인용 검증을 통과했다 (헤드라인)
- first_try: 첫 응답이 재시도 없이 검증을 통과했다
- cite_precision: 첫 응답의 인용 중 유효한 비율 (매핑된 코드 + 원문에 있음 + 형식 문구 아님)
- core_basis: 핵심 근거를 인용했다. KISA 매핑이 있으면 그 항목의 판단 기준·조치 방법·점검 및 조치
  사례 구간, 없으면 매핑된 ISMS-P 통제 본문
- cli_valid: 확인 가능한 AWS CLI 명령 중 botocore 모델로 서비스·작업·옵션이 모두 있는 비율
- action_cover: 해설 대상 상태(FAIL·REVIEW·ERROR)마다 정답 작업이 명령에 하나라도 있는 비율
- target_match: 변경 명령 중 케이스의 대상 리소스를 가리키는 비율
- leak_free: LLM에 보낸 프롬프트에 원본 식별정보가 없다
- no_invented: 복원 뒤에도 남은(지어낸) 자리표시자가 없다
- style_ok: 보고서 문장이 개조식(명사형)으로 끝난다 (~다·~습니다 없음)
"""

import json
import re
import shlex
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any, Literal

import botocore.session
import yaml
from botocore import xform_name

from kompass.evals.cases import NEEDS_ACTION, case_report
from kompass.interpreter.explainer import (
    RuleGroup,
    check_draft,
    prepare_request,
    report_names,
    select_groups,
)
from kompass.interpreter.sources import SourceLookup, normalize_for_match
from kompass.models import (
    EvalCase,
    Golden,
    RuleExplanation,
    RuleExplanationDraft,
    Status,
)
from kompass.rules.base import ACCOUNT_RESOURCE

METRICS = (
    "verified",
    "first_try",
    "cite_precision",
    "core_basis",
    "cli_valid",
    "action_cover",
    "target_match",
    "leak_free",
    "no_invented",
    "style_ok",
)

# --- 정답 ---


def load_golden(path: Path) -> Golden:
    return Golden.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


# --- AWS CLI 검사 ---

_GLOBAL_WITH_VALUE = frozenset(
    {
        "region",
        "profile",
        "output",
        "query",
        "endpoint-url",
        "ca-bundle",
        "color",
        "cli-read-timeout",
        "cli-connect-timeout",
        "cli-binary-format",
    }
)
_GLOBAL_FLAGS = frozenset(
    {
        "debug",
        "no-verify-ssl",
        "no-paginate",
        "no-sign-request",
        "no-cli-pager",
        "cli-auto-prompt",
        "no-cli-auto-prompt",
    }
)
_COMMON_OPTIONS = frozenset(
    {
        "cli-input-json",
        "cli-input-yaml",
        "generate-cli-skeleton",
        "starting-token",
        "page-size",
        "max-items",
    }
)
_SERVICE_ALIASES = {"s3api": "s3", "configservice": "config"}
_HIGH_LEVEL = frozenset({"s3", "configure", "help", "history", "deploy", "ddb"})
# CLI가 덧붙인 옵션 (botocore 모델에 없는 사용자 편의 옵션)
_SG_SHORTHAND = frozenset({"protocol", "port", "cidr", "source-group", "group-owner"})
_CUSTOM_OPTIONS: dict[tuple[str, str], frozenset[str]] = {
    ("ec2", "AuthorizeSecurityGroupIngress"): _SG_SHORTHAND,
    ("ec2", "AuthorizeSecurityGroupEgress"): _SG_SHORTHAND,
    ("ec2", "RevokeSecurityGroupIngress"): _SG_SHORTHAND,
    ("ec2", "RevokeSecurityGroupEgress"): _SG_SHORTHAND,
    ("ec2", "RunInstances"): frozenset(
        {
            "count",
            "secondary-private-ip-addresses",
            "secondary-private-ip-address-count",
            "associate-public-ip-address",
        }
    ),
    ("iam", "CreateVirtualMFADevice"): frozenset({"outfile", "bootstrap-method"}),
}
_WRITE_PREFIXES = (
    "Put",
    "Delete",
    "Revoke",
    "Authorize",
    "Modify",
    "Update",
    "Attach",
    "Detach",
    "Disassociate",
    "Release",
    "Enable",
    "Disable",
    "Create",
    "Stop",
    "Start",
    "Remove",
    "Associate",
    "Replace",
    "Set",
    "Deactivate",
    "Add",
    "Reset",
)

CliStatus = Literal["valid", "invalid", "unverifiable"]


@dataclass(frozen=True)
class CliCommand:
    text: str
    status: CliStatus
    service: str | None = None  # botocore 서비스 이름
    operation: str | None = None  # botocore 작업 이름
    problem: str | None = None

    @property
    def action(self) -> str | None:
        return f"{self.service}:{self.operation}" if self.service and self.operation else None

    @property
    def is_write(self) -> bool:
        return self.status == "valid" and (self.operation or "").startswith(_WRITE_PREFIXES)


@cache
def _session() -> Any:
    return botocore.session.get_session()


@cache
def _services() -> frozenset[str]:
    return frozenset(_session().get_available_services())


@cache
def _operations(service: str) -> dict[str, str]:
    model = _session().get_service_model(service)
    return {xform_name(name, "-"): name for name in model.operation_names}


@cache
def _options(service: str, operation: str) -> frozenset[str]:
    shape = _session().get_service_model(service).operation_model(operation).input_shape
    names: set[str] = set()
    for member, member_shape in shape.members.items() if shape else []:
        option = xform_name(member, "-")
        names.add(option)
        if member_shape.type_name == "boolean":
            names.add(f"no-{option}")
    return frozenset(
        names
        | _GLOBAL_WITH_VALUE
        | _GLOBAL_FLAGS
        | _COMMON_OPTIONS
        | _CUSTOM_OPTIONS.get((service, operation), frozenset())
    )


def split_commands(text: str) -> list[list[str]]:
    """명령 문자열에서 `aws` 명령을 토큰 목록으로 꺼낸다. `&&`, `|`, `;`, `$( )` 안의 명령도 꺼낸다.

    따옴표는 지키고, `<관리자_IP>` 같은 자리표시자는 구분자로 보지 않는다.
    따옴표가 맞지 않으면 ValueError.
    """
    lexer = shlex.shlex(text.replace("\\\n", " "), posix=True, punctuation_chars="();|&")
    lexer.whitespace_split = True
    commands: list[list[str]] = []
    current: list[str] = []
    for token in lexer:
        if token and set(token) <= set("();|&"):
            commands.append(current)
            current = []
        else:
            current.append(token.removeprefix("$") if not current else token)
    commands.append(current)
    return [c for c in commands if c and c[0] == "aws"]


def check_command(tokens: Sequence[str], text: str) -> CliCommand:
    rest = list(tokens[1:])
    while rest and rest[0].startswith("--"):  # aws --region x ec2 ...
        name = rest.pop(0)[2:].split("=")[0]
        if name in _GLOBAL_WITH_VALUE and rest:
            rest.pop(0)
    if len(rest) < 2:
        return CliCommand(text, "invalid", problem="서비스나 작업이 없음")
    service_cli, operation_cli, *args = rest
    if service_cli in _HIGH_LEVEL or operation_cli == "wait":
        return CliCommand(text, "unverifiable", problem="botocore 모델 밖의 CLI 명령")
    service = _SERVICE_ALIASES.get(service_cli, service_cli)
    if service not in _services():
        return CliCommand(text, "invalid", problem=f"없는 서비스: {service_cli}")
    operation = _operations(service).get(operation_cli)
    if operation is None:
        return CliCommand(text, "invalid", service, problem=f"없는 작업: {operation_cli}")
    allowed = _options(service, operation)
    for arg in args:
        if arg.startswith("--"):
            name = arg[2:].split("=")[0]
            if name not in allowed:
                return CliCommand(text, "invalid", service, operation, f"없는 옵션: --{name}")
    return CliCommand(text, "valid", service, operation)


def parse_cli(lines: Iterable[str]) -> list[CliCommand]:
    commands: list[CliCommand] = []
    for line in lines:
        try:
            parsed = split_commands(line)
        except ValueError:
            commands.append(CliCommand(line, "invalid", problem="따옴표가 맞지 않음"))
            continue
        commands += [check_command(tokens, line) for tokens in parsed]
    return commands


# --- 인용 ---

_KISA_SECTIONS = (
    "점검 대상 및 판단 기준",
    "점검 및 조치 사례",
    "조치 시 영향",
    "점검 내용",
    "점검 목적",
    "보안 위협",
    "판단 기준",
    "조치 방법",
    "참고",
    "대상",
)
CORE_SECTIONS = frozenset({"판단 기준", "조치 방법", "점검 및 조치 사례"})


def kisa_sections(text: str) -> dict[str, str]:
    """KISA 항목 원문을 구간별로 나눈다. 구간 이름으로 시작하는 줄이 새 구간을 연다."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        label = next((s for s in _KISA_SECTIONS if line.startswith(s)), None)
        if label is not None:
            current = label
            line = line[len(label) :]
        if current is not None:
            sections.setdefault(current, []).append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}


def is_core_quote(lookup: SourceLookup, code: str, quote: str) -> bool:
    entry = lookup.entry("kisa", code)
    if entry is None:
        return False
    sections = kisa_sections(entry.text)
    core = normalize_for_match("".join(sections.get(s, "") for s in CORE_SECTIONS))
    needle = normalize_for_match(quote)
    return bool(needle) and needle in core


# --- 안전 ---

_SENSITIVE = (
    re.compile(
        r"(?<![\w.-])(?:sg|vpc|subnet|eni|igw|rtb|nat|i|vol|acl|pl)-[0-9a-f]{8,17}(?![\w-])"
    ),
    re.compile(r"\b(?:AIDA|AROA|AKIA|ASIA|AGPA|ANPA)[A-Z0-9]{12,20}\b"),
    re.compile(r"(?<!\d)\d{12}(?!\d)"),
    re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.])"),
)
_KEEP = frozenset({"0.0.0.0/0", "0.0.0.0"})
_TOKEN = re.compile(r"MASKED_[A-Z0-9]+_\d+")
_ENDING = re.compile(r"(다|니다|어요|에요)[.!]?$")


def sensitive_values(case: EvalCase) -> set[str]:
    """LLM에 가면 안 되는 원본 값: 리소스, 모은 이름, 정규식으로 찾은 ID·계정·IP."""
    report = case_report(case)
    values = {f.resource for f in case.findings if f.resource != ACCOUNT_RESOURCE}
    values |= set(report_names(report))
    text = json.dumps([f.model_dump(mode="json") for f in case.findings], ensure_ascii=False)
    for pattern in _SENSITIVE:
        values |= set(pattern.findall(text))
    return {v for v in values if v not in _KEEP and len(v) >= 3}


def style_violations(draft: RuleExplanationDraft) -> list[str]:
    texts = [draft.summary, draft.risk, draft.priority_reason, *draft.remediation.steps]
    texts += [note.note for note in draft.resource_notes]
    sentences = [s.strip() for t in texts for s in re.split(r"\n|(?<=[.!?])\s+", t)]
    return [s for s in sentences if s and _ENDING.search(s.rstrip(" )"))]


# --- 채점 ---


@dataclass(frozen=True)
class CaseOutcome:
    """실행기가 한 케이스(반복 1회)에서 얻은 것."""

    case: EvalCase
    explanation: RuleExplanation
    first_draft: RuleExplanationDraft  # 첫 응답 (마스킹된 상태 그대로)
    prompts: Sequence[str]  # LLM에 보낸 사용자 프롬프트 (재시도 포함)


@dataclass(frozen=True)
class Grade:
    scores: dict[str, float | None]
    details: dict[str, Any] = field(default_factory=dict)


def case_group(case: EvalCase) -> RuleGroup:
    [group] = [g for g in select_groups(case_report(case)) if g.rule_id == case.rule_id]
    return group


def grade(outcome: CaseOutcome, golden: Golden, lookup: SourceLookup) -> Grade:
    case, final = outcome.case, outcome.explanation.explanation
    report = case_report(case)
    group = case_group(case)
    mapping = next(f.mappings for f in group.findings if f.mappings is not None)
    kisa_codes, isms_codes = set(mapping.kisa), set(mapping.isms_p)

    # 인용
    prepared = prepare_request(group, lookup, report_names(report))
    first_problems = check_draft(outcome.first_draft, prepared, lookup)
    first_cites = outcome.first_draft.citations
    valid_first = [
        c
        for c in first_cites
        if _valid_citation(c.scheme, c.code, c.quote, kisa_codes, isms_codes, lookup)
    ]
    if kisa_codes:
        core = any(
            c.scheme == "kisa"
            and c.code in kisa_codes
            and lookup.contains_quote("kisa", c.code, c.quote)
            and is_core_quote(lookup, c.code, c.quote)
            for c in final.citations
        )
    else:
        core = any(
            c.scheme == "isms_p"
            and _valid_citation(c.scheme, c.code, c.quote, kisa_codes, isms_codes, lookup)
            for c in final.citations
        )

    # 조치
    commands = parse_cli(final.remediation.aws_cli)
    checked = [c for c in commands if c.status != "unverifiable"]
    actions = {c.action for c in commands if c.status == "valid"}
    required = _required_actions(group.findings, golden, case.rule_id)
    covered = [bool(actions & set(options)) for options in required.values()]
    targets = _targets(group.findings)
    # 점검 권한 부여(ERROR 조치)는 finding 리소스가 아니라 점검 주체를 바꾸므로 제외한다
    writes = [c for c in commands if c.is_write and c.action not in golden.error_actions]
    on_target = [any(t in c.text for t in targets) for c in writes]

    # 안전
    sensitive = sensitive_values(case)
    leaked = sorted({v for v in sensitive for p in outcome.prompts if v in p})
    invented = sorted(set(_TOKEN.findall(final.model_dump_json())))
    style = style_violations(final)

    scores: dict[str, float | None] = {
        "verified": float(outcome.explanation.verified),
        "first_try": float(not first_problems),
        "cite_precision": len(valid_first) / len(first_cites) if first_cites else 0.0,
        "core_basis": float(core),
        "cli_valid": sum(c.status == "valid" for c in checked) / len(checked) if checked else None,
        "action_cover": sum(covered) / len(covered) if covered else None,
        "target_match": sum(on_target) / len(on_target) if targets and on_target else None,
        "leak_free": float(not leaked),
        "no_invented": float(not invented),
        "style_ok": float(not style),
    }
    details = {
        "first_problems": first_problems,
        "cli": [
            {"text": c.text, "status": c.status, "action": c.action, "problem": c.problem}
            for c in commands
        ],
        "required_actions": {k: sorted(v) for k, v in required.items()},
        "covered": dict(zip(required, covered, strict=True)),
        "leaked_count": len(leaked),  # 원본 값은 결과 파일에 남기지 않는다
        "invented": invented,
        "style_violations": style,
        "terraform": final.remediation.terraform is not None,
        "attempts": outcome.explanation.attempts,
    }
    return Grade(scores, details)


def _valid_citation(
    scheme: str, code: str, quote: str, kisa: set[str], isms: set[str], lookup: SourceLookup
) -> bool:
    allowed = kisa if scheme == "kisa" else isms
    return (
        code in allowed
        and lookup.contains_quote(scheme, code, quote)  # type: ignore[arg-type]
        and not lookup.is_boilerplate(scheme, quote)  # type: ignore[arg-type]
    )


def _required_actions(findings: Sequence[Any], golden: Golden, rule_id: str) -> dict[str, set[str]]:
    """해설 대상 상태별 정답 작업. ERROR는 권한 부여 또는 거부된 조회 작업의 재실행."""
    rule = golden.rules[rule_id]
    required: dict[str, set[str]] = {}
    statuses = {f.status for f in findings if f.status in NEEDS_ACTION}
    for status in (Status.FAIL, Status.REVIEW):
        if status in statuses:
            required[status.value] = set(rule.actions_for(status))
    if Status.ERROR in statuses:
        denied = {
            _iam_action_to_botocore(e["operation"])
            for f in findings
            if f.status == Status.ERROR
            for e in f.evidence.get("errors", [])
        }
        required[Status.ERROR.value] = set(golden.error_actions) | {d for d in denied if d}
    return required


def _iam_action_to_botocore(operation: str) -> str | None:
    """`cloudtrail:DescribeTrails` → 같은 형식. 서비스 접두어가 botocore 이름과 다르면 None."""
    service, _, name = operation.partition(":")
    if service not in _services() or name not in _operations(service).values():
        return None
    return f"{service}:{name}"


def _targets(findings: Sequence[Any]) -> set[str]:
    """변경 명령이 가리켜야 할 리소스 표기: 리소스 값과 ARN 마지막 구간."""
    targets: set[str] = set()
    for finding in findings:
        if finding.status in NEEDS_ACTION and finding.resource != ACCOUNT_RESOURCE:
            targets.add(finding.resource)
            targets.add(finding.resource.rsplit("/", 1)[-1].partition("#")[0])
    return {t for t in targets if len(t) >= 3}
