"""마스킹: LLM에 보내기 전에 식별정보를 자리표시자로 바꾸고, 응답을 받은 뒤 되돌린다.

원칙 5: 계정 ID, IP, ARN, 리소스 이름은 이 모듈을 거친 뒤에만 LLM으로 보낸다 (ADR-007).
치환표는 `Masker` 인스턴스 안에만 있고 저장하거나 전송하지 않는다. dict의 키도 값과 똑같이
마스킹한다 (증적이 리소스 ID를 키로 쓰는 경우가 있다).

치환 순서 (앞 단계의 결과를 뒤 단계가 다시 바꾸지 않도록):
1. ARN: 서비스와 리소스 종류(`user`, `assumed-role` 등)만 남기고 계정과 경로 구간을 모두 바꾼다
   (`arn:aws:iam::MASKED_ACCOUNT_1:user/MASKED_NAME_1`). AWS가 정한 경로 구간(`aws-reserved`,
   `sso.amazonaws.com`, 리전)은 남긴다. S3는 리소스 전체가 버킷·객체 이름이므로 모두 바꾼다.
   AWS 관리형(계정 `aws`)은 그대로 둔다.
2. 이름: finding에서 모은 이름(리소스, 사용자, 그룹, 버킷, 정책, 설명 등)을 긴 것부터 바꾼다.
   리소스 ID 패턴보다 먼저 바꿔야 이름 속의 `-acl-0e094f74` 같은 부분이 ID로 잘리지 않는다.
   3자 미만이나 AWS 기본값(`default`)은 바꾸지 않는다.
3. 리소스 ID: 종류를 남긴다 (`sg-…` → `MASKED_SG_1`). 앞뒤가 이름의 일부이면 잡지 않는다.
4. IAM 고유 ID·액세스 키 ID (`AIDA…`, `AROA…`, `AKIA…`).
5. 계정 ID(12자리).
6. IP 주소·CIDR. `0.0.0.0/0`, `::/0`은 판정의 의미 자체이므로 남긴다.

증적 문서(ADR-049)에는 개인정보가 들어가므로 `personal=True`로 1 다음에 메일 주소·전화번호·
주민등록번호를 먼저 바꾸고(메일 주소 속 사용자 이름이 따로 잘리지 않도록), 사용자 사전의 용어
(직원 이름 등, `terms`)를 이름과 함께 긴 것부터 바꾼다. 한글 이름은 두 글자도 있어 사전 용어는
2자부터 받는다. 해설·조사는 평가셋 기준선(ADR-033)에 묶여 있어 개인정보 패턴을 켜지 않는다.
"""

import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

TOKEN_PREFIX = "MASKED_"
_TOKEN = re.compile(r"MASKED_[A-Z0-9]+_\d+")
# 자리표시자 앞뒤에 이름 문자가 붙어 있으면 값의 일부만 바뀐 것이다
# 번호는 끝까지 읽은 뒤 판단한다 (`MASKED_NAME_10`을 `MASKED_NAME_1` + `0`으로 보지 않는다)
# JSON 문자열의 이스케이프(`\n`, `\t`)는 글자가 앞에 붙은 것으로 보지 않는다. 검사는 json.dumps
# 결과에 하므로, 줄바꿈 뒤에 자리표시자가 오면 `\nMASKED_…`의 `n` 때문에 막히던 오판이 있었다
_PARTIAL = re.compile(
    r"(?<!\\)[A-Za-z0-9.-]MASKED_[A-Z0-9]+_\d+|MASKED_[A-Z0-9]+_\d+(?!\d)[A-Za-z-]"
)
_KEEP = frozenset({"0.0.0.0/0", "::/0"})
_MIN_NAME_LENGTH = 3
_MIN_TERM_LENGTH = 2  # 사용자 사전 용어. 두 글자 한글 이름이 있다
# 계정 단위 리소스 표기, AWS 기본값, 루트 사용자 (AWS가 정한 고정 이름이라 식별정보가 아니다)
_NOT_NAMES = frozenset({"account", "default", "root"})

_ARN = re.compile(
    r"arn:(?P<partition>aws[a-z-]*):(?P<service>[a-z0-9-]+):(?P<region>[a-z0-9-]*):"
    r"(?P<account>\d{12}|aws|):(?P<resource>[^\s\"',]+)"
)
_RESOURCE_ID = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<kind>sg|vpc|subnet|eni|igw|rtb|nat|i|vol|snap|ami|eipalloc|eipassoc|pl|acl"
    r"|tgw|vpce|pcx|fl)-[0-9a-f]{8,17}(?![A-Za-z0-9_-])"
)
_UNIQUE_ID = re.compile(
    r"(?<![A-Za-z0-9])(?:AIDA|AROA|AKIA|ASIA|AGPA|ANPA|ANVA|AIPA|APKA|ASCA)[A-Z0-9]{12,20}"
    r"(?![A-Za-z0-9])"
)
_ACCOUNT = re.compile(r"(?<!\d)\d{12}(?!\d)")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?")
# 개인정보 (personal=True). 앞뒤가 숫자·하이픈이면 더 긴 숫자열의 일부이므로 잡지 않는다
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)
_PHONE = re.compile(
    r"(?<![\d+-])(?:"
    r"\+82[- ]?1[016789][- ]?\d{3,4}[- ]?\d{4}"  # 국제 표기 휴대전화
    r"|01[016789]-?\d{3,4}-?\d{4}"  # 휴대전화
    r"|0(?:2|[3-6][1-5])-\d{3,4}-\d{4}"  # 지역번호 유선전화 (하이픈 필수)
    r")(?![\d-])"
)
_RRN = re.compile(  # 주민등록번호·외국인등록번호
    r"(?<![\d-])\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-?[1-8]\d{6}(?![\d-])"
)
_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d")
_AWS_SEGMENTS = frozenset({"aws-reserved", "aws-service-role", "service-role", "root"})
# ELB ARN의 둘째 구간은 로드 밸런서 종류다 (`loadbalancer/app/<이름>/<ID>`, `listener/net/...`)
_ELB_TYPES = frozenset({"app", "net", "gwy"})

# 이름이 들어 있는 증적·데이터 키 (실제 증적에서 확인한 키)
_NAME_KEYS = frozenset(
    {
        "resource",
        "user",
        "user_name",
        "group_name",
        "name",
        "description",
        "bucket",
        "target_bucket",
        "log_target_for",
        "trail",
        "role",
        "db_identifier",
        "detector_id",
        "log_group",
        "db_cluster",
        "endpoint",
        "subnet_group",
        "parameter_group",
        "load_balancer",
        "policy_name",
        "UserName",
        "GroupName",
        "RoleName",
        "Description",
    }
)
_PREFIXED_NAMES = {"via": "group:", "policy": "inline:"}  # "group:관리자그룹", "inline:정책이름"


class MaskingError(Exception):
    """마스킹 뒤에도 원본 식별정보가 남아 있다. 이 요청은 보내지 않는다."""


class Masker:
    """치환표를 가진 마스커. 한 번의 해설 요청(룰 묶음)마다 새로 만든다."""

    def __init__(
        self, names: Iterable[str] = (), *, terms: Iterable[str] = (), personal: bool = False
    ) -> None:
        self._forward: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._personal = personal
        self._names = _longest_first(
            n for n in names if len(n) >= _MIN_NAME_LENGTH and n not in _NOT_NAMES
        )
        self._terms = frozenset(t for t in terms if len(t) >= _MIN_TERM_LENGTH) - set(self._names)
        self._compile()

    def _compile(self) -> None:
        """이름과 사전 용어를 긴 것부터 바꾸는 패턴 목록 (종류, 원래 값, 패턴)."""
        entries = _longest_first({*self._names, *self._terms})
        self._patterns = [
            (
                "TERM" if value in self._terms else "NAME",
                value,
                _value_pattern(value, value in self._terms),
            )
            for value in entries
        ]

    @classmethod
    def for_values(cls, values: Iterable[Any]) -> "Masker":
        """값(finding dict 등)에서 이름을 모아 마스커를 만든다.

        해설 대상 묶음만이 아니라 보고서 전체의 finding을 넘긴다. 다른 finding의 이름이
        증적 안에서 참조되기 때문이다 (예: S3 로그 대상 버킷).
        """
        names: set[str] = set()
        for value in values:
            _collect_names(value, names)
        return cls(names)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._names)

    def add_names(self, names: Iterable[str]) -> None:
        """나중에 알게 된 이름을 더한다 (에이전트 도구 결과에 처음 나온 이름).

        ID·ARN·계정·IP처럼 정규식 단계가 맡는 값은 이름으로 더하지 않는다. 이미 만든 자리표시자는
        그대로 유지되므로 같은 값은 계속 같은 자리표시자로 바뀐다.
        """
        new = {
            n for n in names if len(n) >= _MIN_NAME_LENGTH and n not in _NOT_NAMES and _is_name(n)
        } - set(self._names)
        if not new:
            return
        self._names = _longest_first({*self._names, *new})
        self._terms -= new
        self._compile()

    # --- 마스킹 ---

    def mask(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {self.mask(key): self.mask(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.mask(item) for item in value]
        if isinstance(value, str):
            return self.mask_text(value)
        return value

    def mask_text(self, text: str) -> str:
        text = _ARN.sub(self._mask_arn, text)
        if self._personal:
            text = _EMAIL.sub(lambda m: self._token("EMAIL", m.group(0)), text)
            text = _PHONE.sub(lambda m: self._token("PHONE", m.group(0)), text)
            text = _RRN.sub(lambda m: self._token("RRN", m.group(0)), text)
        for kind, _, pattern in self._patterns:
            text = pattern.sub(self._replacer(kind), text)
        text = _RESOURCE_ID.sub(lambda m: self._token(m.group("kind").upper(), m.group(0)), text)
        text = _UNIQUE_ID.sub(lambda m: self._token("IAMID", m.group(0)), text)
        text = _ACCOUNT.sub(lambda m: self._token("ACCOUNT", m.group(0)), text)
        text = _IPV4.sub(self._mask_ip, text)
        return _IPV6.sub(self._mask_ipv6, text)

    # --- 복원 ---

    def unmask(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {self.unmask(key): self.unmask(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.unmask(item) for item in value]
        if isinstance(value, str):
            return self.unmask_text(value)
        return value

    def unmask_text(self, text: str) -> str:
        """자리표시자를 원래 값으로 되돌린다. 모르는 자리표시자(LLM이 지어낸 것)는 그대로 둔다."""
        return _TOKEN.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)

    # --- 검사 ---

    def unknown_tokens(self, text: str) -> set[str]:
        """이 마스커가 만들지 않은 자리표시자 (LLM이 지어낸 식별자)."""
        return {token for token in _TOKEN.findall(text) if token not in self._reverse}

    def partially_masked(self, text: str) -> bool:
        """값의 일부만 자리표시자로 바뀐 곳이 있다 (나머지 부분이 노출됨)."""
        return _PARTIAL.search(text) is not None

    def require_clean(self, text: str, resources: Iterable[str]) -> None:
        """보내기 직전 검사. 원본 리소스 값, 일부만 가려진 값, 남은 이름이 있으면 MaskingError.

        오류 메시지에는 원본 값을 넣지 않는다 (원칙 5, fail closed).
        """
        reasons: list[str] = []
        if any(resource in text for resource in resources):
            reasons.append("리소스 식별자가 남아 있음")
        if self.partially_masked(text):
            reasons.append("일부만 가려진 값이 있음")
        if self.remaining_names(text):
            reasons.append("가리지 못한 이름이 있음")
        if reasons:
            raise MaskingError(f"마스킹 검증 실패로 전송하지 않음 ({', '.join(reasons)})")

    def remaining_names(self, text: str) -> list[str]:
        """마스킹했어야 할 이름·사전 용어 중 텍스트에 남아 있는 것."""
        return [value for _, value, pattern in self._patterns if pattern.search(text)]

    def token_counts(self) -> dict[str, int]:
        """종류별로 바꾼 서로 다른 값의 수 (전송 전 미리보기용, 원래 값은 담지 않는다)."""
        return dict(sorted(self._counters.items()))

    # --- 내부 ---

    def _replacer(self, kind: str) -> Callable[[re.Match[str]], str]:
        return lambda match: self._token(kind, match.group(0))

    def _token(self, kind: str, original: str) -> str:
        if original in _KEEP:
            return original
        token = self._forward.get(original)
        if token is None:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            token = f"{TOKEN_PREFIX}{kind}_{self._counters[kind]}"
            self._forward[original] = token
            self._reverse[token] = original
        return token

    def _mask_arn(self, match: re.Match[str]) -> str:
        account = match.group("account")
        if account == "aws":
            return match.group(0)  # AWS 관리형 리소스(정책 등)는 식별정보가 아니다
        service = match.group("service")
        resource, _, suffix = match.group("resource").partition("#")
        segments = resource.split("/")
        # 리소스 종류 구간만 남긴다 (`_type_segments`)
        keep = _type_segments(service, segments)
        kept, masked = segments[:keep], segments[keep:]
        masked_account = self._token("ACCOUNT", account) if account else ""
        head = f"arn:{match.group('partition')}:{service}:{match.group('region')}"
        path = "/".join([*kept, *(self._mask_segment(s) for s in masked)])
        tail = f"#{suffix}" if suffix else ""
        return f"{head}:{masked_account}:{path}{tail}"

    def _mask_segment(self, segment: str) -> str:
        if not segment or not _is_custom_segment(segment):
            return segment
        id_match = _RESOURCE_ID.fullmatch(segment)
        return self._token(id_match.group("kind").upper() if id_match else "NAME", segment)

    def _mask_ip(self, match: re.Match[str]) -> str:
        return self._token("CIDR", match.group(0))

    def _mask_ipv6(self, match: re.Match[str]) -> str:
        value = match.group(0)
        # 시각("08:38:24") 같은 값과 구분: "::"를 포함하거나 콜론이 5개 이상이어야 IPv6로 본다
        if "::" not in value and value.count(":") < 5:
            return value
        return self._token("CIDR", value)


def _longest_first(values: Iterable[str]) -> list[str]:
    """긴 것부터, 길이가 같으면 문자 순. 집합 순서에 따라 자리표시자 번호가 달라지지 않게 한다."""
    return sorted(set(values), key=lambda v: (-len(v), v))


def _value_pattern(value: str, term: bool) -> re.Pattern[str]:
    """이름은 더 긴 이름의 일부가 아닐 때만 바꾼다. 한글 등이 섞인 사전 용어는 경계 없이 바꾼다.

    한글 이름은 파일 이름(`홍길동_권한.xlsx`)이나 조사(`홍길동님`)와 붙어 나와 경계를 두면 놓친다.
    """
    if term and not value.isascii():
        return re.compile(re.escape(value))
    return re.compile(rf"(?<![A-Za-z0-9_.-]){re.escape(value)}(?![A-Za-z0-9_-])")


def _is_name(value: str) -> bool:
    """리소스 ID·ARN·계정 ID·IP는 종류를 남기는 정규식 단계가 맡으므로 이름으로 모으지 않는다."""
    return not (
        value.startswith("arn:")
        or _RESOURCE_ID.fullmatch(value)
        or _UNIQUE_ID.fullmatch(value)
        or _ACCOUNT.fullmatch(value)
        or _IPV4.fullmatch(value)
    )


def _collect_names(value: Any, names: set[str], key: str | None = None) -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            _collect_names(child, names, child_key)
    elif isinstance(value, list):
        for child in value:
            _collect_names(child, names, key)
    elif isinstance(value, str):
        if key in _NAME_KEYS and _is_name(value):
            names.add(value)
        prefix = _PREFIXED_NAMES.get(key or "")
        if prefix and value.startswith(prefix):
            names.add(value.removeprefix(prefix))
        # ARN 속 이름(경로 구간)이 메시지 등에 따로 나올 때도 같은 자리표시자로 바꾼다
        for arn in _ARN.finditer(value):
            if arn.group("account") == "aws":
                continue
            segments = arn.group("resource").partition("#")[0].split("/")
            segments = segments[_type_segments(arn.group("service"), segments) :]
            names.update(s for s in segments if _is_name(s) and _is_custom_segment(s))


def _type_segments(service: str, segments: list[str]) -> int:
    """ARN 리소스 경로 앞쪽에서 리소스 종류라 남길 구간 수. S3는 버킷·객체 이름뿐이라 0이다."""
    if service == "s3" or len(segments) == 1:
        return 0
    if service == "elasticloadbalancing" and len(segments) > 2 and segments[1] in _ELB_TYPES:
        return 2
    return 1


def _is_custom_segment(segment: str) -> bool:
    return not (
        segment in _AWS_SEGMENTS
        or segment.endswith(".amazonaws.com")
        or _REGION.fullmatch(segment)
        or segment == "*"
    )


def load_terms(path: Path) -> tuple[str, ...]:
    """마스킹 사전: 한 줄에 용어 하나 (UTF-8). 빈 줄과 `#`로 시작하는 줄은 건너뛴다."""
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except FileNotFoundError as exc:
        raise MaskingError(f"마스킹 사전 파일이 없습니다: {path}") from exc
    except UnicodeDecodeError as exc:
        raise MaskingError(f"마스킹 사전을 UTF-8로 읽지 못했습니다: {path}") from exc
    lines = (line.strip() for line in text.splitlines())
    return tuple(dict.fromkeys(line for line in lines if line and not line.startswith("#")))
