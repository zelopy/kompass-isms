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
"""

import re
from collections.abc import Iterable
from typing import Any

TOKEN_PREFIX = "MASKED_"
_TOKEN = re.compile(r"MASKED_[A-Z0-9]+_\d+")
# 자리표시자 앞뒤에 이름 문자가 붙어 있으면 값의 일부만 바뀐 것이다
# 번호는 끝까지 읽은 뒤 판단한다 (`MASKED_NAME_10`을 `MASKED_NAME_1` + `0`으로 보지 않는다)
_PARTIAL = re.compile(r"[A-Za-z0-9.-]MASKED_[A-Z0-9]+_\d+|MASKED_[A-Z0-9]+_\d+(?!\d)[A-Za-z-]")
_KEEP = frozenset({"0.0.0.0/0", "::/0"})
_MIN_NAME_LENGTH = 3
_NOT_NAMES = frozenset({"account", "default"})  # 계정 단위 리소스 표기, AWS 기본값

_ARN = re.compile(
    r"arn:(?P<partition>aws[a-z-]*):(?P<service>[a-z0-9-]+):(?P<region>[a-z0-9-]*):"
    r"(?P<account>\d{12}|aws|):(?P<resource>[^\s\"',]+)"
)
_RESOURCE_ID = re.compile(
    r"(?<![\w.-])(?P<kind>sg|vpc|subnet|eni|igw|rtb|nat|i|vol|snap|ami|eipalloc|eipassoc|pl|acl"
    r"|tgw|vpce|pcx)-[0-9a-f]{8,17}(?![\w-])"
)
_UNIQUE_ID = re.compile(
    r"(?<![A-Za-z0-9])(?:AIDA|AROA|AKIA|ASIA|AGPA|ANPA|ANVA|AIPA|APKA|ASCA)[A-Z0-9]{12,20}"
    r"(?![A-Za-z0-9])"
)
_ACCOUNT = re.compile(r"(?<!\d)\d{12}(?!\d)")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?")
_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d")
_AWS_SEGMENTS = frozenset({"aws-reserved", "aws-service-role", "service-role"})

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

    def __init__(self, names: Iterable[str] = ()) -> None:
        self._forward: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._names = sorted(
            {n for n in names if len(n) >= _MIN_NAME_LENGTH and n not in _NOT_NAMES},
            key=len,
            reverse=True,
        )
        self._name_patterns = [
            re.compile(rf"(?<![A-Za-z0-9_.-]){re.escape(name)}(?![A-Za-z0-9_-])")
            for name in self._names
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
        for pattern in self._name_patterns:
            text = pattern.sub(lambda m: self._token("NAME", m.group(0)), text)
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

    def remaining_names(self, text: str) -> list[str]:
        """마스킹했어야 할 이름 중 텍스트에 남아 있는 것."""
        return [n for n, p in zip(self._names, self._name_patterns, strict=True) if p.search(text)]

    # --- 내부 ---

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
        # 리소스 종류(첫 구간)만 남긴다. S3는 버킷·객체 이름뿐이라 모두 바꾼다
        keep = 0 if service == "s3" or len(segments) == 1 else 1
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
            if arn.group("service") != "s3" and len(segments) > 1:
                segments = segments[1:]
            names.update(s for s in segments if _is_name(s) and _is_custom_segment(s))


def _is_custom_segment(segment: str) -> bool:
    return not (
        segment in _AWS_SEGMENTS
        or segment.endswith(".amazonaws.com")
        or _REGION.fullmatch(segment)
        or segment == "*"
    )
