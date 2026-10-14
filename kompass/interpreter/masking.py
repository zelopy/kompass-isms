"""마스킹: LLM에 보내기 전에 식별정보를 자리표시자로 바꾸고, 응답을 받은 뒤 되돌린다.

원칙 5: 계정 ID, IP, ARN, 리소스 이름은 이 모듈을 거친 뒤에만 LLM으로 보낸다 (ADR-007).
치환표는 `Masker` 인스턴스 안에만 있고 저장하거나 전송하지 않는다.

치환 순서 (앞 단계의 결과를 뒤 단계가 다시 바꾸지 않도록):
1. ARN: 계정과 리소스 이름만 바꾸고 서비스·리소스 종류는 남긴다
   (`arn:aws:iam::MASKED_ACCOUNT_1:user/MASKED_NAME_1`). AWS 관리형(계정 `aws`)은 그대로 둔다.
2. 리소스 ID: 종류를 남긴다 (`sg-…` → `MASKED_SG_1`).
3. 계정 ID(12자리).
4. IP 주소·CIDR. `0.0.0.0/0`, `::/0`은 판정의 의미 자체이므로 남긴다.
5. 이름: finding에서 모은 이름(사용자, 그룹, 버킷, 설명 등)을 긴 것부터 바꾼다. 3자 미만은
   다른 단어를 망가뜨릴 수 있어 바꾸지 않는다.
"""

import re
from collections.abc import Iterable
from typing import Any

TOKEN_PREFIX = "MASKED_"
_TOKEN = re.compile(r"MASKED_[A-Z0-9]+_\d+")
_KEEP = frozenset({"0.0.0.0/0", "::/0"})
_MIN_NAME_LENGTH = 3

_ARN = re.compile(
    r"arn:(?P<partition>aws[a-z-]*):(?P<service>[a-z0-9-]+):(?P<region>[a-z0-9-]*):"
    r"(?P<account>\d{12}|aws|):(?P<resource>[^\s\"',]+)"
)
_RESOURCE_ID = re.compile(
    r"\b(?P<kind>sg|vpc|subnet|eni|igw|rtb|nat|i|vol|snap|ami|eipalloc|eipassoc|pl|acl|tgw|vpce"
    r"|pcx)-[0-9a-f]{8,17}\b"
)
_ACCOUNT = re.compile(r"(?<!\d)\d{12}(?!\d)")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?")

# 이름이 들어 있는 증적·데이터 키
_NAME_KEYS = frozenset(
    {
        "user",
        "user_name",
        "group_name",
        "name",
        "description",
        "bucket",
        "target_bucket",
        "trail",
        "role",
        "UserName",
        "GroupName",
        "RoleName",
        "Description",
    }
)
_GROUP_VIA = "group:"


class Masker:
    """치환표를 가진 마스커. 한 번의 해설 요청(룰 묶음)마다 새로 만든다."""

    def __init__(self, names: Iterable[str] = ()) -> None:
        self._forward: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._names = sorted(
            {n for n in names if len(n) >= _MIN_NAME_LENGTH}, key=len, reverse=True
        )

    @classmethod
    def for_values(cls, values: Iterable[Any]) -> "Masker":
        """값(finding dict 등)에서 이름을 모아 마스커를 만든다."""
        names: set[str] = set()
        for value in values:
            _collect_names(value, names)
        return cls(names)

    # --- 마스킹 ---

    def mask(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.mask(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.mask(item) for item in value]
        if isinstance(value, str):
            return self.mask_text(value)
        return value

    def mask_text(self, text: str) -> str:
        text = _ARN.sub(self._mask_arn, text)
        text = _RESOURCE_ID.sub(lambda m: self._token(m.group("kind").upper(), m.group(0)), text)
        text = _ACCOUNT.sub(lambda m: self._token("ACCOUNT", m.group(0)), text)
        text = _IPV4.sub(self._mask_ip, text)
        text = _IPV6.sub(self._mask_ipv6, text)
        for name in self._names:
            text = re.sub(
                rf"(?<![A-Za-z0-9_.-]){re.escape(name)}(?![A-Za-z0-9_-])",
                lambda m: self._token("NAME", m.group(0)),
                text,
            )
        return text

    # --- 복원 ---

    def unmask(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.unmask(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.unmask(item) for item in value]
        if isinstance(value, str):
            return self.unmask_text(value)
        return value

    def unmask_text(self, text: str) -> str:
        """자리표시자를 원래 값으로 되돌린다. 모르는 자리표시자(LLM이 지어낸 것)는 그대로 둔다."""
        return _TOKEN.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)

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
        resource, _, suffix = match.group("resource").partition("#")
        kind, sep, name = resource.rpartition("/") if "/" in resource else ("", "", resource)
        id_match = _RESOURCE_ID.fullmatch(name)
        masked_name = (
            self._token(id_match.group("kind").upper(), name)
            if id_match
            else self._token("NAME", name)
        )
        masked_account = self._token("ACCOUNT", account) if account else ""
        head = f"arn:{match.group('partition')}:{match.group('service')}:{match.group('region')}"
        tail = f"#{suffix}" if suffix else ""
        return f"{head}:{masked_account}:{kind}{sep}{masked_name}{tail}"

    def _mask_ip(self, match: re.Match[str]) -> str:
        return self._token("CIDR", match.group(0))

    def _mask_ipv6(self, match: re.Match[str]) -> str:
        value = match.group(0)
        # 시각("08:38:24") 같은 값과 구분: "::"를 포함하거나 콜론이 5개 이상이어야 IPv6로 본다
        if "::" not in value and value.count(":") < 5:
            return value
        return self._token("CIDR", value)


def _collect_names(value: Any, names: set[str], key: str | None = None) -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            _collect_names(child, names, child_key)
    elif isinstance(value, list):
        for child in value:
            _collect_names(child, names, key)
    elif isinstance(value, str):
        if key in _NAME_KEYS and not value.startswith("arn:"):
            names.add(value)
        elif key == "via" and value.startswith(_GROUP_VIA):
            names.add(value.removeprefix(_GROUP_VIA))
        for arn in _ARN.finditer(value):
            if arn.group("account") != "aws":
                resource = arn.group("resource").partition("#")[0]
                names.add(resource.rpartition("/")[2])
