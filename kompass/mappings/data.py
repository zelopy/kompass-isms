"""매핑 데이터 로드 (ADR-002, ADR-025).

- `kisa_items.yaml`: KISA 클라우드 항목의 속성 (이름, 중요도, 쪽, 자동화 분류, ISMS-P 후보)
- `rules.yaml`: 룰 → KISA 항목, 룰별 ISMS-P 후보, 확인 여부
- `isms_p_controls.yaml`: ISMS-P 통제항목 101개 (별표 7)

세 파일의 SHA-256(`digest`)을 보고서에 남겨, 어떤 매핑으로 보고서를 만들었는지 재현할 수 있게 한다.
"""

import hashlib
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Any

import yaml

from kompass.models import KisaItem, RuleMapping

_FILES = ("kisa_items.yaml", "rules.yaml", "isms_p_controls.yaml")
_CRLF = bytes([13, 10])
_LF = bytes([10])


@dataclass(frozen=True)
class MappingData:
    kisa_items: dict[str, KisaItem]
    rules: dict[str, RuleMapping]
    isms_p_controls: dict[str, str]  # 항목 번호 → 명칭
    isms_p_areas: dict[str, str]  # "1" → "관리체계 수립 및 운영"
    digest: str  # 세 파일 내용의 SHA-256

    def rules_for_item(self, code: str) -> list[str]:
        return [rule_id for rule_id, m in self.rules.items() if code in m.kisa]


def _read(name: str) -> tuple[bytes, Any]:
    # git 체크아웃 설정(CRLF 변환)과 관계없이 같은 해시가 나오도록 줄바꿈을 통일한다
    raw = files("kompass.mappings").joinpath(name).read_bytes().replace(_CRLF, _LF)
    return raw, yaml.safe_load(raw.decode("utf-8"))


@cache
def load_mappings() -> MappingData:
    raws: list[bytes] = []
    parsed: dict[str, Any] = {}
    for name in _FILES:
        raw, data = _read(name)
        raws.append(raw)
        parsed[name] = data
    items = parsed["kisa_items.yaml"]["items"]
    controls = parsed["isms_p_controls.yaml"]
    return MappingData(
        kisa_items={code: KisaItem(code=code, **attrs) for code, attrs in items.items()},
        rules={
            rule_id: RuleMapping(**attrs)
            for rule_id, attrs in parsed["rules.yaml"]["rules"].items()
        },
        isms_p_controls={str(k): v for k, v in controls["controls"].items()},
        isms_p_areas={str(k): v for k, v in controls["areas"].items()},
        digest=hashlib.sha256(b"".join(raws)).hexdigest(),
    )
