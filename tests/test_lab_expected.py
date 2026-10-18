"""실습 기대값 파일 검사 (실제 AWS 없이 기본 실행에 포함).

`when`에 쓴 변수가 `LAB_FLAGS`에 없으면 그 기대값은 조용히 대조에서 빠진다.
"""

import re
from typing import Any

import yaml

from tests.lab.test_lab_scan import EXPECTED, LAB, LAB_FLAGS

_BOOL_VARIABLE = re.compile(
    r'variable "(\w+)" \{[^}]*?type\s*=\s*bool[^}]*?default\s*=\s*(true|false)', re.S
)


def test_when_variables_are_known_flags() -> None:
    data: dict[str, Any] = yaml.safe_load(EXPECTED.read_text(encoding="utf-8"))
    used = {key for item in data["expectations"] for key in item.get("when", {})}
    assert used <= set(LAB_FLAGS), used - set(LAB_FLAGS)


def test_flag_defaults_match_variables_tf() -> None:
    text = (LAB / "variables.tf").read_text(encoding="utf-8")
    defaults = {name: value == "true" for name, value in _BOOL_VARIABLE.findall(text)}
    for name, value in LAB_FLAGS.items():
        assert defaults.get(name) == value, name
