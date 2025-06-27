"""
이 모듈은 scanners 패키지를 초기화하며, BaseScanner를 상속받는 모든 스캐너 클래스를 자동으로 탐색합니다.
발견된 스캐너 클래스들은 _REGISTRY에 등록되어 쉽게 접근할 수 있습니다.
"""

# src/scanners/__init__.py
import pkgutil
import inspect
from importlib import import_module
from typing import Type, Dict

from .base import BaseScanner

_REGISTRY: Dict[str, Type[BaseScanner]] = {}


def _discover_scanners() -> None:
    # scanners 패키지 하위 모듈 순회
    for _, mod_name, ispkg in pkgutil.walk_packages(__path__, prefix=__name__ + "."):
        if ispkg:
            continue
        mod = import_module(mod_name)
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(obj, BaseScanner)
                and obj is not BaseScanner
                and obj.vulnerability_name
            ):
                _REGISTRY[obj().vulnerability_name] = obj


_discover_scanners()
# print(f"발견된 취약점 스캐너 목록: {list(_REGISTRY.keys())}")
