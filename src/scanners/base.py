"""
취약점 스캐너를 공통 구조로 관리하기 위한 추상 클래스 구현
"""

# src/scanners/base.py
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, List
import logging

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    모든 취약점 스캐너가 상속해야 하는 공통 인터페이스

    - vulnerability_name: 취약점 이름
    - is_target: 스캐너 적용 대상 판단
    - generate_mutations: 변조 요청 생성
    - analyze: 응답 분석
    - main: 전체 실행 흐름(요청→변조→전송→분석)
    """

    #: 하위 클래스에서 *반드시* 오버라이드할 메타데이터
    @property
    @abstractmethod
    def vulnerability_name(self) -> str:
        """
        vulnerability_name: str  # "XSS", "SQLi"
        """

    # ------- 필수 메서드 -------
    @abstractmethod
    def is_target(self, request: Dict[str, Any]) -> bool:
        """취약점 분류기 역할: 이 스캐너가 해당 요청을 퍼징할 가치가 있는지 판단"""

    @abstractmethod
    def generate_fuzzing_requests(
        self, request: Dict[str, Any]
    ) -> Iterable[Dict[str, Any]]:
        """퍼징용 변형(request 사본)을 순차적으로 yield"""

    @abstractmethod
    def run(
        self,
        request: Dict[str, Any],
        request_id: int,
    ) -> List[Dict[str, Any]]:
        """
        request 에 대해 퍼징을 실행하고, 변조된 요청을 비동기로 전송하여
        응답을 분석한 결과를 반환합니다.
        Args:
            request (Dict[str, Any]): 원본 HTTP 요청 데이터
        Returns:
            List[Dict[str, Any]]: 분석 결과 리스트
            - 각 요소는 {"param": "id", "payload": "' OR 1=1 --", "evidence": "..."} 형태

        필수 구현 사항:

        1. is_target(request) 메서드를 호출하여
           이 스캐너가 해당 요청을 퍼징할 가치가 있는지 판단합니다.
        예시:
        if not self.is_target(request):
            return []

        2. generate_mutations(request) 메서드를 호출하여
           퍼징용 변조 요청을 생성합니다.
           이 메서드는 request 사본을 변조하여 yield 합니다.
        예시:
        for mutant in self.generate_mutations(request):
        3. 각 변조된 요청(mutant)을 비동기로 전송하고,
        4. 응답을 분석하여 취약점 정보를 수집합니다.
           이때, celery task를 사용하여 비동기적으로 처리할 수 있습니다.
        5. 최종적으로 분석 결과를 리스트로 반환합니다.
        예시:

        # 퍼징 요청을 생성하고, 각 변조된 요청을 비동기로 전송
        """
