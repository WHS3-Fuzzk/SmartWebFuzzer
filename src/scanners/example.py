"""
이 모듈은 BaseScanner를 상속받아 새로운 취약점 스캐너를 구현할 때 참고할 수 있는 예시입니다.

- 반드시 오버라이드해야 하는 메타데이터(vulnerability_name, description, risk_level)와 필수 메서드 구현 예시 포함
- 각 메서드의 역할과 반환값 예시를 한글 주석으로 설명
- celery_app import 및 task 데코레이터 사용 예시 포함

새로운 취약점 스캐너를 만들 때, 이 구조를 참고하여 구현하세요.
"""

import time
from typing import Any, Dict, Iterable, List
from celery.result import AsyncResult
from celery import chain
from db_writer import insert_fuzzed_request, insert_fuzzed_response
from scanners.base import BaseScanner
from fuzzing_scheduler.fuzzing_scheduler import celery_app  # celery_app import 예시
from fuzzing_scheduler.fuzzing_scheduler import send_fuzz_request


class ExampleScanner(BaseScanner):
    """
    BaseScanner를 상속받는 예시 취약점 스캐너
    """

    # --- 반드시 오버라이드해야 하는 메타데이터 ---
    # 취약점 이름 (예: "XSS", "SQLi" 등)
    @property
    def vulnerability_name(self) -> str:
        return "example"

    def is_target(self, request: Dict[str, Any]) -> bool:
        """
        이 스캐너가 해당 요청을 퍼징할 가치가 있는지 판단
        예시: GET 요청 또는 application/x-www-form-urlencoded POST만 대상으로 함
        """
        method = request.get("method", "").upper()
        content_type = request.get("headers", {}).get("Content-Type", "")

        if method == "GET":
            return True
        if method == "POST" and "application/x-www-form-urlencoded" in content_type:
            return True
        return False  # super().is_target(request)는 호출할 필요 없음

    def generate_fuzzing_requests(
        self, request: Dict[str, Any]
    ) -> Iterable[Dict[str, Any]]:
        """
        퍼징용 변형(request 사본) 생성 예시
        - 모든 파라미터에 XSS 페이로드를 삽입한 변형을 생성
        - 변조된 파라미터명을 'fuzzed_param' 키로 mutant에 기록
        """
        params = request.get("params", {}).copy()
        payload = "<script>alert(1)</script>"  # 예시 페이로드
        for key in params:
            fuzzing_request = request.copy()
            fuzzing_request["params"] = params.copy()
            fuzzing_request["params"][key] = payload  # 예시 페이로드
            fuzzing_request["fuzzed_param"] = key  # 변조된 파라미터명 기록
            fuzzing_request["payload"] = payload  # 삽입된 페이로드 기록
            yield fuzzing_request

    def run(
        self,
        request: Dict[str, Any],
        request_id: int,
    ) -> List[Dict[str, Any]]:
        if not self.is_target(request):
            return []

        async_results: List[AsyncResult] = []

        # 퍼징 요청을 생성하고, 각 변조된 요청을 비동기로 전송
        for fuzzing_request in self.generate_fuzzing_requests(request):

            async_result = chain(
                send_fuzz_request.s(fuzzing_request) | analyze_response.s()
            ).apply_async()
            if async_result is not None:
                async_results.append(async_result)

        # 완료된 비동기 작업의 결과를 수집
        pending = list(async_results)

        while pending:
            print(f"[{self.vulnerability_name}] 대기 중인 작업 수: {len(pending)}")
            for res in pending[:]:
                if res.ready():
                    result = res.get()

                    # 추가 동작
                    if result and res.parent is not None:

                        print(
                            f"요청: {res.parent.get().get('request_info')}, "
                            f"응답: {res.parent.get()}"
                            f"분석 결과: {result}"
                        )
                        # TODO: 퍼징 요청과 응답, 분석 결과를 DB에 저장하는 로직 추가
                        fuzzed_request = res.parent.get().get(
                            "request_info"
                        )  # 퍼징 요청

                        fuzzed_request = to_fuzzed_request_dict(
                            fuzzed_request,
                            original_request_id=request_id,
                            scanner=self.vulnerability_name,
                            payload=res.parent.get().get("payload"),
                        )

                        fuzzed_response = res.parent.get()  # 퍼징 응답
                        fuzzed_response = to_fuzzed_response_dict(fuzzed_response)

                        fuzzed_request_id = insert_fuzzed_request(fuzzed_request)
                        insert_fuzzed_response(fuzzed_response, fuzzed_request_id)
                    else:
                        print(f"완료된 작업: {res.id}, 취약점 없음")

                    pending.remove(res)
            time.sleep(0.5)
        return []


@celery_app.task(name="tasks.analyze_response", queue="analyze_response")
def analyze_response(
    response: Dict[str, Any],
) -> Dict[str, Any]:
    """
    응답을 분석해 취약점을 발견하면 Finding 리스트 반환
    - 예시: 페이로드가 응답 본문에 그대로 반영되면 취약점으로 판단
    - 변조된 파라미터명을 findings['param']에 기록
    """
    vulnerability = {}
    payload = "<script>alert(1)</script>"
    if payload in response.get("text", ""):

        vulnerability = {
            "payload": payload,
            "evidence": "응답에 페이로드가 반영됨",
        }

    return vulnerability


def to_fuzzed_request_dict(
    fuzzing_request: dict,
    original_request_id: int,
    scanner: str,
    payload: str,
) -> dict:
    """traffic_filter.py의 flow_to_request_dict 구조에 맞게 변환"""
    return {
        "original_request_id": original_request_id,
        "scanner": scanner,
        "payload": payload,
        "is_http": fuzzing_request.get("is_http"),
        "http_version": fuzzing_request.get("http_version"),
        "domain": fuzzing_request.get("domain"),
        "path": fuzzing_request.get("path"),
        "method": fuzzing_request.get("method"),
        "timestamp": fuzzing_request.get("timestamp"),
        "headers": dict(fuzzing_request.get("headers", {})),
        "query": fuzzing_request.get("query", []),
        "body": fuzzing_request.get("body"),
    }


def to_fuzzed_response_dict(fuzzed_response: dict) -> dict:
    """traffic_filter.py의 flow_to_response_dict 구조에 맞게 변환"""
    return {
        "http_version": fuzzed_response.get("http_version"),
        "status_code": fuzzed_response.get("status_code"),
        "timestamp": fuzzed_response.get("timestamp"),
        "headers": dict(fuzzed_response.get("headers", {})),
        "body": fuzzed_response.get("body"),
    }


# 1. 환경변수 등록
# PYTHONPATH=src
# 2. 예시 스캐너 실행
# example.py 실행

if __name__ == "__main__":
    example_request = {
        "method": "GET",
        "url": "https://xss-game.appspot.com/level1/frame",
        "headers": {
            "User-Agent": "ExampleScanner",
        },
        "params": {
            "search": "0",  # value는 임의의 값
            "query": "1",  # 이 파라미터에서 XSS 취약점 발생
        },
        "http_version": "1.1",  # 추가: HTTP 버전 명시
    }
    # ExampleScanner 인스턴스 생성 및 실행
    example_vuln_scanner = ExampleScanner()
    scannerResult = example_vuln_scanner.run(
        request=example_request,
        request_id=1,  # 예시로 임의의 request_id 사용
    )
    print(f"스캐너 실행 완료: {scannerResult}")
