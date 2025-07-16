# pylint: disable=duplicate-code
"""
이 모듈은 BaseScanner를 상속받아 새로운 취약점 스캐너를 구현할 때 참고할 수 있는 예시입니다.

- 반드시 오버라이드해야 하는 메타데이터(vulnerability_name, description, risk_level)와 필수 메서드 구현 예시 포함
- 각 메서드의 역할과 반환값 예시를 한글 주석으로 설명
- celery_app import 및 task 데코레이터 사용 예시 포함

새로운 취약점 스캐너를 만들 때, 이 구조를 참고하여 구현하세요.
"""


import time
import copy
from datetime import datetime
from typing import Any, Dict, Iterable, List
from celery.result import AsyncResult
from celery import chain
from db_writer import (
    insert_fuzzed_request,
    insert_fuzzed_response,
    insert_vulnerability_scan_result,
)
from scanners.base import BaseScanner
from scanners.utils import to_fuzzed_request_dict, to_fuzzed_response_dict
from fuzzing_scheduler.fuzzing_scheduler import celery_app  # celery_app import 예시
from fuzzing_scheduler.fuzzing_scheduler import send_fuzz_request
from typedefs import RequestData


class ExampleScanner(BaseScanner):
    """
    BaseScanner를 상속받는 예시 취약점 스캐너
    """

    # --- 반드시 오버라이드해야 하는 메타데이터 ---
    # 취약점 이름 (예: "XSS", "SQLi" 등)
    @property
    def vulnerability_name(self) -> str:
        return "example"

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """
        이 스캐너가 해당 요청을 퍼징할 가치가 있는지 판단
        예시: GET 요청 또는 application/x-www-form-urlencoded POST만 대상으로 함
        """
        method = request["meta"]["method"]
        headers = request["headers"]
        content_type = ""
        if headers is not None:
            for header in headers:
                if header.get("key", "").lower() == "Content-Type".lower():
                    content_type = header.get("value", "")

        if method == "GET":
            return True
        if method == "POST" and "application/x-www-form-urlencoded" in content_type:
            return True
        return False  # super().is_target(request)는 호출할 필요 없음

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """
        모든 쿼리 파라미터에 XSS 페이로드를 삽입한 변형 RequestData를 생성
        """
        payload = "<script>alert(1)</script>"
        query_params = request.get("query_params") or []
        for i, param in enumerate(query_params):
            # query_params 복사 및 변조
            new_query_params = [p.copy() for p in query_params]
            new_query_params[i]["value"] = payload

            # 변조된 RequestData 생성
            fuzzing_request = copy.deepcopy(request)
            fuzzing_request["query_params"] = new_query_params
            # 변조 정보 기록 (RequestData에 없는 필드는 따로 관리 필요)
            fuzzing_request["extra"] = {
                "fuzzed_param": param["key"],
                "payload": payload,
            }
            yield fuzzing_request

    def run(
        self,
        request_id: int,
        request: RequestData,
    ) -> List[Dict[str, Any]]:
        print(f"[{self.vulnerability_name}]\n요청 ID: {request_id}\n")
        if not self.is_target(request_id, request):
            return []

        async_results: List[AsyncResult] = []

        # 퍼징 요청을 생성하고, 각 변조된 요청을 비동기로 전송
        for fuzzing_request in self.generate_fuzzing_requests(request):

            async_result = chain(
                send_fuzz_request.s(request_data=fuzzing_request)
                | analyze_response_example.s()
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
                    print(result, f"완료된 작업: {res.id}")
                    # 추가 동작
                    if result and res.parent is not None:

                        # print(
                        #     f"요청: {res.parent.get().get('request_data')}\n"
                        #     f"응답: {res.parent.get()}\n"
                        #     f"분석 결과: {result}\n"
                        # )
                        fuzzed_request: RequestData = res.parent.get().get(
                            "request_data"
                        )  # 퍼징 요청

                        fuzzed_request_dict = to_fuzzed_request_dict(
                            fuzzed_request,
                            original_request_id=request_id,
                            scanner=self.vulnerability_name,
                            payload=fuzzed_request.get("extra", {}).get("payload", ""),
                        )

                        fuzzed_response = res.parent.get()  # 퍼징 응답
                        fuzzed_response = to_fuzzed_response_dict(fuzzed_response)

                        # 퍼징 요청과 응답을 DB에 저장

                        fuzzed_request_id = insert_fuzzed_request(fuzzed_request_dict)
                        insert_fuzzed_response(fuzzed_response, fuzzed_request_id)

                        # 취약점이 발견된 경우에만 vulnerability_scan_results에 저장
                        if result and result != {}:
                            print(f"취약점 발견: {result}")
                            scan_result = {
                                "vulnerability_name": self.vulnerability_name,
                                "original_request_id": request_id,
                                "fuzzed_request_id": fuzzed_request_id,
                                "domain": fuzzed_request.get("meta", {}).get(
                                    "domain", ""
                                ),
                                "endpoint": fuzzed_request.get("meta", {}).get(
                                    "path", ""
                                ),
                                "method": fuzzed_request.get("meta", {}).get(
                                    "method", ""
                                ),
                                "payload": fuzzed_request.get("extra", {}).get(
                                    "payload", ""
                                ),
                                "parameter": fuzzed_request.get("extra", {}).get(
                                    "fuzzed_param", ""
                                ),
                                "extra": {
                                    "confidence": 0.9,
                                    "details": result.get("evidence", "취약점 발견"),
                                    "timestamp": datetime.now().isoformat(),
                                },
                            }
                            # 취약점 스캔 결과를 DB에 저장
                            result_id = insert_vulnerability_scan_result(scan_result)
                            print(f"취약점 스캔 결과 저장 완료: {result_id}")
                        else:
                            print("취약점이 발견되지 않았습니다.")

                        print(f"퍼징 요청 저장 완료: {fuzzed_request_id}")
                    else:
                        print(f"완료된 작업: {res.id}, 취약점 없음")

                    pending.remove(res)
            time.sleep(0.5)
        return []


@celery_app.task(name="tasks.analyze_response_example", queue="analyze_response")
def analyze_response_example(
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


# 1. 환경변수 등록
# PYTHONPATH=src
# 2. 예시 스캐너 실행
# example.py 실행

if __name__ == "__main__":
    example_request: RequestData = {
        "meta": {
            "id": 1,  # 예시값
            "is_http": 0,
            "http_version": "1.1",
            "domain": "xss-game.appspot.com",
            "path": "/level1/frame",
            "method": "GET",
            "timestamp": datetime.now(),
        },
        "headers": [
            {"key": "User-Agent", "value": "ExampleScanner"},
        ],
        "query_params": [
            {"key": "search", "value": "0", "source": "url"},
            {"key": "query", "value": "1", "source": "url"},
        ],
        "body": None,
    }
    # ExampleScanner 인스턴스 생성 및 실행
    example_vuln_scanner = ExampleScanner()
    scannerResult = example_vuln_scanner.run(
        request=example_request,
        request_id=1,  # 예시로 임의의 request_id 사용
    )
    print(f"스캐너 실행 완료: {scannerResult}")
