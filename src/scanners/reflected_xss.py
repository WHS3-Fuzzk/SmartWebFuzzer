"""
reflected_xss.py

Reflected XSS 취약점 스캐너 모듈입니다.
BaseScanner를 상속받아 요청 변조 및 결과 분석 기능을 구현합니다.
"""

import os
from typing import Any, Dict, Iterable, List
from datetime import datetime
from celery import chain
from scanners.base import BaseScanner
from fuzzing_scheduler.fuzzing_scheduler import celery_app, send_fuzz_request
from typedefs import RequestData


def realdictrow_to_dict(obj):
    """
    RealDictRow, dict, list, datetime 객체를 재귀적으로 dict/리스트/문자열로 변환
    """
    if isinstance(obj, list):
        return [realdictrow_to_dict(i) for i in obj]
    if hasattr(obj, "keys") and hasattr(obj, "__getitem__"):
        # RealDictRow나 dict 형태일 때
        return {k: realdictrow_to_dict(obj[k]) for k in obj.keys()}
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


class ReflectedXSS(BaseScanner):
    """
    BaseScanner를 상속받는 예시 취약점 스캐너
    """

    @property
    def vulnerability_name(self) -> str:
        return "reflected_xss"

    def __init__(self):
        """
        페이로드 불러오기
        """
        base_dir = os.path.dirname(os.path.abspath(__file__))  # src/scanners 폴더 경로
        payload_file = os.path.join(
            base_dir, "payloads", "xss.txt"
        )  # payloads/xss.txt 경로

        with open(payload_file, "r", encoding="utf-8") as f:
            self.payloads = [line.strip() for line in f if line.strip()]

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """
        이 스캐너가 해당 요청을 퍼징할 가치가 있는지 판단
        예시: GET 요청 또는 application/x-www-form-urlencoded POST만 대상으로 함
        """
        method = request["meta"]["method"]
        headers = request.get("headers") or []
        content_type = ""
        for header in headers:
            if header.get("key", "").lower() == "content-type":
                content_type = header.get("value", "")
        if method == "GET":
            return True
        if method == "POST" and "application/x-www-form-urlencoded" in content_type:
            return True
        return False

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """
        주어진 요청에서 각 쿼리 파라미터에 대해 페이로드를 삽입한 변조 요청 생성기
        """
        query_params = request.get("query_params") or []
        for payload in self.payloads:  # 수정: 페이로드 리스트에서 하나씩 꺼내기
            for i, param in enumerate(query_params):
                new_query_params = [p.copy() for p in query_params]
                new_query_params[i]["value"] = payload

                fuzzing_request = request.copy()
                fuzzing_request["query_params"] = new_query_params
                fuzzing_request["extra"] = {
                    "fuzzed_param": param["key"],
                    "payload": payload,
                }
                print(f"[+] Generated fuzzing request with payload: {payload}")
                yield fuzzing_request

    def run(
        self,
        request_id: int,
        request: RequestData,
    ) -> List[Dict[str, Any]]:
        """
        해당 요청을 변조하여 퍼징 요청 생성 및 전송, 결과 수집
        """
        print(f"[{self.vulnerability_name}]\n요청 ID: {request_id}\n")
        if not self.is_target(request_id, request):
            return []

        results = []
        for fuzz_request in self.generate_fuzzing_requests(request):
            fuzz_request_dict = realdictrow_to_dict(fuzz_request)
            print(fuzz_request_dict)
            task_chain = chain(
                send_fuzz_request.s(fuzz_request_dict),
                analyze_response.s(),
            )
            task_chain.apply_async(queue="fuzz_request")

            url = fuzz_request_dict.get("meta", {}).get("path", "Unknown URL")

            results.append(
                {
                    "url": url,
                    "attack_type": "reflected",
                    "payload": fuzz_request["extra"]["payload"],
                    "target_param": fuzz_request["extra"]["fuzzed_param"],
                }
            )

        for r in results:
            print(
                f"URL: {r['url']}, Attack Type: {r['attack_type']}, "
                f"Payload: {r['payload']}, Target Param: {r['target_param']}"
            )
        return results


@celery_app.task(name="tasks.analyze_response", queue="analyze_response")
def analyze_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    응답을 분석해 취약점을 발견하면 Finding 리스트 반환
    - 페이로드가 응답 본문에 반영되면 취약점으로 판단
    - 변조된 파라미터명을 findings['param']에 기록
    """
    # 모든 페이로드에 대해 체크하도록 수정
    base_dir = os.path.dirname(os.path.abspath(__file__))  # src/scanners 폴더 경로
    payload_file = os.path.join(base_dir, "payloads", "xss.txt")  # payloads/xss.txt 경로
    with open(payload_file, "r", encoding="utf-8") as f:
        payloads = [line.strip() for line in f if line.strip()]

    response_text = response.get("text", "")
    for payload in payloads:
        if payload in response_text:
            return {
                "payload": payload,
                "evidence": "응답에 페이로드가 반영됨",
            }
    return {}
