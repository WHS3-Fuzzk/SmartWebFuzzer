# pylint: skip-file
"""
이 모듈은 BaseScanner를 상속받아 새로운 취약점 스캐너를 구현할 때 참고할 수 있는 예시입니다.

- 반드시 오버라이드해야 하는 메타데이터(vulnerability_name, description, risk_level)와 필수 메서드 구현 예시 포함
- 각 메서드의 역할과 반환값 예시를 한글 주석으로 설명
- celery_app import 및 task 데코레이터 사용 예시 포함

새로운 취약점 스캐너를 만들 때, 이 구조를 참고하여 구현하세요.
"""

import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, cast
from celery.result import AsyncResult
from celery import chain
from db_writer import (
    insert_fuzzed_request,
    insert_fuzzed_response,
    insert_vulnerability_scan_result,
)
from scanners.base import BaseScanner
from fuzzing_scheduler.fuzzing_scheduler import celery_app  # celery_app import 예시
from fuzzing_scheduler.fuzzing_scheduler import send_fuzz_request
from typedefs import RequestData, Body
from scanners.utils import to_fuzzed_request_dict, to_fuzzed_response_dict


class CommandiScanner(BaseScanner):
    """
    BaseScanner를 상속받는 예시 취약점 스캐너
    """

    # --- 반드시 오버라이드해야 하는 메타데이터 ---analyze_response_commandi
    # 취약점 이름 (예: "XSS", "SQLi" 등)
    @property
    def vulnerability_name(self) -> str:
        return "CMDi"

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
        import urllib.parse

        payload = ";ls && whoami"

        method = request["meta"].get("method", "")
        headers = request.get("headers") or []
        content_type = ""
        if headers:
            for header in headers:
                if header.get("key", "").lower() == "content-type":
                    content_type = header.get("value", "")

        # GET 또는 쿼리 파라미터가 있는 경우 기존 방식
        query_params = request.get("query_params") or []
        for i, param in enumerate(query_params):
            new_query_params = [p.copy() for p in query_params]
            new_query_params[i]["value"] = payload

            fuzzing_request = request.copy()
            fuzzing_request["query_params"] = new_query_params
            fuzzing_request["extra"] = {
                "fuzzed_param": param["key"],
                "payload": payload,
            }
            yield fuzzing_request

        # POST + application/x-www-form-urlencoded인 경우 body 파라미터 변조
        if (
            method == "POST"
            and "application/x-www-form-urlencoded" in content_type.lower()
            and request.get("body") is not None
        ):
            form_body = request["body"]

            # body가 dict/RealDictRow면 그 안의 'body' 필드를 꺼내서 파싱
            if (
                form_body is not None
                and hasattr(form_body, "get")
                and callable(form_body.get)
            ):
                raw_body = form_body.get("body")
                if not isinstance(raw_body, str):
                    return  # 변조 불가
                parsed_form = dict(urllib.parse.parse_qsl(raw_body))
                for key in parsed_form.keys():
                    new_form = parsed_form.copy()
                    new_form[key] = payload
                    encoded_body = urllib.parse.urlencode(new_form)
                    # 원본 form_body를 복사해서 'body' 필드만 변조
                    if hasattr(form_body, "copy") and callable(form_body.copy):
                        new_body_obj = form_body.copy()
                        new_body_obj["body"] = encoded_body
                    else:
                        new_body_obj = {"body": encoded_body}
                    fuzzing_request = request.copy()
                    fuzzing_request["body"] = cast(Body, new_body_obj)
                    fuzzing_request["extra"] = {
                        "fuzzed_param": key,
                        "payload": payload,
                    }
                    yield fuzzing_request
            elif isinstance(form_body, str):
                parsed_form = dict(urllib.parse.parse_qsl(form_body))
                for key in parsed_form.keys():
                    new_form = parsed_form.copy()
                    new_form[key] = payload
                    encoded_body = urllib.parse.urlencode(new_form)
                    new_body_obj = {"body": encoded_body}
                    fuzzing_request = request.copy()
                    fuzzing_request["body"] = cast(Body, new_body_obj)
                    fuzzing_request["extra"] = {
                        "fuzzed_param": key,
                        "payload": payload,
                    }
                    yield fuzzing_request

    def run(
        self,
        request_id: int,
        request: RequestData,
    ) -> List[Dict[str, Any]]:
        if not self.is_target(request_id, request):
            return []

        async_results: List[AsyncResult] = []

        # 퍼징 요청을 생성하고, 각 변조된 요청을 비동기로 전송
        for fuzzing_request in self.generate_fuzzing_requests(request):
            async_result = chain(
                send_fuzz_request.s(request_data=fuzzing_request)
                | analyze_response_commandi.s()
            ).apply_async()
            if async_result is not None:
                async_results.append(async_result)

        # 완료된 비동기 작업의 결과를 수집
        pending = list(async_results)

        while pending:
            for res in pending[:]:
                if res.ready():
                    result = res.get()
                    # 추가 동작
                    if result and res.parent is not None:
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
                        try:
                            fuzzed_request_id = insert_fuzzed_request(
                                fuzzed_request_dict
                            )
                        except Exception as e:
                            continue

                        try:
                            insert_fuzzed_response(fuzzed_response, fuzzed_request_id)
                        except Exception as e:
                            pass

                        # 취약점이 발견된 경우에만 vulnerability_scan_results에 저장
                        if result and result != {}:
                            print(f"[{self.vulnerability_name}] {result.get('evidence', '')}")
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
                            try:
                                insert_vulnerability_scan_result(
                                    scan_result
                                )
                                print(f"[{self.vulnerability_name}] 취약점 스캔 결과 저장 완료")
                            except Exception as e:
                                pass

                    pending.remove(res)
            time.sleep(0.5)
        return []


@celery_app.task(name="tasks.analyze_response_commandi", queue="analyze_response")
def analyze_response_commandi(
    response: Dict[str, Any],
) -> Dict[str, Any]:
    """
    커맨드 인젝션 탐지: 페이로드 실행 결과가 응답에 포함되어 있으면 취약점으로 판단
    """
    payloads = [";whoami", ";id", ";uname -a", ";ls", "&& whoami", "| whoami"]
    evidence_keywords = [
        "uid=",
        "gid=",
        "groups=",  # id 명령 결과
        "Linux",
        "Darwin",
        "Windows",  # uname -a 결과
        "root",
        "www-data",
        "user",  # whoami 결과(일반적인 리눅스/웹서버 계정)
    ]
    text = response.get("text", "")
    for payload in payloads:
        if payload in text:
            return {
                "payload": payload,
                "evidence": f"응답에 페이로드({payload})가 그대로 반영됨",
            }
    for keyword in evidence_keywords:
        if keyword in text:
            return {
                "payload": "command_injection",
                "evidence": f"응답에 명령 실행 결과({keyword})가 포함됨",
            }
    return {}
