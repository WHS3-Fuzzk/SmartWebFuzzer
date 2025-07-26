# pylint: disable=too-many-locals
"""
sqli.py

SQL Injection 취약점 스캔 모듈입니다.
Error-based 및 Time-based SQLi 탐지를 수행합니다.
"""

import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, cast
from urllib.parse import urlencode, parse_qsl
import copy

from celery import chain
from db_writer import (
    insert_fuzzed_request,
    insert_fuzzed_response,
    insert_vulnerability_scan_result,
)
from scanners.base import BaseScanner
from scanners.utils import to_fuzzed_request_dict, to_fuzzed_response_dict
from fuzzing_scheduler.fuzzing_scheduler import celery_app, send_fuzz_request
from typedefs import RequestData, Body

DB_ERRORS: Dict[str, List[str]] = {
    "MySQL": ["You have an error in your SQL syntax", "Warning: mysql_"],
    "PostgreSQL": ["pg_query()", "pg_exec()", "PostgreSQL"],
    "MSSQL": [
        "Unclosed quotation mark after the character string",
        "Microsoft OLE DB Provider for SQL Server",
    ],
    "Oracle": ["ORA-01756", "quoted string not properly terminated"],
    "Error response": ["error"],
}


class SqliScanner(BaseScanner):
    """SQL Injection 취약점 스캐너 클래스"""

    @property
    def vulnerability_name(self) -> str:
        """탐지 대상 취약점 이름을 반환합니다."""
        return "SQLi"

    def __init__(self):
        """SQLiScanner 인스턴스를 초기화하며, 페이로드와 임계값을 설정합니다."""
        self.error_payloads = [
            "'\"",
        ]
        self.time_payloads = {
            "1' AND SLEEP(5)--+",
            "1' AND pg_sleep(5)--+",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('X',5) FROM dual--",
        }

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """해당 요청이 SQLi 퍼징 대상인지 판단합니다."""

        method = request["meta"]["method"]  # TypedDict이므로 바로 접근
        # 1. 쿼리 파라미터가 있는지 확인
        if method == "GET":
            query_params = request.get("query_params") or []
            if query_params:
                return True

        # 2. POST 요청이면서 application/x-www-form-urlencoded 형식인지 확인

        content_type = request["body"]["content_type"]

        if method == "POST" and content_type == "application/x-www-form-urlencoded":
            return True
        return False

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """SQLi 페이로드를 삽입한 변조 요청들을 생성합니다."""
        query_params = request.get("query_params") or []
        method = request["meta"]["method"]

        for fuzz_type, payloads in [
            ("error", self.error_payloads),
            ("time", self.time_payloads),
        ]:
            for payload in payloads:
                for i, param in enumerate(query_params):
                    new_params = [copy.deepcopy(p) for p in query_params]
                    new_params[i]["value"] = payload

                    fuzzing_request = copy.deepcopy(request)
                    fuzzing_request["query_params"] = new_params

                    fuzzing_request["extra"] = {
                        "fuzzed_param": param["key"],
                        "payload": payload,
                        "fuzz_type": fuzz_type,
                    }
                    yield fuzzing_request

                body = request.get("body")
                content_type = (
                    body["content_type"] if body and "content_type" in body else ""
                )

                if (
                    method == "POST"
                    and content_type == "application/x-www-form-urlencoded"
                ):
                    form_body = request.get("body")
                    if form_body and hasattr(form_body, "get"):
                        raw = form_body.get("body")
                        if not isinstance(raw, str):
                            continue
                        parsed = dict(parse_qsl(raw))
                        for key in parsed:
                            new_form = copy.deepcopy(parsed)
                            new_form[key] = payload
                            encoded_body = urlencode(new_form)
                            new_body_obj = (
                                form_body.copy() if hasattr(form_body, "copy") else {}
                            )
                            new_body_obj["body"] = encoded_body
                            fuzzing_request = copy.deepcopy(request)
                            fuzzing_request["body"] = cast(Body, new_body_obj)

                            fuzzing_request["extra"] = {
                                "fuzzed_param": key,
                                "payload": payload,
                                "fuzz_type": fuzz_type,
                            }
                            yield fuzzing_request

    def run(self, request_id: int, request: RequestData) -> List[Dict[str, Any]]:
        """퍼징 요청을 실행하고, 탐지 결과를 수집합니다."""
        if not self.is_target(request_id, request):
            return []

        async_results = []
        for fuzzing_request in self.generate_fuzzing_requests(request):

            async_result = chain(
                send_fuzz_request.s(fuzzing_request) | analyze_response_sqli.s()
            ).apply_async()
            if async_result:
                async_results.append(async_result)

        self.handle_completed_tasks(async_results, request_id)
        return []

    def handle_completed_tasks(self, async_results: List[Any], request_id: int) -> None:
        """비동기 퍼징 작업들의 결과를 수집하고 DB에 저장합니다."""
        pending = list(async_results)
        while pending:
            for res in pending[:]:
                if res.ready():
                    result = res.get()
                    if res.parent is not None:
                        fuzzed_request = res.parent.get().get("request_data")
                        fuzzed_response = res.parent.get()
                        fuzzed_request_dict = to_fuzzed_request_dict(
                            fuzzed_request,
                            original_request_id=request_id,
                            scanner=self.vulnerability_name,
                            payload=fuzzed_request.get("extra", {}).get("payload", ""),
                        )
                        fuzzed_response_dict = to_fuzzed_response_dict(fuzzed_response)

                        fuzzed_request_id = insert_fuzzed_request(fuzzed_request_dict)
                        insert_fuzzed_response(fuzzed_response_dict, fuzzed_request_id)

                        if result:
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
                                    "details": result.get("evidence", "취약점 발견됨"),
                                    "dbms": result.get("dbms", "Unknown"),
                                    "timestamp": datetime.now().isoformat(),
                                },
                            }

                            insert_vulnerability_scan_result(scan_result)
                            # print(
                            #     f"[SQLi]\n"
                            #     f" - 파라미터: {scan_result['parameter']}\n"
                            #     f" - 입력값: {scan_result['payload']}\n"
                            #     f" - DBMS: {scan_result['extra']['dbms']}\n"
                            #     f" - 근거: {scan_result['extra']['details']}"
                            # )
                            print(
                                f"[{self.vulnerability_name}] 취약점 스캔 결과 저장 완료"
                            )

                    pending.remove(res)
            time.sleep(0.5)


@celery_app.task(name="tasks.analyze_response_sqli", queue="analyze_response")
def analyze_response_sqli(response: Dict[str, Any]) -> Dict[str, Any]:
    """SQLi 응답 분석 함수. 에러 메시지나 지연 시간을 기준으로 취약점을 판단합니다."""
    text = response.get("text", "").replace("\x00", "")
    status = response.get("status_code", -1)
    request_data = response.get("request_data")
    extra = request_data.get("extra", {}) if request_data else {}

    payload = extra.get("payload")
    payload_type = extra.get("fuzz_type", "None")
    elapsed = response.get("elapsed_time", 0)

    # print(
    #     f"[SQLi] 분석 - 상태: {status}, 페이로드 타입: {payload_type}, 지연: {elapsed:.2f}s"
    # )
    if payload_type == "time":
        if elapsed >= 4.5:

            return {
                "type": "Time-based SQLi",
                "dbms": "Unknown",
                "payload": payload,
                "evidence": f"Delayed response ({elapsed:.2f}s)",
            }
    else:
        for dbms, errors in DB_ERRORS.items():
            for err in errors:
                if err in text or status == 500:
                    return {
                        "type": "Error-based SQLi",
                        "dbms": dbms,
                        "payload": payload,
                        "evidence": err,
                    }
    return {}
