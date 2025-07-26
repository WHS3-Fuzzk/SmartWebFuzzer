# pylint: disable=duplicate-code,too-many-nested-blocks,too-many-branches
"""SSRF Scanner Module"""

import re
import json
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
from fuzzing_scheduler.fuzzing_scheduler import celery_app
from fuzzing_scheduler.fuzzing_scheduler import send_fuzz_request
from typedefs import RequestData


class SSRFScanner(BaseScanner):
    """SSRF Scanner Class"""

    keywords = [
        "file",
        "url",
        "uri",
        "path",
        "host",
        "port",
        "ip",
        "src",
        "dest",
        "redirect",
        "callback",
        "next",
        "target",
        "link",
        "href",
        "api",
    ]

    @property
    def vulnerability_name(self) -> str:
        return "SSRF"

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """
        쿼리 파라미터, 바디에 file, url, uri, path, host, ip 등의 키워드가 포함되어 있는지 확인합니다.
        """

        # 쿼리 파라미터에서 키워드 검색
        if request["query_params"]:
            for param in request["query_params"]:
                param_key = param["key"].lower()
                param_value = param["value"].lower()
                for keyword in self.keywords:
                    if keyword in param_key or keyword in param_value:
                        return True

        # 바디에서 키워드 검색
        if request["body"]:
            body_content = request["body"]["body"].lower()
            for keyword in self.keywords:
                if keyword in body_content:
                    return True

        return False

    def _find_all_injection_points(self, obj, path=""):
        """JSON에서 모든 SSRF 주입 가능 지점을 찾는 메서드"""
        injection_points = []

        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, str) and any(
                    keyword in key.lower() or keyword in value.lower()
                    for keyword in self.keywords
                ):
                    injection_points.append(current_path)
                if isinstance(value, (dict, list)):
                    # 재귀 호출
                    injection_points.extend(
                        self._find_all_injection_points(value, current_path)
                    )
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                if isinstance(item, (dict, list)):
                    injection_points.extend(
                        self._find_all_injection_points(item, current_path)
                    )

        return injection_points

    def _inject_payload_at_specific_point(
        self, obj, payload, target_path, current_path=""
    ):
        """특정 지점에만 페이로드를 주입하는 메서드"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                path = f"{current_path}.{key}" if current_path else key
                if path == target_path and isinstance(value, str):
                    obj[key] = payload
                    return True
                if isinstance(value, (dict, list)):
                    if self._inject_payload_at_specific_point(
                        value, payload, target_path, path
                    ):
                        return True
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                path = f"{current_path}[{i}]" if current_path else f"[{i}]"
                if isinstance(item, (dict, list)):
                    if self._inject_payload_at_specific_point(
                        item, payload, target_path, path
                    ):
                        return True
        return False

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """SSRF 페이로드를 생성하여 퍼징 요청을 만듭니다."""
        payloads = [
            "@198.51.100.42",
            "file:///etc/services",
        ]

        for payload in payloads:
            # 원본 요청을 복사
            fuzzed_request = copy.deepcopy(request)

            # 쿼리 파라미터에 페이로드 주입
            if fuzzed_request["query_params"]:
                for param in fuzzed_request["query_params"]:
                    # 키워드가 포함된 파라미터를 모두 퍼징 (stockApi, myApiKey 등도 포함)
                    if any(
                        keyword.lower() in param["key"].lower()
                        for keyword in self.keywords
                    ):
                        param["value"] = payload
                        # 퍼징 정보 기록
                        fuzzed_request["extra"] = {
                            "fuzzed_param": param["key"],
                            "payload": payload,
                            "injection_point": "query_param",
                        }
                        yield fuzzed_request

            # 바디에 페이로드 주입
            if fuzzed_request["body"]:
                body_content = fuzzed_request["body"]["body"]
                content_type = fuzzed_request["body"]["content_type"].lower()

                # Content-Type에 따른 주입 방식 결정
                if "application/x-www-form-urlencoded" in content_type:
                    # URL 인코딩된 폼 데이터
                    for keyword in self.keywords:
                        if keyword in body_content.lower():

                            # 키워드가 포함된 파라미터를 모두 퍼징 (stockApi, myApiKey 등도 포함)
                            pattern = rf"([^&=]*{keyword}[^&=]*=)([^&]+)"
                            if re.search(pattern, body_content, re.IGNORECASE):
                                fuzzed_request["body"]["body"] = re.sub(
                                    pattern,
                                    rf"\1{payload}",
                                    body_content,
                                    flags=re.IGNORECASE,
                                )
                                # 퍼징 정보 기록
                                fuzzed_request["extra"] = {
                                    "fuzzed_param": keyword,
                                    "payload": payload,
                                    "injection_point": "body_form",
                                }
                                yield fuzzed_request

                elif "application/json" in content_type:
                    # JSON 데이터
                    try:
                        json_data = json.loads(body_content)

                        # 모든 주입 지점 찾기
                        injection_points = self._find_all_injection_points(json_data)

                        # 각 지점마다 별도의 퍼징 요청 생성
                        for target_point in injection_points:
                            # JSON 데이터 복사
                            json_copy = json.loads(body_content)  # 원본에서 다시 파싱

                            # 특정 지점에만 페이로드 주입
                            if self._inject_payload_at_specific_point(
                                json_copy, payload, target_point
                            ):
                                point_fuzzed_request = fuzzed_request.copy()

                                if point_fuzzed_request["body"] is not None:
                                    # JSON 바디 업데이트
                                    point_fuzzed_request["body"]["body"] = json.dumps(
                                        json_copy
                                    )
                                point_fuzzed_request["extra"] = {
                                    "fuzzed_param": target_point,
                                    "payload": payload,
                                    "injection_point": "body_json",
                                }
                                yield point_fuzzed_request

                    except json.JSONDecodeError:
                        # JSON 파싱 실패 시 기존 방식 사용
                        pass

                elif "multipart/form-data" in content_type:
                    # 멀티파트 폼 데이터
                    for keyword in self.keywords:
                        if keyword in body_content.lower():

                            # Content-Disposition 헤더에서 키워드가 포함된 파라미터 찾기
                            pattern = rf'name="([^"]*{keyword}[^"]*)"[^>]*\r?\n\r?\n([^\r\n-]+)'
                            if re.search(pattern, body_content, re.IGNORECASE):
                                fuzzed_request["body"]["body"] = re.sub(
                                    pattern,
                                    rf'name="\1"\r\n\r\n{payload}',
                                    body_content,
                                    flags=re.IGNORECASE,
                                )
                                # 퍼징 정보 기록
                                fuzzed_request["extra"] = {
                                    "fuzzed_param": keyword,
                                    "payload": payload,
                                    "injection_point": "body_multipart",
                                }
                                yield fuzzed_request
                                break

                else:
                    # 기타 Content-Type (text/plain, application/xml 등)
                    for keyword in self.keywords:
                        if keyword in body_content.lower():

                            # 키워드가 포함된 파라미터를 모두 퍼징 (stockApi, myApiKey 등도 포함)
                            pattern = rf"([^=:]*{keyword}[^=:]*[=:]\s*)([^&\s]+)"
                            if re.search(pattern, body_content, re.IGNORECASE):
                                fuzzed_request["body"]["body"] = re.sub(
                                    pattern,
                                    rf"\1{payload}",
                                    body_content,
                                    flags=re.IGNORECASE,
                                )
                                # 퍼징 정보 기록
                                fuzzed_request["extra"] = {
                                    "fuzzed_param": keyword,
                                    "payload": payload,
                                    "injection_point": "body_other",
                                }
                                yield fuzzed_request
                                break

    def run(
        self,
        request_id: int,
        request: RequestData,
    ) -> List[Dict[str, Any]]:
        """SSRF 스캔을 실행합니다."""
        # print(f"[{self.vulnerability_name}]\n요청 ID: {request_id}\n")

        if not self.is_target(request_id, request):
            return []

        async_results: List[AsyncResult] = []

        # 퍼징 요청을 생성하고, 각 변조된 요청을 비동기로 전송
        for fuzzing_request in self.generate_fuzzing_requests(request):
            # print(f"[{self.vulnerability_name}] 퍼징 요청 생성")
            async_result = chain(
                send_fuzz_request.s(request_data=fuzzing_request)
                | analyze_ssrf_response.s()
            ).apply_async()
            if async_result is not None:
                async_results.append(async_result)

        # 완료된 비동기 작업의 결과를 수집
        pending = list(async_results)

        while pending:
            # print(f"[{self.vulnerability_name}] 대기 중인 작업 수: {len(pending)}")
            for res in pending[:]:
                if res.ready():
                    result = res.get()

                    # 추가 동작
                    if res.parent is not None:
                        # 퍼징 요청과 응답, 분석 결과를 DB에 저장
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

                        # 퍼징 요청과 응답을 DB에 저장
                        fuzzed_request_id = insert_fuzzed_request(fuzzed_request_dict)
                        insert_fuzzed_response(fuzzed_response, fuzzed_request_id)

                        # 취약점이 발견된 경우에만 vulnerability_scan_results에 저장
                        if result and result != {}:
                            # print(f"[{self.vulnerability_name}] 취약점 발견")
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
                                    "confidence": result.get("confidence", 0.8),
                                    "details": result.get(
                                        "evidence", "SSRF 취약점 발견"
                                    ),
                                    "injection_point": fuzzed_request.get(
                                        "extra", {}
                                    ).get("injection_point", ""),
                                    "timestamp": datetime.now().isoformat(),
                                },
                            }
                            # 취약점 스캔 결과를 DB에 저장
                            insert_vulnerability_scan_result(scan_result)
                            print(
                                f"[{self.vulnerability_name}] SSRF 취약점 스캔 결과 저장 완료"
                            )
                        else:
                            print(
                                f"[{self.vulnerability_name}] SSRF 취약점이 발견되지 않았습니다."
                            )

                        print(f"[{self.vulnerability_name}] 퍼징 요청 저장 완료")
                    else:
                        print(f"[{self.vulnerability_name}] 취약점 없음")

                    pending.remove(res)
            time.sleep(0.5)

        return []


@celery_app.task(name="tasks.analyze_ssrf_response", queue="analyze_response")
def analyze_ssrf_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    SSRF 응답을 분석해 취약점을 발견하면 Finding 반환
    - 5초 이상 타임아웃 시 SSRF 취약점으로 판단
    - 빠른 응답 시 /etc/services 내용이 포함되어 있는지 확인
    """
    vulnerability = {}

    # 응답 시간과 상태 코드 확인
    response_time = response.get("elapsed_time", 0)
    status_code = response.get("status_code", 0)
    response_text = response.get("text", "")
    error_message = response.get("error_message", "").lower()
    error_type = response.get("error_type", "")

    # 긴 로그 메시지를 여러 줄로 분할
    # print(f"[SSRF] 응답 분석 시작")
    # print(f"[{self.vulnerability_name}] 응답 시간: {response_time}초")
    # print(f"[{self.vulnerability_name}] 상태 코드: {status_code}, 에러 타입: {error_type}")
    # print(f"[{self.vulnerability_name}] 에러 메시지: {error_message}")

    # 페이로드 정보 추출
    payload = response.get("request_data", {}).get("extra", {}).get("payload", "")

    # 1. 타임아웃 기반 탐지 (명시적 타임아웃 또는 5초 이상)
    if error_type == "timeout" or response_time >= 5:
        vulnerability = {
            "payload": payload,
            "evidence": f"SSRF 타임아웃 탐지 (응답시간: {response_time}초, 에러타입: {error_type})",
            "confidence": 0.9,
            "attack_type": "timeout_based",
        }

    # 2. 연결 오류 기반 탐지 (내부 서비스 접근 시도)
    if error_type == "connection_error":
        # 내부 IP나 로컬 서비스에 접근을 시도했을 때 연결 오류가 발생하는 경우
        if any(
            internal_indicator in payload
            for internal_indicator in [
                "127.0.0.1",
                "localhost",
                "0.0.0.0",
                "::1",
                "10.",
                "172.",
                "192.168.",
                "169.254.",
                "file://",
                "@",
                ":",
            ]
        ):
            vulnerability = {
                "payload": payload,
                "evidence": f"SSRF 내부 서비스 접근 시도 탐지 (연결오류: {error_message})",
                "confidence": 0.7,
                "attack_type": "internal_access_attempt",
            }

    # 3. 빠른 응답의 경우 /etc/services 내용 검사
    if error_type == "" and response_time < 5 and status_code == 200:
        # /etc/services 파일의 특징적인 내용들
        services_indicators = [
            "ftp",
            "ssh",
            "telnet",
            "smtp",
            "domain",
            "pop3",
            "nntp",
            "ntp",
            "snmp",
            "ldap",
            "# Network services",
            "# Internet (IP) ports",
            "/tcp",
            "/udp",
            "echo",
            "discard",
            "daytime",
            "chargen",
            "time",
        ]

        # 응답 텍스트에서 /etc/services 특성 확인
        services_found = []
        response_lower = response_text.lower()

        for indicator in services_indicators:
            if indicator in response_lower:
                services_found.append(indicator)

        # 3개 이상의 특징적인 키워드가 발견되면 /etc/services 파일로 판단
        if len(services_found) >= 3:
            vulnerability = {
                "payload": payload,
                "evidence": f"/etc/services 파일 내용 탐지됨. 발견된 서비스: {', '.join(services_found[:5])}",
                "confidence": 0.95,
                "attack_type": "file_disclosure",
                "services_count": len(services_found),
            }

        # 포트 번호 패턴 확인 (예: ssh 22/tcp, http 80/tcp)
        if (
            "22/tcp" in response_lower
            or "80/tcp" in response_lower
            or "443/tcp" in response_lower
        ):
            vulnerability = {
                "payload": payload,
                "evidence": "시스템 서비스 포트 정보 탐지됨 (TCP 포트 리스트 형식)",
                "confidence": 0.8,
                "attack_type": "port_disclosure",
            }

    return vulnerability
