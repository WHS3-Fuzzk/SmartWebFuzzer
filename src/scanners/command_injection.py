# pylint: skip-file
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
from scanners.utils import to_fuzzed_request_dict, to_fuzzed_response_dict
import copy


class CommandiScanner(BaseScanner):
    @property
    def vulnerability_name(self) -> str:
        return "CMD_injection"

    def is_target(self, request_id: int, request: RequestData) -> bool:
        method = request["meta"]["method"]
        headers = request.get("headers") or []
        content_type = ""
        for h in headers:
            if h.get("key", "").lower() == "content-type":
                content_type = h.get("value", "")
        if method == "GET":
            return True
        if (
            method == "POST"
            and "application/x-www-form-urlencoded" in content_type.lower()
        ):
            return True
        return False

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        # 리플렉티드 페이로드용 분리자 (중요한 것만)
        command_separators = [
            ";",
            "&&",
            "|",
            "`",
        ]

        # 리플렉티드 페이로드 템플릿 (중요한 것만)
        unix_payload_templates = [
            "echo CMDTEST{marker}",
            "whoami; echo CMDTEST{marker}",
        ]

        # 시간 기반 페이로드 (다양한 OS 커맨드)
        delay_time = 5
        time_based_payloads = [
            f"sleep {delay_time}",  # Unix/Linux
            f"ping -c {delay_time} 127.0.0.1",  # Unix/Linux
            f"timeout /T {delay_time}",  # Windows CMD
            f"Start-Sleep -s {delay_time}",  # PowerShell
        ]

        all_payloads: List[Dict[str, Any]] = []

        # 리플렉티드 페이로드 생성
        for template in unix_payload_templates:
            unique_marker = "".join(
                random.choices(string.ascii_letters + string.digits, k=8)
            )
            base = template.format(marker=unique_marker)
            for sep in command_separators:
                if sep.strip():
                    p = f"{sep}{base}".strip()
                    all_payloads.append(
                        {
                            "payload": p,
                            "unique_marker": unique_marker,
                            "type": "reflected",
                            "expected_delay": None,
                        }
                    )

        # 타임 기반 페이로드 추가 (분리자별로 다양한 명령어)
        for time_payload in time_based_payloads:
            for sep in command_separators:
                if sep.strip():
                    p = f"{sep}{time_payload}".strip()
                    all_payloads.append(
                        {
                            "payload": p,
                            "unique_marker": None,
                            "type": "time_based",
                            "expected_delay": delay_time,
                        }
                    )

        # === GET 파라미터 퍼징 ===
        query_params = request.get("query_params") or []
        for info in all_payloads:
            for i, param in enumerate(query_params):
                new_q = copy.deepcopy(query_params)
                new_q[i]["value"] = info["payload"]

                fuzzing_request = copy.deepcopy(request)
                fuzzing_request["query_params"] = new_q
                fuzzing_request["extra"] = {
                    "fuzzed_param": param["key"],
                    "payload": info["payload"],
                    "unique_marker": info["unique_marker"],
                    "expected_delay": info["expected_delay"],
                    "detection_type": info["type"],
                }
                yield fuzzing_request

        # === POST 파라미터 퍼징 ===
        method = request["meta"].get("method", "")
        headers = request.get("headers") or []
        content_type = ""
        for h in headers:
            if h.get("key", "").lower() == "content-type":
                content_type = h.get("value", "")

        if (
            method == "POST"
            and "application/x-www-form-urlencoded" in content_type.lower()
            and request.get("body")
        ):
            form_body = request["body"]
            raw = form_body.get("body") if form_body else None
            if isinstance(raw, str) and form_body is not None:
                parsed = dict(urllib.parse.parse_qsl(raw))
                for info in all_payloads:
                    for key in parsed.keys():
                        new_form = copy.deepcopy(parsed)
                        new_form[key] = info["payload"]
                        encoded = urllib.parse.urlencode(new_form)
                        nb = copy.deepcopy(form_body)
                        if nb is not None:
                            nb["body"] = encoded

                            fuzzing_request = copy.deepcopy(request)
                            fuzzing_request["body"] = cast(Body, nb)
                            fuzzing_request["extra"] = {
                                "fuzzed_param": key,
                                "payload": info["payload"],
                                "unique_marker": info["unique_marker"],
                                "expected_delay": info["expected_delay"],
                                "detection_type": info["type"],
                            }
                            yield fuzzing_request

    def _classify_payload_type(self, payload: str) -> str:
        if "CMDTEST" in payload:
            return "reflected"
        if any(x in payload for x in ["sleep", "ping", "timeout", "Start-Sleep"]):
            return "time_based"
        return "general"

    def run(self, request_id: int, request: RequestData) -> List[Dict[str, Any]]:
        if not self.is_target(request_id, request):
            return []
        async_results: List[AsyncResult] = []
        for fr in self.generate_fuzzing_requests(request):
            try:
                ar = chain(
                    send_fuzz_request.s(request_data=fr) | analyze_response_commandi.s()
                ).apply_async()
                if ar:
                    async_results.append(ar)
            except Exception as e:
                print(f"[ERROR] 퍼징 요청 전송 실패: {e}")
        pending = list(async_results)
        while pending:
            for r in pending[:]:
                if r.ready():
                    try:
                        result = r.get()
                        parent = r.parent.get() if r.parent else {}
                        fr_req = parent.get("request_data")

                        # 퍼징 요청 응답 시간 및 페이로드 출력
                        if parent and "elapsed_time" in parent:
                            elapsed_time = parent["elapsed_time"]

                        if fr_req:
                            fr_dict = to_fuzzed_request_dict(
                                fr_req,
                                request_id,
                                self.vulnerability_name,
                                fr_req.get("extra", {}).get("payload", ""),
                            )
                            fr_id = insert_fuzzed_request(fr_dict)
                            insert_fuzzed_response(
                                to_fuzzed_response_dict(parent), fr_id
                            )
                            if result:
                                scan = {
                                    "vulnerability_name": self.vulnerability_name,
                                    "original_request_id": request_id,
                                    "fuzzed_request_id": fr_id,
                                    "domain": fr_req["meta"].get("domain", ""),
                                    "endpoint": fr_req["meta"].get("path", ""),
                                    "method": fr_req["meta"].get("method", ""),
                                    "payload": fr_req["extra"].get("payload", ""),
                                    "parameter": fr_req["extra"].get(
                                        "fuzzed_param", ""
                                    ),
                                    "extra": {
                                        **result,  # result 전체를 넣고
                                        "evidence": result.get(
                                            "evidence", "취약점 발견"
                                        ),  # evidence가 반드시 포함되게
                                    },
                                }

                                insert_vulnerability_scan_result(scan)
                                print(f"[취약점 발견] {result.get('evidence', '')}")
                    except Exception as e:
                        print(f"[ERROR] 결과 처리 실패: {e}")
                    pending.remove(r)
            time.sleep(0.5)
        return []


@celery_app.task(name="tasks.analyze_response_commandi", queue="analyze_response")
def analyze_response_commandi(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    개선된 커맨드 인젝션 탐지 함수 (대시보드 호환)
    """
    request_data = response.get("request_data", {})
    extra = request_data.get("extra", {})
    payload = extra.get("payload", "")
    unique = extra.get("unique_marker")
    expected = extra.get("expected_delay")
    text = response.get("text", "")
    elapsed_time = response.get("elapsed_time", 0)
    response_time_ms = elapsed_time * 1000  # 초를 밀리초로 변환
    sc = response.get("status_code", 200)

    # 1. Reflected
    if unique and f"CMDTEST{unique}" in text:
        return {"payload": payload, "evidence": f"고유 마커 CMDTEST{unique} 반영"}

    # 2. Time-based (5초 이상)
    if response_time_ms >= 5000.00:
        seconds = response_time_ms / 1000.0
        return {
            "payload": payload,
            "evidence": f"응답 지연(타임아웃) 탐지: {seconds:.2f}초 (5초 이상 지연)",
        }

    # 3. Pattern-based
    patterns = [
        r"uid=\\d+\\([^)]+\\)\\s+gid=\\d+\\([^)]+\\)",
        r"root:.*?:0:0:",
        r"/(?:bin|usr|etc|var|tmp|home)/[A-Za-z0-9_/.-]*",
        r"[A-Z]:\\\\(?:Windows|Program Files|Users)\\\\",
        r"Linux.*?\\d+\.\\d+\.\\d+",
        r"Darwin.*?\\d+\.\\d+\.\\d+",
        r"Microsoft Windows.*?Version \\d+\.\\d+",
        r"total \\d+",
        r"Directory of [A-Z]:\\\\",
    ]
    for pat in patterns:
        if re.search(pat, text, re.MULTILINE | re.IGNORECASE):
            return {"payload": payload, "evidence": f"패턴 매칭: {pat}"}

    # 4. Error-based
    errors = [
        r"command not found",
        r"is not recognized as an internal or external command",
    ]
    for err in errors:
        if re.search(err, text, re.IGNORECASE):
            return {"payload": payload, "evidence": f"오류 메시지 탐지: {err}"}

    # 5. Status-code-based
    if sc in [500, 502, 503, 504]:
        return {"payload": payload, "evidence": f"서버 오류 코드 {sc}"}

    # 6. Empty-response
    if not text.strip() and extra.get("detection_type") == "general" and sc == 200:
        return {"payload": payload, "evidence": "빈 응답 가능성"}

    # 7. Suspicious-string
    sus = [
        "root:",
        "admin:",
        "administrator",
        "bin/bash",
        "cmd.exe",
        "Program Files",
        "etc/passwd",
        "etc/hosts",
    ]
    for s in sus:
        if s.lower() in text.lower():
            return {"payload": payload, "evidence": f"의심 문자열: {s}"}

    return {}
