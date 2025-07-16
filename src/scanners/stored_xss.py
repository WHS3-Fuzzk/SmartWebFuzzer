# pylint: skip-file
"""
stored_xss.py

Stored XSS 취약점 스캐너 모듈입니다.
"""

import urllib.parse

import json
import copy
from typing import Any, Dict, Iterable, List
from datetime import datetime

from db_writer import insert_fuzzed_request, insert_fuzzed_response
from scanners.base import BaseScanner
from fuzzing_scheduler.fuzzing_scheduler import send_fuzz_request
from typedefs import RequestData
from scanners.utils import to_fuzzed_request_dict, to_fuzzed_response_dict

# from fuzzing_scheduler.fuzzing_scheduler import requestdata_to_requests_kwargs
# import requests


def realdictrow_to_dict(obj):
    """
    DB에서 가져온 정보 변환
    dictRow, dict, list, datetime 객체를 재귀적으로 dict/리스트/문자열로 변환
    """
    if isinstance(obj, list):
        return [realdictrow_to_dict(i) for i in obj]
    if hasattr(obj, "keys") and hasattr(obj, "__getitem__"):
        return {k: realdictrow_to_dict(obj[k]) for k in obj.keys()}
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


class StoredXSS(BaseScanner):
    """
    BaseScanner를 상속받아 Stored XSS 취약점 스캐너 구현
    """

    @property
    def vulnerability_name(self) -> str:
        return "stored_xss"

    def __init__(self):
        """
        단일 페이로드에 request_id를 포함하여 사용할 것.
        """
        self.payload_template = "'\"fake=whs3fuzzk-{rid}-{pid}><whs3fuzzk-{rid}-{pid}>"

    def get_payload(self, request_id: int, param_id: int) -> str:
        """
        request_id를 포함한 페이로드 생성
        """
        return self.payload_template.format(rid=request_id, pid=param_id)

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """
        우선 POST + x-www-form-urlencoded, json, form-data 형태의 요청을 대상으로 함
        + 이후 GET 요청이나 JSON 형태도 추가하는 느낌으로..
        """
        method = request["meta"].get("method", "")
        headers = request.get("headers") or []
        content_type = ""
        for header in headers:
            if header.get("key", "").lower() == "content-type":
                content_type = header.get("value", "")
        if method == "POST":
            if "application/x-www-form-urlencoded" in content_type:
                return True
            if "application/json" in content_type:
                return True
            if "multipart/form-data" in content_type:
                return True
        return False

    def generate_fuzzing_requests(
        self,
        request: RequestData,
        request_id: int,  # 이 request_id를 어떻게 해야할까요... base를 바꿔야하나.. 필요하긴 함..근데
    ) -> Iterable[RequestData]:
        body = request.get("body")
        if not body or not body.get("body"):
            return
        content_type = (body.get("content_type") or "").lower()
        raw_body = body.get("body", "")
        headers = request.get("headers") or []
        if "application/x-www-form-urlencoded" in content_type:
            params = urllib.parse.parse_qsl(raw_body, keep_blank_values=True)
            for param_id, (k, v) in enumerate(params):
                payload = self.get_payload(request_id, param_id)
                new_params = list(params)
                new_params[param_id] = (k, payload)
                new_body_str = urllib.parse.urlencode(new_params)
                new_content_length = str(len(new_body_str.encode("utf-8")))
                # deepcopy로 원본 훼손 방지
                new_request = copy.deepcopy(request)
                new_request["headers"] = [h.copy() for h in headers]
                for h in new_request["headers"]:
                    if h["key"].lower() == "content-length":
                        h["value"] = new_content_length
                new_request["body"] = body.copy()
                new_request["body"]["body"] = new_body_str
                new_request["body"]["content_length"] = int(new_content_length)
                new_request["extra"] = {
                    "fuzzed_param": k,
                    "payload": payload,
                    "param_id": param_id,
                    "type": "stored_xss",
                }
                # print(f"{request}")
                # print("------------------------")
                print(f"{new_request}")
                print("------------------------")

                yield new_request
        elif "application/json" in content_type:
            try:
                params = json.loads(raw_body)
            except Exception as e:
                print(f"JSON 파싱 오류: {e}")
                return
            if isinstance(params, dict):
                for param_id, k in enumerate(params.keys()):
                    payload = self.get_payload(request_id, param_id)
                    new_params = params.copy()
                    new_params[k] = payload
                    new_body_str = json.dumps(new_params, ensure_ascii=False)
                    new_content_length = str(len(new_body_str.encode("utf-8")))
                    new_request = copy.deepcopy(request)
                    new_request["headers"] = [h.copy() for h in headers]
                    for h in new_request["headers"]:
                        if h["key"].lower() == "content-length":
                            h["value"] = new_content_length
                    new_request["body"] = body.copy()
                    new_request["body"]["body"] = new_body_str
                    new_request["body"]["content_length"] = int(new_content_length)
                    new_request["extra"] = {
                        "fuzzed_param": k,
                        "payload": payload,
                        "param_id": param_id,
                        "type": "stored_xss",
                    }
                    print(f"{new_request}")
                    print("------------------------")
                    yield new_request
        # TODO: json, multipart/form-data 등은 추후 구현 필요

    def run(
        self,
        request_id: int,
        request: RequestData,
    ) -> List[Dict[str, Any]]:
        """
        Stored XSS용 퍼징 요청 생성 및 전송
        """
        if not self.is_target(request_id, request):
            return []

        print(
            "[+] This is Target for Stored XSS scanner on request ID:", request_id
        )  # 테스트용 출력
        # results = []
        for fuzz_request in self.generate_fuzzing_requests(request, request_id):
            # fuzz_request_dict = realdictrow_to_dict(fuzz_request)

            # Celery에 단일 태스크만 큐에 넣음
            result = send_fuzz_request.delay(fuzz_request)
            response = result.get(timeout=30)
            # DB에 저장
            fuzz_request_dict = to_fuzzed_request_dict(
                fuzzing_request=fuzz_request,
                original_request_id=request_id,
                scanner=self.vulnerability_name,
                payload="{}:{}:{}".format(
                    fuzz_request.get("extra", {}).get("payload", ""),
                    fuzz_request.get("extra", {}).get("fuzzed_param", ""),
                    fuzz_request.get("extra", {}).get("param_id", ""),
                ),
            )
            try:
                fuzzed_request_id = insert_fuzzed_request(fuzz_request_dict)
                insert_fuzzed_response(
                    to_fuzzed_response_dict(response), fuzzed_request_id
                )
                print(f"퍼징 요청 저장 완료: {fuzzed_request_id}")
            except Exception as e:
                print(f"DB 저장 중 오류 발생: {e}")

        return []
