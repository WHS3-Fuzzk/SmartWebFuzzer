"""
stored_xss_detector.py

Stored XSS 취약점 스캐너 모듈에서 발생시킨 요청을
이후, 프록시를 통해 수집한 정보에서 검출하는 모듈입니다.
"""

import json
import re
from typing import List

from db_reader import DBReader
from db_writer import insert_vulnerability_scan_result

def extract_ids_from_json_payload(response_body: str, payload_prefix="whs3fuzzk-"):
    """
    JSON 응답에서 whs3fuzzk-{request_id}-{param_id} 패턴을 찾아 request_id, param_id 추출
    """
    try:
        json_data = json.loads(response_body)
    except Exception:
        return []

    results = []
    pattern = re.compile(rf"{payload_prefix}(\d+)-(\d+)")
    def recursive_search(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                recursive_search(v)
        elif isinstance(obj, list):
            for item in obj:
                recursive_search(item)
        elif isinstance(obj, str):
            for m in pattern.findall(obj):
                results.append(m)
    recursive_search(json_data)
    return results

def analyze_stored_xss_flow(response: dict) -> List[dict]:
    """
    mitmproxy HTTPFlow 객체를 dict형식으로 변환한 후
    Stored XSS 페이로드 반영 여부를 분석 (reflected_xss의 analyze_response와 유사)
    이제는 payload와 함께 parameter명을 직접 추출하여 기록
    """
    reader = DBReader()
    # payload + request_id + param_id
    pattern = re.compile(r'\'"fake=whs3fuzzk-(\d+)-(\d+)>')
    body_dict = response.get("body")
    if isinstance(body_dict, dict):
        response_body = body_dict.get("body", "")
    else:
        response_body = ""

    matches = pattern.findall(response_body)
    if not matches:
        print("[S_XSS] 페이로드가 응답에 없음")
        json_matches = extract_ids_from_json_payload(response_body)
        if json_matches:
            print("[S_XSS] JSON 응답에서 페이로드가 탐지됨")
            matches = json_matches
        else:
            print("[S_XSS] JSON 응답에서도 페이로드 없음")
            return []
    print(f"[S_XSS] 총 {len(matches)}개의 페이로드 탐지됨")

    all_fuzzed_requests = reader.select_fuzzed_request_with_original_id_all(int(matches[0][0]))
    if not all_fuzzed_requests:
        print(f"[S_XSS] fuzzed_request 조회 실패: request_id={matches[0][0]}")
        return []

    # DB에 저장할 dict 구성
    results = []
    for req_id_str, param_id_str in matches:
        request_id = int(req_id_str)
        param_id = int(param_id_str)

        matched_fuzzed_request = None
        for fr in all_fuzzed_requests:
            payload_meta = fr["meta"].get("payload", "")
            if payload_meta.endswith(f":{param_id}"):
                matched_fuzzed_request = fr
                break

        if not matched_fuzzed_request:
            print(f"[S_XSS] param_id={param_id}에 맞는 fuzzed_request가 없음")
            continue

        payload_param = matched_fuzzed_request["meta"].get("payload", "")
        parts = payload_param.split(":")
        payload = parts[0] if len(parts) >= 1 else ""
        parameter = parts[1] if len(parts) >= 2 else ""

        scan_result = {
            "vulnerability_name": "stored_xss",
            "original_request_id": request_id,
            "fuzzed_request_id": matched_fuzzed_request["meta"].get("id"),
            "domain": matched_fuzzed_request["meta"].get("domain"),
            "endpoint": matched_fuzzed_request["meta"].get("path"),
            "method": matched_fuzzed_request["meta"].get("method"),
            "payload": payload,
            "parameter": parameter,
            "extra": {},
        }

        insert_vulnerability_scan_result(scan_result)
        results.append(scan_result)

    return results
