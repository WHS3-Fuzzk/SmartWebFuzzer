# pylint: skip-file
"""
stored_xss_detector.py

Stored XSS 취약점 스캐너 모듈에서 발생시킨 요청을
이후, 프록시를 통해 수집한 정보에서 검출하는 모듈입니다.
"""

import json
import re
from typing import List
from bs4 import BeautifulSoup

from db_reader import DBReader
from db_writer import insert_vulnerability_scan_result

def append_custom_tag_surrounding_info(results: list, custom_tag) -> None:
    """
    커스텀 태그 주변 정보(부모, 이전/다음 형제 태그) 결과 리스트에 추가
    """
    results.append(f"[커스텀 태그 발견] <{custom_tag.name}> → {str(custom_tag)}")

    parent = custom_tag.parent
    if parent:
        results.append(f"  - 부모 태그: <{parent.name}> → {str(parent)}")

    for sibling, desc in [
        (custom_tag.previous_sibling, "이전"),
        (custom_tag.next_sibling, "다음"),
    ]:
        if sibling and getattr(sibling, "name", None):
            results.append(f"  - {desc} 형제 태그: <{sibling.name}> → {str(sibling)}")

    results.append("")


def inspect_custom_tag_attributes(soup, tag_regex, payload) -> List[str]:
    """
    whs3fuzzk-* 태그가 생성되었을 때 해당 속성 및 주변 정보를 수집
    """
    results = []
    found_in_attr = False

    results.append("=== <whs3fuzzk-*> 태그가 생성됨 → 모든 태그에서 속성 검사 시작 ===")
    for tag in soup.find_all(True):
        if not re.match(tag_regex, tag.name):
            continue
        for attr, value in tag.attrs.items():
            if not isinstance(value, (str, list)):
                continue
            if isinstance(value, str):
                if re.search(tag_regex, value):
                    found_in_attr = True
                    results.append(
                        f"<{tag.name}> 태그의 '{attr}' 속성에서 발견 → {value}"
                    )
                    results.append(f"→ (테스트 페이로드: '{payload}')")
                    results.append(f"→ 해당 태그 전체: {str(tag)}")
            if isinstance(value, list):
                matched_items = [item for item in value if re.search(tag_regex, item)]
                if matched_items:
                    found_in_attr = True
                    for item in matched_items:
                        results.append(
                            f"<{tag.name}> 태그의 '{attr}' 속성(list)에서 발견 → {item}"
                        )
                        results.append(f"→ (테스트 페이로드: '{payload}')")
                        results.append(f"→ 해당 태그 전체: {str(tag)}")

    # 속성에서 발견 못했을 경우, 커스텀 태그 주변 정보 출력
    if not found_in_attr:
        custom_tags = soup.find_all(tag_regex)
        for ctag in custom_tags:
            append_custom_tag_surrounding_info(results, ctag)

    return results


def check_payload_in_attributes(html_text, payload):
    """
    HTML 내에서 페이로드가 속성(attribute) 값에 반영됐는지 검사
    HTML 내에서 whs3fuzzk-숫자 패턴을 찾아 반환
    """
    results = []
    soup = BeautifulSoup(html_text, "html.parser")
    tag_regex = re.compile(r"^whs3fuzzk-(\d+)-(\d+)")
    custom_tags = soup.find_all(tag_regex)
    if custom_tags:
        results += inspect_custom_tag_attributes(soup, tag_regex, payload)
    else:
        print("[-] <whs3fuzzk-*> 태그는 생성되지 않음. 속성 검사 생략됨.")
    
    return results


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
    pattern = re.compile(r'whs3fuzzk-(\d+)-(\d+)')
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

    all_fuzzed_requests = reader.select_fuzzed_request_with_original_id_all(
        int(matches[0][0])
    )
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
            "extra": {
                "attribute_check": check_payload_in_attributes(response_body, pattern),

            },
        }

        insert_vulnerability_scan_result(scan_result)
        results.append(scan_result)

    return results
