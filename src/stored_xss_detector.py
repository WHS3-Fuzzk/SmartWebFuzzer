"""
stored_xss_detector.py

Stored XSS 취약점 스캐너 모듈에서 발생시킨 요청을
이후, 프록시를 통해 수집한 정보에서 검출하는 모듈입니다.
"""

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
    tag_regex = re.compile(r"^whs3fuzzk-(\d+)")
    custom_tags = soup.find_all(tag_regex)
    if custom_tags:
        results += inspect_custom_tag_attributes(soup, tag_regex, payload)
    else:
        print("[-] <whs3fuzzk-*> 태그는 생성되지 않음. 속성 검사 생략됨.")

    return results


def analyze_stored_xss_flow(response: dict) -> dict:
    """
    mitmproxy HTTPFlow 객체에서 Stored XSS 페이로드 반영 여부를 분석 (reflected_xss의 analyze_response와 유사)
    """
    reader = DBReader()
    pattern = re.compile(r'\'"fake=whs3fuzzk-(\d+)>')
    body_dict = response.get("body")
    if isinstance(body_dict, dict):
        response_body = body_dict.get("body", "")
    else:
        response_body = ""

    match = pattern.search(response_body)
    if not match:
        print("[S_XSS] 페이로드가 응답에 없음")
        return {}

    request_id = int(match.group(1))
    fuzzed_request = reader.select_fuzzed_request_with_original_id(request_id)
    if not fuzzed_request:
        print(f"[S_XSS] fuzzed_request 조회 실패: request_id={request_id}")
        return {}
    print(f"[S_XSS] fuzzed_request 조회 성공! request_id: {request_id}")

    # DB에 저장할 dict 구성
    payload_param = fuzzed_request["meta"].get("payload", "")
    if ":" in payload_param:
        payload, parameter = payload_param.split(":", 1)
    else:
        payload, parameter = payload_param, ""
    scan_result = {
        "vulnerability_name": "stored_xss",
        "original_request_id": request_id,
        "fuzzed_request_id": fuzzed_request["meta"].get("id"),
        "domain": fuzzed_request["meta"].get("domain"),
        "endpoint": fuzzed_request["meta"].get("path"),
        "method": fuzzed_request["meta"].get("method"),
        "payload": payload,
        "parameter": parameter,
        "extra": {
            "attribute_check": check_payload_in_attributes(response_body, pattern),
        },
    }
    insert_vulnerability_scan_result(scan_result)
    return scan_result
