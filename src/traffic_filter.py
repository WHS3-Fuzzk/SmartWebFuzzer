"""
[요청/응답 필터링 모듈]
mitmproxy를 이용한 요청/응답 필터링 및 로그 저장 스크립트
"""

import os
import re
import urllib.parse
from datetime import datetime

from mitmproxy import http

from stored_xss_detector import analyze_stored_xss_flow
from db_writer import insert_filtered_request, insert_filtered_response
from recon import run_recon

# flow.id 와 request_id 매핑용
flow_id_to_request_id_map = {}

# 요청/응답 중복 식별용 set
seen_request_keys = set()
seen_response_keys = set()

# 중요 파라미터 키 (값까지 체크 대상)
KEY_PARAMS_TO_INCLUDE_VALUES = {"cmd", "action", "mode", "type"}

domains_str = os.getenv("TARGET_DOMAINS", "")
TARGET_DOMAINS = [d.strip() for d in domains_str.split(",") if d.strip()]


EXCLUDED_PATTERNS = [
    "favicon",
    "robots\\.txt",
    "\\.ico$",
    "\\.png$",
    "\\.jpg$",
    "\\.css$",
    "\\.js$",
    "\\.gif$",
    "\\.svg$",
    "\\.woff2?$",
    "\\.ttf$",
    "\\.eot$",
    "\\.otf$",
]


def is_excluded_url(url: str) -> bool:
    """
    URL이 제외 패턴에 일치하는지 검사
    """
    return any(re.search(pattern, url) for pattern in EXCLUDED_PATTERNS)


def build_view_filter(domains: list) -> str:
    """
    도메인 리스트와 제외 패턴으로 mitmproxy view-filter 문자열 생성
    """
    excluded_filter = " & ".join([f'!~u "{pattern}"' for pattern in EXCLUDED_PATTERNS])
    filters = [f"(~d {domain} & {excluded_filter})" for domain in domains]
    return " | ".join(filters)


def is_duplicated_by_flow(flow: http.HTTPFlow, mode: str = "request") -> bool:
    """
    요청 또는 응답이 중복인지 판단
    """
    parsed_url = urllib.parse.urlparse(flow.request.url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    query_params = urllib.parse.parse_qs(parsed_url.query)

    param_keys_only = tuple(sorted(query_params.keys()))
    important_param_pairs = tuple(
        sorted(
            (k, tuple(v))
            for k, v in query_params.items()
            if k in KEY_PARAMS_TO_INCLUDE_VALUES
        )
    )

    method = flow.request.method  # 'GET', 'POST', 등
    identifier = (method, base_url, param_keys_only, important_param_pairs)

    if mode == "request":
        if identifier in seen_request_keys:
            return True
        seen_request_keys.add(identifier)
        return False

    if mode == "response":
        if identifier in seen_response_keys:
            return True
        seen_response_keys.add(identifier)
        return False

    return False


def is_valid_request(flow: http.HTTPFlow) -> bool:
    """
    타겟 도메인이 포함된 요청인지 검사
    """
    host = flow.request.pretty_host.lower()
    return any(target in host for target in TARGET_DOMAINS)


def is_valid_response(flow: http.HTTPFlow) -> bool:
    """
    타겟 도메인이 포함되고 304 제외, 3XX는 포함한 응답인지 검사
    """
    if not flow.response:
        return False

    host = flow.request.pretty_host.lower()
    if not any(target in host for target in TARGET_DOMAINS):
        return False

    status_code = flow.response.status_code
    if status_code == 304:
        return False

    if 300 <= status_code < 400:
        return True

    return True


def flow_to_request_dict(flow: http.HTTPFlow):
    """
    insert_filtered_request 인터페이스에 맞게 변환
    """
    # 쿼리 파라미터 변환
    query_params = []
    for k, v in flow.request.query.items(multi=True):
        query_params.append({"key": k, "value": v, "source": "url"})

    # body 변환
    content_type = flow.request.headers.get("content-type", "")
    # charset 파싱
    charset = "utf-8"
    if "charset=" in content_type:
        charset = content_type.split("charset=")[-1].split(";")[0].strip()
    content_length = int(
        flow.request.headers.get("content-length", len(flow.request.raw_content or b""))
    )
    content_encoding = flow.request.headers.get("content-encoding", "identity")
    body = flow.request.get_text(strict=False) if flow.request.raw_content else ""

    body_dict = (
        {
            "content_type": content_type,
            "charset": charset,
            "content_length": content_length,
            "content_encoding": content_encoding,
            "body": body,
        }
        if body
        else None
    )

    # HTTP/HTTPS 구분 (HTTP=1, HTTPS=0, 기타= -1)
    scheme = flow.request.scheme.lower()

    if scheme == "http":
        is_http = 1
    elif scheme == "https":
        is_http = 0
    else:
        is_http = -1

    # flow.request.path에서 ?를 기준으로 쿼리 파라미터 제거
    path = flow.request.path.split("?")[0]

    request_dict = {
        "is_http": is_http,
        "http_version": flow.request.http_version,
        "domain": flow.request.host,
        "path": path,
        "method": flow.request.method,
        "timestamp": datetime.fromtimestamp(flow.request.timestamp_start),
        "headers": dict(flow.request.headers),
        "query": query_params,
        "body": body_dict,
    }
    return request_dict


def flow_to_response_dict(flow: http.HTTPFlow):
    """
    insert_filtered_response 인터페이스에 맞게 변환
    """
    headers = dict(flow.response.headers) if flow.response else {}

    if flow.response and flow.response.raw_content:
        content_type = flow.response.headers.get("content-type", "")
        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.split("charset=")[-1].split(";")[0].strip()
        content_length = int(
            flow.response.headers.get("content-length", len(flow.response.raw_content))
        )
        content_encoding = flow.response.headers.get("content-encoding", "identity")
        body = flow.response.get_text(strict=False)
        body_dict = {
            "content_type": content_type,
            "charset": charset,
            "content_length": content_length,
            "content_encoding": content_encoding,
            "body": body,
        }
    else:
        body_dict = None

    response_dict = {
        "http_version": flow.response.http_version if flow.response else "-1",
        "status_code": flow.response.status_code if flow.response else -1,
        "timestamp": datetime.fromtimestamp(
            flow.response.timestamp_start if flow.response else -1
        ),
        "headers": headers,
        "body": body_dict,
    }
    return response_dict


def request(flow: http.HTTPFlow) -> None:
    """
    mitmproxy 요청 이벤트 처리
    """
    if not is_valid_request(flow):
        return

    url = flow.request.pretty_url.lower()
    if is_excluded_url(url):
        return

    if is_duplicated_by_flow(flow, mode="request"):
        return

    run_recon(flow.request.host, flow.request.path)

    request_dict = flow_to_request_dict(flow)
    request_id = insert_filtered_request(request_dict)

    # flow.id와 request_id 매핑하여 저장 -> 응답에서 사용
    flow_id_to_request_id_map[flow.id] = request_id


def response(flow: http.HTTPFlow) -> None:
    """
    mitmproxy 응답 이벤트 처리
    """
    if not is_valid_response(flow):
        return

    url = flow.request.pretty_url.lower()
    if is_excluded_url(url):
        return

    # 응답 저장 (DB_Writer)
    response_dict = flow_to_response_dict(flow)

    # Stored XSS 분석
    # print(f"[BEFORE_STORED_XSS]{response_dict}")
    findings = analyze_stored_xss_flow(response_dict)
    # print(f"[S_XSS] Stored XSS 분석 결과: {findings}")

    if is_duplicated_by_flow(flow, mode="response"):
        return

    # flow.id로 이 응답에 대응하는 request_id 조회
    request_id = flow_id_to_request_id_map.get(flow.id)

    if request_id is not None:
        insert_filtered_response(response_dict, request_id)
    else:
        print(
            f"[Error] request_id를 찾을 수 없습니다 (flow.id: {flow.id}). 응답을 저장하지 않습니다."
        )
