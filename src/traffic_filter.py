"""
[요청/응답 필터링 모듈]
mitmproxy를 이용한 요청/응답 필터링 및 로그 저장 스크립트
"""

import os
import re
import urllib.parse
from datetime import datetime

from mitmproxy import http

from db_writer import (
    insert_filtered_request,
    insert_filtered_response,
    insert_preflight_request,
)
from recon import run_recon

# flow.id 와 request_id 매핑용
flow_id_to_request_id_map = {}

# 요청/응답 중복 식별용 set
seen_request_keys = set()
seen_response_keys = set()

# 중요 파라미터 키 (값까지 체크 대상)
KEY_PARAMS_TO_INCLUDE_VALUES = {"cmd", "action", "mode", "type"}

# 타겟 도메인 리스트 환경변수에서 불러오기
domains_str = os.getenv("TARGET_DOMAINS", "")
TARGET_DOMAINS = [d.strip() for d in domains_str.split(",") if d.strip()]

# 제외할 URL 패턴 정의 (정적 리소스 등)
EXCLUDED_PATTERNS = [
    "favicon",
    "robots\\.txt",
    "\\.ico$",
    "\\.png$",
    "\\.jpg$",
    "\\.css$",
    "\\.js$",
    "\\.gif$",
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

    identifier = (base_url, param_keys_only, important_param_pairs)

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


def flow_to_request_dict(flow: http.HTTPFlow) -> dict:
    """
    insert_filtered_request 인터페이스에 맞게 변환
    """
    query_params = []
    for k, v in flow.request.query.items(multi=True):
        query_params.append({"key": k, "value": v, "source": "url"})

    content_type = flow.request.headers.get("content-type", "")
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

    scheme = flow.request.scheme.lower()
    is_http = 1 if scheme in ("http", "https") else 0

    request_dict = {
        "is_http": is_http,
        "http_version": flow.request.http_version,
        "domain": flow.request.host,
        "path": flow.request.path,
        "method": flow.request.method,
        "timestamp": datetime.now(),
        "headers": dict(flow.request.headers),
        "query": query_params,
        "body": body_dict,
    }
    return request_dict


def flow_to_response_dict(flow: http.HTTPFlow) -> dict:
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
        "http_version": flow.response.http_version if flow.response else "",
        "status_code": flow.response.status_code if flow.response else 0,
        "timestamp": datetime.now(),
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

    # OPTIONS 요청 → 프리플라이트 수집용으로 태깅
    if flow.request.method == "OPTIONS":
        flow.metadata["is_preflight"] = True
        return

    if is_duplicated_by_flow(flow, mode="request"):
        return

    run_recon(flow.request.host, flow.request.path)

    request_dict = flow_to_request_dict(flow)
    request_id = insert_filtered_request(request_dict)

    flow_id_to_request_id_map[flow.id] = request_id


def response(flow: http.HTTPFlow) -> None:
    """
    mitmproxy 응답 이벤트 처리
    """
    if not is_valid_request(flow):
        return

    url = flow.request.pretty_url.lower()
    if is_excluded_url(url):
        return

    # 프리플라이트 응답 처리
    if flow.request.method == "OPTIONS" and flow.metadata.get("is_preflight"):
        assert flow.response is not None  # IDE 타입 안정성 확보

        status_code = flow.response.status_code
        allow_origin = flow.response.headers.get("Access-Control-Allow-Origin")
        allow_methods = flow.response.headers.get("Access-Control-Allow-Methods")
        preflight_allowed = status_code == 200 and allow_origin and allow_methods

        preflight_data = {
            "domain": flow.request.host,
            "path": flow.request.path,
            "origin": flow.request.headers.get("Origin"),
            "access_control_request_method": flow.request.headers.get(
                "Access-Control-Request-Method"
            ),
            "timestamp": datetime.now(),
            "headers": dict(flow.response.headers),
            "preflight_allowed": preflight_allowed,
        }
        insert_preflight_request(preflight_data)
        return

    if not is_valid_response(flow):
        return

    if is_duplicated_by_flow(flow, mode="response"):
        return

    response_dict = flow_to_response_dict(flow)
    request_id = flow_id_to_request_id_map.get(flow.id)

    if request_id is not None:
        insert_filtered_response(response_dict, request_id)
    else:
        print(
            f"[Error] request_id를 찾을 수 없습니다 (flow.id: {flow.id}). 응답을 저장하지 않습니다."
        )
