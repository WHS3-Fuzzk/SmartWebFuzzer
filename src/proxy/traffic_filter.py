"""
mitmproxy를 이용한 요청/응답 필터링 및 로그 저장 스크립트
"""

import os
import re
import urllib.parse

from mitmproxy import http

# 요청/응답 중복 식별용 set
seen_request_keys = set()
seen_response_keys = set()

# 중요 파라미터 키 (값까지 체크 대상)
KEY_PARAMS_TO_INCLUDE_VALUES = {"cmd", "action", "mode", "type"}

TARGET_DOMAINS = ["testphp.vulnweb.com", "naver.com"]

LOG_DIR = os.path.abspath(os.path.dirname(__file__))
REQUESTS_LOG = os.path.join(LOG_DIR, "requests.log")
RESPONSES_LOG = os.path.join(LOG_DIR, "responses.log")

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


def ensure_log_file(path: str) -> None:
    """로그 파일이 없으면 빈 파일 생성"""
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8"):
            pass


ensure_log_file(REQUESTS_LOG)
ensure_log_file(RESPONSES_LOG)


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
            (k, tuple(query_params[k]))
            for k in query_params
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

    log_line = f"{flow.request.method} {flow.request.pretty_url}\n"
    with open(REQUESTS_LOG, "a", encoding="utf-8") as _:
        _.write(log_line)


def response(flow: http.HTTPFlow) -> None:
    """
    mitmproxy 응답 이벤트 처리
    """
    if not is_valid_response(flow):
        return

    url = flow.request.pretty_url.lower()
    if is_excluded_url(url):
        return

    if is_duplicated_by_flow(flow, mode="response"):
        return

    log_line = f"{flow.request.method} {flow.request.pretty_url}\n"
    with open(RESPONSES_LOG, "a", encoding="utf-8") as _:
        _.write(log_line)
