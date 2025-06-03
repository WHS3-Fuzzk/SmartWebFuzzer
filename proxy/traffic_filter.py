from mitmproxy import http
from urllib.parse import urlparse, parse_qs
import os
import re
import urllib.parse


# 요청/응답 각각을 구분해 저장할 set
seen_request_keys = set()
seen_response_keys = set()

# 예시: 중요하게 여겨야 하는 파라미터 이름들 화이트리스트 기반
KEY_PARAMS_TO_INCLUDE_VALUES = {"cmd", "action", "mode", "type"}

def is_duplicated_by_flow(flow: http.HTTPFlow, mode: str = "request") -> bool:
    parsed_url = urllib.parse.urlparse(flow.request.url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    query_params = urllib.parse.parse_qs(parsed_url.query)

    # 일반 파라미터: key만 정렬
    param_keys_only = tuple(sorted(query_params.keys()))

    # 중요 파라미터: key + value 조합 포함
    important_param_pairs = tuple(
        sorted((k, tuple(query_params[k])) for k in query_params if k in KEY_PARAMS_TO_INCLUDE_VALUES)
    )

    # 식별자 구성: base_url + key만 파라미터 + 중요 파라미터 key-value
    identifier = (base_url, param_keys_only, important_param_pairs)

    # 각각 요청/응답 저장소에서 처리
    if mode == "request":
        if identifier in seen_request_keys:
            return True
        seen_request_keys.add(identifier)
        return False

    elif mode == "response":
        if identifier in seen_response_keys:
            return True
        seen_response_keys.add(identifier)
        return False

    return False

# 타겟 도메인 리스트 (여기에 원하는 도메인 추가)
TARGET_DOMAINS = [
    "testphp.vulnweb.com",
    "naver.com"
]

LOG_DIR = os.path.abspath(os.path.dirname(__file__))
REQUESTS_LOG = os.path.join(LOG_DIR, "requests.log")
RESPONSES_LOG = os.path.join(LOG_DIR, "responses.log")

def ensure_log_file(path):
    """로그 파일이 없으면 빈 파일로 생성"""
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            pass

ensure_log_file(REQUESTS_LOG)
ensure_log_file(RESPONSES_LOG)

# 제외할 URL 패턴 리스트(정규식)
EXCLUDED_PATTERNS = [
    "favicon",
    "robots\\.txt",
    "\\.ico$",
    "\\.png$",
    "\\.jpg$",
    "\\.css$",
    "\\.js$",
    "\\.gif$"
]



def is_excluded_url(url: str) -> bool:
    """
    URL이 제외 패턴에 일치하는지 검사
    """
    for pattern in EXCLUDED_PATTERNS:
        if re.search(pattern, url):
            return True
    return False


def build_view_filter(domains):
    """
    도메인 리스트와 제외 패턴을 받아 mitmproxy view-filter 문자열을 생성한다.
    Args:
        domains (list): 타겟 도메인 리스트
    Returns:
        str: mitmproxy view-filter 문자열
    """
    # 제외 조건들을 AND로 조합
    excluded_filter = " & ".join([f'!~u "{pattern}"' for pattern in EXCLUDED_PATTERNS])
    # 각 도메인별로 필터 생성
    filters = [
        f'(~d {domain} & {excluded_filter})'
        for domain in domains
    ]
    return " | ".join(filters)

def is_valid_request(flow: http.HTTPFlow) -> bool:
    """
    요청 필터링: 의미 있는 트래픽만 통과
    """

    host = flow.request.pretty_host.lower()

    # 타겟 도메인을 포함하는 경우만 허용
    if not any(target in host for target in TARGET_DOMAINS):
        return False

    return True

def is_valid_response(flow: http.HTTPFlow) -> bool:
    """
    응답 필터링: 3XX 중에서도 304는 제외
    """
    if not flow.response:
        return False
    host = flow.request.pretty_host.lower()

    # 타겟 도메인을 포함하는 경우만 허용
    if not any(target in host for target in TARGET_DOMAINS):
        return False

    status_code = flow.response.status_code

    # 304는 저장하지 않음
    if status_code == 304:
        return False

    # 3XX (300~399) 상태코드는 저장 (open redirect 탐지 목적)
    if 300 <= status_code < 400:
        return True

    # 그 외는 모두 저장
    return True




def request(flow: http.HTTPFlow):
    if is_valid_request(flow):
        url = flow.request.pretty_url.lower()
        if is_excluded_url(url):
            return  # 제외 패턴에 해당하면 저장하지 않음
        if is_duplicated_by_flow(flow, mode="request"):
            return
        log_line = f"{flow.request.method} {flow.request.pretty_url}\n"
        #print(f"[VALID REQUEST] {flow.request.method} {flow.request.pretty_url}")
        with open(REQUESTS_LOG, "a", encoding="utf-8") as f:
            f.write(log_line)
        # DB 저장 또는 후속 처리 로직 추가 가능

    
def response(flow: http.HTTPFlow):
    if is_valid_response(flow) and (flow):
        url = flow.request.pretty_url.lower()
        if is_excluded_url(url):
            return  # 제외 패턴에 해당하면 저장하지 않음
        if is_duplicated_by_flow(flow, mode="response"):
            return
        log_line = f"{flow.request.method} {flow.request.pretty_url}\n"
        #print(f"[VALID RESPONSE] {flow.request.pretty_url} -> {flow.response.status_code}")
        with open(RESPONSES_LOG, "a", encoding="utf-8") as f:
            f.write(log_line)
        # DB 저장 또는 후속 처리 로직 추가 가능

