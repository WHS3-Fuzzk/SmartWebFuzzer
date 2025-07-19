"""
Fuzzing 요청/응답을 dict로 변환하는 유틸리티 함수 모음.
"""

from typedefs import RequestData


def to_fuzzed_request_dict(
    fuzzing_request: RequestData,
    original_request_id: int,
    scanner: str,
    payload: str,
) -> dict:
    """
    traffic_filter.py의 flow_to_request_dict 구조에 맞게 변환
    headers: 리스트→dict 변환, query_params는 'query'로 저장
    """
    meta = fuzzing_request["meta"]
    headers = fuzzing_request.get("headers")
    headers_dict = {}
    if headers:
        for h in headers:
            headers_dict[h["key"]] = h["value"]
    return {
        "original_request_id": original_request_id,
        "scanner": scanner,
        "payload": payload,
        "is_http": meta.get("is_http"),
        "http_version": meta.get("http_version"),
        "domain": meta.get("domain"),
        "path": meta.get("path"),
        "method": meta.get("method"),
        "timestamp": meta.get("timestamp"),
        "headers": headers_dict,
        "query": fuzzing_request.get("query_params", []),
        "body": fuzzing_request.get("body"),
    }


def to_fuzzed_response_dict(
    fuzzed_response: dict,
    remove_null: bool = False,
) -> dict:
    """
    traffic_filter.py의 flow_to_response_dict 구조에 맞게 변환
    remove_null=True로 하면 body에서 널 문자(\x00) 제거
    """
    headers = fuzzed_response.get("headers", {})
    content_type = headers.get("Content-Type", "")
    charset = None
    if "charset=" in content_type.lower():
        charset = content_type.split("charset=")[-1].strip()
    body = fuzzed_response.get("body")
    if remove_null:
        if isinstance(body, str):
            body = body.replace("\x00", "")
        elif isinstance(body, bytes):
            body = body.replace(b"\x00", b"")
        elif isinstance(body, memoryview):
            body = body.tobytes().replace(b"\x00", b"")

    # content-length 계산
    content_length = headers.get("Content-Length")
    if content_length is not None:
        try:
            content_length = int(content_length)
        except ValueError:
            content_length = None

    if content_length is None:
        # body가 None이면 길이 계산 대신 None
        if body is None:
            content_length = None
        elif isinstance(body, str):
            content_length = len(body.encode("utf-8"))
        elif isinstance(body, (bytes, bytearray, memoryview)):
            content_length = len(body)
        else:
            # body가 예상치 못한 타입이면 None
            content_length = None

    # Content-Encoding이 없으면 identity로 설정
    content_encoding = headers.get("Content-Encoding")
    if content_encoding is None:
        content_encoding = "identity"

    body_dict = {
        "content_type": content_type,
        "charset": charset,
        "content_length": content_length,
        "content_encoding": content_encoding,
        "body": body,
    }

    return {
        "http_version": fuzzed_response.get("http_version"),
        "status_code": fuzzed_response.get("status_code"),
        "timestamp": fuzzed_response.get("timestamp"),
        "headers": headers,
        "body": body_dict,
    }
