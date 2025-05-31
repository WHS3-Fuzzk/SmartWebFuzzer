"""SmartWebFuzzer 테스트용 삽입 스크립트입니다."""

from datetime import datetime  # ← 표준 라이브러리 먼저
from db_writer import insert_filtered_request, insert_filtered_response

# 테스트용 요청 데이터
test_request = {
    "is_http": 1,  # 정수형으로 삽입 (True → 1)
    "http_version": "HTTP/1.1",
    "domain": "example.com",
    "path": "/login",
    "method": "POST",
    "timestamp": datetime.now(),
    "headers": {"User-Agent": "TestAgent/1.0", "Content-Type": "application/json"},
    "query": [{"key": "ref", "value": "test", "source": "url"}],
    "body": {
        "content_type": "application/json",
        "charset": "utf-8",
        "content_length": 42,
        "content_encoding": "identity",
        "body": '{"username": "admin", "password": "pass"}',
    },
}

# 요청 삽입 → ID 얻기
request_id = insert_filtered_request(test_request)
print(f"[+] 요청 ID: {request_id}")

# 테스트용 응답 데이터
test_response = {
    "http_version": "HTTP/1.1",
    "status_code": 200,
    "timestamp": datetime.now(),
    "headers": {"Content-Type": "application/json"},
    "body": {
        "content_type": "application/json",
        "charset": "utf-8",
        "content_length": 28,
        "content_encoding": "identity",
        "body": '{"status": "ok", "token": "..."}',
    },
}

# 응답 삽입
response_id = insert_filtered_response(test_response, request_id)
print(f"[+] 응답 ID: {response_id}")
