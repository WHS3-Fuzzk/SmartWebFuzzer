"""
이 모듈은 퍼저에서 보내는 변조된 요청을 중앙화하여 관리하는 역할을 수행합니다.
필요조건
- redis 컨테이너 실행 중
- 아래 명령 실행
celery -A fuzzing_scheduler worker --concurrency=2 --loglevel=INFO

"""

from celery import Celery
import requests


celery_app = Celery(
    "fuzzer",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1",
    task_acks_late=True,
)


@celery_app.task(name="tasks.send_fuzz_request")
def send_fuzz_request(request_data):
    """HTTP 요청을 보내고 응답을 반환합니다.

    Args:
        request_data (dict): 요청 데이터
            - method (str): HTTP 메소드 (GET, POST, PUT 등)
            - url (str): 요청할 URL
            - headers (dict, optional): HTTP 헤더
            - params (dict, optional): URL 쿼리 파라미터
            - data (str, optional): 요청 본문
            - json (dict, optional): JSON 형식의 요청 본문
            - allow_redirects (bool, optional): 리다이렉트 허용 여부 (기본값: True)
            - timeout (int, optional): 요청 타임아웃 (기본값: 10초)

    Returns:
        dict: 응답 데이터
            - status_code (int): HTTP 상태 코드
            - headers (dict): 응답 헤더
            - text (str): 응답 본문
            - elapsed_time (float): 요청 처리 시간
            - content_type (str): Content-Type 헤더
            - content_length (str): Content-Length 헤더
            - cookies (dict): 응답 쿠키
            - request_info (dict): 실제로 보낸 요청 정보
            - error (str, optional): 요청 실패 시 에러 정보
            - redirect_history (list, optional): 리다이렉트 히스토리
    """

    response = requests.request(
        method=request_data["method"],
        url=request_data["url"],
        headers=request_data.get("headers", {}),
        params=request_data.get("params", {}),
        data=request_data.get("data", ""),
        json=request_data.get("json"),
        allow_redirects=request_data.get("allow_redirects", True),
        timeout=request_data.get("timeout", 10),
    )

    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "text": response.text,
        "elapsed_time": response.elapsed.total_seconds(),
        "content_type": response.headers.get("content-type", ""),
        "content_length": response.headers.get("content-length", ""),
        "cookies": dict(response.cookies),
        "request_info": {
            "method": response.request.method,
            "url": response.request.url,
            "headers": dict(response.request.headers),
            "body": (
                response.request.body.decode("utf-8")
                if isinstance(response.request.body, bytes)
                else str(response.request.body)
            ),
        },
        "redirect_history": (
            [
                {
                    "status_code": r.status_code,
                    "url": r.url,
                    "headers": dict(r.headers),
                }
                for r in response.history
            ]
            if response.history
            else None
        ),
    }
