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
    """request 요청"""

    response = requests.request(
        method=request_data["method"],
        url=request_data["url"],
        headers=request_data.get("headers", {}),
        data=request_data.get("body", ""),
        timeout=10,
    )

    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "text": response.text,
        "elapsed_time": response.elapsed.total_seconds(),
        "content_type": response.headers.get("content-type", ""),
        "content_length": response.headers.get("content-length", ""),
        "cookies": dict(response.cookies),
    }
