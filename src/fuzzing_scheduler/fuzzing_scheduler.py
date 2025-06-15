"""
이 모듈은 celery를 활용해 퍼저에서 생성한 변조된 HTTP 요청을 비동기·분산 방식으로 전송하고,
응답 분석까지 워크플로우로 관리하는 중앙 퍼징 스케줄러 역할을 수행합니다.
대규모 분산 퍼징 환경에 적합하며, 각 요청과 분석 작업을 celery task로 처리합니다.
fuzzing_scheduler는 퍼징 요청의 분산/스케줄링만 담당하고,
실제로 어떤 응답이 취약한지 분석하는 로직은
각 스캐너(예: ExampleScanner)에서 구현해야 합니다.

필요조건
- redis 컨테이너 실행 중
- 아래 명령 실행
# cd src/
celery -A fuzzing_scheduler.fuzzing_scheduler worker \
    -Q fuzz_request \
    --concurrency=10 \
    --loglevel=INFO

celery -A fuzzing_scheduler.fuzzing_scheduler worker \
    -Q analyze_response \
    --concurrency=5 \
    --loglevel=INFO

-A: 어떤 모듈에서 celery app을 찾을 것인가"를 의미합니다
-Q: 큐 이름을 지정합니다. 여기서는 "fuzz_request", "analyze_response"큐를 사용합니다.
worker: 워커 프로세스를 실행합니다.
--concurrency=2: 동시에 2개의 작업을 처리할 수 있는 워커 프로세스(스레드/프로세스) 수를 지정합니다.
--loglevel=INFO: 로그 레벨을 INFO로 설정하여 실행 중인 작업의 상태를 출력합니다.
"""

from typing import Any, Dict
from celery import Celery
import requests


celery_app = Celery(
    "fuzzer",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1",
    task_acks_late=True,
    imports=[
        "fuzzing_scheduler.fuzzing_scheduler",
        "scanners.example",  # 예시 스캐너 모듈
    ],
)
# celery_app.autodiscover_tasks(["scanners"])


@celery_app.task(name="tasks.send_fuzz_request", queue="fuzz_request")
def send_fuzz_request(request_data) -> Dict[str, Any]:
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
