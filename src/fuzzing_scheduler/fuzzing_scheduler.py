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

from datetime import datetime
from typing import Any, Dict
from celery import Celery
import requests

from typedefs import RequestData


celery_app = Celery(
    "fuzzer",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1",
    task_acks_late=True,
    # TODO: imports에 스캐너 모듈을 추가하여 자동으로 로드되도록 설정 필요
    imports=[
        "fuzzing_scheduler.fuzzing_scheduler",
        "scanners.example",  # 예시 스캐너 모듈
    ],
)
# celery_app.autodiscover_tasks(["scanners"])


@celery_app.task(name="tasks.send_fuzz_request", queue="fuzz_request")
def send_fuzz_request(request_data: RequestData, *args, **kwargs) -> Dict[str, Any]:
    """requests.request의 모든 인자를 받아 HTTP 요청을 전송하는 범용 래퍼 함수"""
    # RequestData의 형태로 인자가 전달되면 requests.request에 맞게 변환
    if request_data:
        kwargs.update(requestdata_to_requests_kwargs(request_data))
    response = requests.request(*args, **kwargs, timeout=30)

    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "text": response.text,
        "elapsed_time": response.elapsed.total_seconds(),
        "http_version": response.raw.version,
        "url": response.url,
        "body": response.content.decode("utf-8"),
        "timestamp": datetime.now(),
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
        "request_data": request_data,
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


def requestdata_to_requests_kwargs(request_data: RequestData) -> dict:
    """RequestData 객체를 requests.request에 필요한 인자 형태로 변환"""
    method = request_data["meta"]["method"]
    url = f"http://{request_data['meta']['domain']}{request_data['meta']['path']}"
    headers = {h["key"]: h["value"] for h in (request_data.get("headers") or [])}
    params = {q["key"]: q["value"] for q in (request_data.get("query_params") or [])}
    data = None
    if request_data["body"] and request_data["body"].get("body"):
        data = request_data["body"]["body"]
    return {
        "method": method,
        "url": url,
        "headers": headers,
        "params": params,
        "data": data,
    }
