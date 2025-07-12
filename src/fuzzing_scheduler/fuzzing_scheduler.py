"""
이 모듈은 celery를 활용해 퍼저에서 생성한 변조된 HTTP 요청을 비동기·분산 방식으로 전송하고,
응답 분석까지 워크플로우로 관리하는 중앙 퍼징 스케줄러 역할을 수행합니다.
대규모 분산 퍼징 환경에 적합하며, 각 요청과 분석 작업을 celery task로 처리합니다.

fuzzing_scheduler는 퍼징 요청의 분산/스케줄링과 워커 관리를 담당하고,
실제로 어떤 응답이 취약한지 분석하는 로직은
각 스캐너(예: ExampleScanner)에서 구현해야 합니다.

필요조건:
- redis 컨테이너 실행 중
- start_celery_workers() 함수 호출로 워커들이 자동으로 시작됨

주요 기능:
- celery app 설정 및 관리
- HTTP 요청 전송 task (fuzz_request 큐)
- 응답 분석 task (analyze_response 큐)
- 워커 프로세스 자동 시작/종료 관리
"""

import os
from pathlib import Path
import time
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

import chardet
import requests
from celery import Celery

from typedefs import RequestData

# 멀티프로세싱 환경에서 celery 오류 방지
os.environ.setdefault("FORKED_BY_MULTIPROCESSING", "1")

celery_app = Celery(
    "fuzzer",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1",
    task_acks_late=True,
    # TODO: imports에 스캐너 모듈을 추가하여 자동으로 로드되도록 설정 필요
    imports=[
        "fuzzing_scheduler.fuzzing_scheduler",
        "scanners.reflected_xss",  # 예시 스캐너 모듈
        "scanners.example",  # 예시 스캐너 모듈
        "scanners.ssrf",  # SQL Injection 스캐너 모듈
        "scanners.stored_xss",  # Stored XSS 스캐너 모듈
        "scanners.dom_xss",  # Dom XSS 스캐너 모듈
        "scanners.file_download",  # File Download 스캐너
        "scanners.command_injection",  # Command Injection 스캐너
        "scanners.sqli",  # Sqli 스캐너 모듈
    ],
)
# celery_app.autodiscover_tasks(["scanners"])


def create_worker_command(queue_name: str, concurrency: int) -> List[str]:
    """
    Celery 워커 명령어 생성

    -A: 어떤 모듈에서 celery app을 찾을 것인가"를 의미합니다
    -Q: 큐 이름을 지정합니다. 여기서는 "fuzz_request", "analyze_response"큐를 사용합니다.
    worker: 워커 프로세스를 실행합니다.
    --concurrency=2: 동시에 2개의 작업을 처리할 수 있는 워커 프로세스(스레드/프로세스) 수를 지정합니다.
    --loglevel=INFO: 로그 레벨을 INFO로 설정하여 실행 중인 작업의 상태를 출력합니다.
    """
    log_file = (
        Path(__file__).parent.parent.parent
        / "logs"
        / f"celery-{queue_name}_{datetime.now().strftime('%m%d_%H%M%S')}.log"
    )
    log_file.parent.mkdir(exist_ok=True)  # 프로젝트 루트 디렉토리 경로

    node_name = f"worker-{queue_name}@%h"  # %h는 호스트명

    return [
        "celery",
        "-A",
        "fuzzing_scheduler.fuzzing_scheduler",
        "worker",
        "-Q",
        queue_name,
        "-n",  # 노드 이름 옵션 추가
        node_name,
        f"--concurrency={concurrency}",
        "--loglevel=INFO",
        f"--logfile={log_file}",
    ]


def start_celery_worker(
    queue_name: str, concurrency: int
) -> Optional[subprocess.Popen]:
    """단일 Celery 워커 시작"""
    cmd = create_worker_command(queue_name, concurrency)
    print(f"[INFO] {queue_name} 워커 시작 중...")

    try:
        worker = subprocess.Popen(  # pylint: disable=consider-using-with
            cmd,
            cwd=os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            ),  # src/ 디렉토리
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ.copy(),
        )
        return worker
    except (subprocess.SubprocessError, OSError, FileNotFoundError) as e:
        print(f"[ERROR] {queue_name} 워커 시작 실패: {e}")
        return None


def start_celery_workers() -> List[subprocess.Popen]:
    """Celery 워커들을 백그라운드에서 시작"""
    print("[INFO] Celery 워커 시작 중...")

    workers = []
    worker_configs = [("fuzz_request", 6), ("analyze_response", 4)]

    for queue_name, concurrency in worker_configs:
        worker = start_celery_worker(queue_name, concurrency)
        if worker:
            workers.append(worker)

    # 워커들이 제대로 시작될 때까지 잠시 대기
    time.sleep(3)

    # 워커 상태 확인
    for worker in workers:
        if worker.poll() is not None:
            print("[ERROR] celery 워커가 실행 실패")

    return workers


@celery_app.task(name="tasks.send_fuzz_request", queue="fuzz_request")
def send_fuzz_request(request_data: RequestData, *args, **kwargs) -> Dict[str, Any]:
    """requests.request의 모든 인자를 받아 HTTP 요청을 전송하는 범용 래퍼 함수"""

    # RequestData의 형태로 인자가 전달되면 requests.request에 맞게 변환
    if request_data:
        kwargs.update(requestdata_to_requests_kwargs(request_data))

    try:
        response = requests.request(*args, **kwargs, timeout=5)

        # 인코딩 자동 감지
        detected_encoding = chardet.detect(response.content)["encoding"]
        body = response.content.decode(detected_encoding or "utf-8", errors="replace")

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "text": response.text,
            "elapsed_time": response.elapsed.total_seconds(),
            "http_version": response.raw.version,
            "url": response.url,
            "body": body,
            "timestamp": datetime.now(),
            "cookies": dict(response.cookies),
            "request_info": {
                "method": response.request.method,
                "url": response.request.url,
                "headers": dict(response.request.headers),
                "body": (
                    response.request.body.decode("utf-8", errors="replace")
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

    except requests.exceptions.Timeout as e:
        # 타임아웃 발생 시 타임아웃 정보를 포함한 응답 반환
        return {
            "elapsed_time": 5.0,  # 타임아웃 시간
            "error_message": f"timeout: {str(e)}",
            "error_type": "timeout",
            "request_data": request_data,
        }

    except requests.exceptions.ConnectionError as e:
        # 연결 오류 발생 시 - SSRF 탐지에 중요한 정보
        error_str = str(e).lower()

        # 에러 종류 세분화
        if "connection refused" in error_str:
            error_subtype = "connection_refused"
        elif (
            "name or service not known" in error_str
            or "nodename nor servname provided" in error_str
        ):
            error_subtype = "dns_resolution_failed"
        elif "network is unreachable" in error_str:
            error_subtype = "network_unreachable"
        elif "connection timed out" in error_str:
            error_subtype = "connection_timeout"
        else:
            error_subtype = "connection_error"

        return {
            "error_message": f"{error_subtype}: {str(e)}",
            "error_type": "connection_error",
            "error_subtype": error_subtype,
            "request_data": request_data,
        }

    except requests.exceptions.RequestException as e:
        # 기타 요청 관련 예외 (SSL 오류, 잘못된 URL 등)
        return {
            "error_message": f"request_error: {str(e)}",
            "error_type": "request_error",
            "request_data": request_data,
        }


def requestdata_to_requests_kwargs(request_data: RequestData) -> dict:
    """RequestData 객체를 requests.request에 필요한 인자 형태로 변환"""
    is_http = request_data["meta"]["is_http"]
    scheme = "http://"
    if is_http:
        scheme = "http://" if is_http == 1 else "https://"
    method = request_data["meta"]["method"]
    url = f"{scheme}{request_data['meta']['domain']}{request_data['meta']['path']}"
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
