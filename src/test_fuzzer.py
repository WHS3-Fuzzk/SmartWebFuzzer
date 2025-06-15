"""
fuzzing_scheduler 모듈의 send_fuzz_request 함수를 테스트
redis아래 명령 실행 후 테스트
cd src/
celery -A fuzzing_scheduler worker --concurrency=2 --loglevel=INFO

"""

import time

from requests.exceptions import (
    ConnectionError as RequestsConnectionError,
    RequestException,
    Timeout,
)

from fuzzing_scheduler.fuzzing_scheduler import send_fuzz_request


def test_request(request_data, description):
    """단일 요청 테스트 실행"""
    print(f"\n=== {description} 테스트 시작 ===")
    print(f"요청 데이터: {request_data}")

    try:
        # 비동기 태스크 실행
        task = send_fuzz_request.delay(request_data)
        print(f"태스크 ID: {task.id}")

        # 태스크 완료 대기 (최대 30초)
        max_wait_time = 30
        start_time = time.time()
        while not task.ready():
            if time.time() - start_time > max_wait_time:
                raise Timeout("태스크 실행 시간 초과")
            print("태스크 실행 중...")
            time.sleep(1)

        # 결과 확인
        result = task.get()
        print("\n테스트 결과:")
        print(f"상태 코드: {result['status_code']}")
        print(f"응답 시간: {result['elapsed_time']:.3f}초")
        print(f"Content-Type: {result['content_type']}")
        print(f"Content-Length: {result['content_length']}")

        print("\n요청 정보:")
        for key, value in result["request_info"].items():
            print(f"  {key}: {value}")

        if result.get("redirect_history"):
            print("\n리다이렉트 히스토리:")
            for idx, redirect in enumerate(result["redirect_history"], 1):
                print(
                    f"  {idx}. {redirect['url']} (상태 코드: {redirect['status_code']})"
                )

        print("\n응답 헤더:")
        for key, value in result["headers"].items():
            print(f"  {key}: {value}")

        print("\n응답 본문:")
        print(f"{result['text'][:200]}...")  # 응답이 너무 길 수 있으므로 일부만 출력

        if result["cookies"]:
            print("\n쿠키:")
            for key, value in result["cookies"].items():
                print(f"  {key}: {value}")

        print(f"\n=== {description} 테스트 완료 ===\n")
        return result

    except Timeout as e:
        print(f"\n타임아웃 발생: {str(e)}")
        raise
    except RequestsConnectionError as e:
        print(f"\n연결 오류 발생: {str(e)}")
        raise
    except RequestException as e:
        print(f"\n요청 오류 발생: {str(e)}")
        raise
    except Exception as e:
        print(f"\n예상치 못한 오류 발생: {str(e)}")
        raise


def test_celery_fuzzer():
    """다양한 HTTP 요청 시나리오 테스트"""
    test_cases = [
        {
            "description": "기본 GET 요청",
            "request": {
                "method": "GET",
                "url": "https://httpbin.org/get",
                "headers": {"User-Agent": "Fuzzer-Test"},
                "params": {"test": "value", "foo": "bar"},
                "timeout": 5,  # 타임아웃 시간 단축
            },
        },
        {
            "description": "POST 요청 (JSON 데이터)",
            "request": {
                "method": "POST",
                "url": "https://httpbin.org/post",
                "headers": {
                    "User-Agent": "Fuzzer-Test",
                    "Content-Type": "application/json",
                },
                "json": {"key": "value", "test": 123},
                "timeout": 5,
            },
        },
        {
            "description": "PUT 요청 (폼 데이터)",
            "request": {
                "method": "PUT",
                "url": "https://httpbin.org/put",
                "headers": {"User-Agent": "Fuzzer-Test"},
                "data": "key1=value1&key2=value2",
                "timeout": 5,
            },
        },
        {
            "description": "DELETE 요청",
            "request": {
                "method": "DELETE",
                "url": "https://httpbin.org/delete",
                "headers": {"User-Agent": "Fuzzer-Test"},
                "timeout": 5,
            },
        },
        {
            "description": "리다이렉트 테스트",
            "request": {
                "method": "GET",
                "url": "https://httpbin.org/redirect/2",
                "headers": {"User-Agent": "Fuzzer-Test"},
                "allow_redirects": True,
                "timeout": 5,
            },
        },
        {
            "description": "타임아웃 테스트",
            "request": {
                "method": "GET",
                "url": "https://httpbin.org/delay/1",
                "headers": {"User-Agent": "Fuzzer-Test"},
                "timeout": 2,
            },
        },
    ]

    results = []
    for test_case in test_cases:
        try:
            result = test_request(test_case["request"], test_case["description"])
            results.append(
                {
                    "description": test_case["description"],
                    "success": True,
                    "status_code": result["status_code"],
                }
            )
        except Timeout as e:
            results.append(
                {
                    "description": test_case["description"],
                    "success": False,
                    "error": f"타임아웃: {str(e)}",
                }
            )
        except RequestsConnectionError as e:
            results.append(
                {
                    "description": test_case["description"],
                    "success": False,
                    "error": f"연결 오류: {str(e)}",
                }
            )
        except RequestException as e:
            results.append(
                {
                    "description": test_case["description"],
                    "success": False,
                    "error": f"요청 오류: {str(e)}",
                }
            )

    # 테스트 결과 요약
    print("\n=== 테스트 결과 요약 ===")
    for result in results:
        status = (
            "성공"
            if result["success"]
            else f"실패: {result.get('error', '알 수 없는 오류')}"
        )
        print(f"{result['description']}: {status}")


if __name__ == "__main__":
    test_celery_fuzzer()
