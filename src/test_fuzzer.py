"""
fuzzing_scheduler 모듈의 send_fuzz_request 함수를 테스트
redis아래 명령 실행 후 테스트
cd src/
celery -A fuzzing_scheduler worker --concurrency=2 --loglevel=INFO

"""

import time
from fuzzing_scheduler import send_fuzz_request


def test_celery_fuzzer():
    """요청 보내고 응답 확인"""
    # 테스트용 요청 데이터
    test_request = {
        "method": "GET",
        "url": "https://httpbin.org/get",  # 테스트용 공개 API
        "headers": {"User-Agent": "Fuzzer-Test"},
        "module": "test_module",
    }

    print("Celery 태스크 전송 시작...")
    # 비동기 태스크 실행
    task = send_fuzz_request.delay(test_request)
    print(f"태스크 ID: {task.id}")

    # 태스크 완료 대기
    while not task.ready():
        print("태스크 실행 중...")
        time.sleep(1)

    # 결과 확인
    result = task.get()
    print("\n테스트 결과:")
    print(f"상태 코드: {result['status_code']}")
    print(f"응답 시간: {result['elapsed_time']:.3f}초")
    print(f"Content-Type: {result['content_type']}")
    print(f"Content-Length: {result['content_length']}")
    print("\n응답 헤더:")
    for key, value in result["headers"].items():
        print(f"  {key}: {value}")
    print("\n응답 본문:")
    print(f"{result['text'][:200]}...")  # 응답이 너무 길 수 있으므로 일부만 출력
    print("\n쿠키:")
    for key, value in result["cookies"].items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    test_celery_fuzzer()
