"""스마트 웹 퍼저의 시작점 모듈

동작 순서:
1. 인프라 실행 (docker-compose up)
2. DB 초기화
3. 프록시 서버 실행 (mitmproxy)
4. 셀레니움 브라우저 실행
5. 대시보드 모듈 실행
"""

import os
import time
import urllib.parse
from selenium.common.exceptions import WebDriverException
from db_init import DBInit
import proxy


def main():
    """스마트 웹 퍼저 메인 함수"""
    input_urls = input(
        "타겟 URL을 쉼표로 구분해서 입력하세요 (예: https://naver.com,http://testphp.vulnweb.com):\n> "
    )
    urls = [u.strip() for u in input_urls.split(",") if u.strip()]
    if not urls:
        print("URL이 입력되지 않았습니다. 종료합니다.")
        return

    domains = [urllib.parse.urlparse(url).netloc for url in urls]
    os.environ["TARGET_DOMAINS"] = ",".join(domains)

    # TODO: 인프라 docker-compose 실행

    # DB 초기화
    db = DBInit()
    db.create_database_if_not_exists()
    db.create_tables()

    # TODO: 대시보드 모듈 실행
    # TODO: 스캐너 트리거 모듈 실행

    print("[INFO] mitmproxy 시작 중...")
    mitmproxy_process = proxy.run_mitmproxy()
    time.sleep(5)

    driver = None
    try:
        print("[INFO] Selenium 브라우저 시작")
        driver = proxy.start_browser_and_browse()

        for url in urls:
            print(f"[INFO] 접속 중: {url}")
            try:
                driver.get(url)
                print(f"[SUCCESS] {url} 접속 성공!")
            except WebDriverException as exc:
                print(f"[ERROR] {url} 접속 실패: {exc}")
            time.sleep(3)

        input("[INFO] 아무 키나 누르면 종료됩니다...")

    except (OSError, KeyboardInterrupt) as exc:
        print(f"[ERROR] 메인 프로세스 중 오류 발생: {exc}")

    finally:
        # TODO: DB 백업
        print("[INFO] DB 백업 시작...")
        db.backup_database()
        
        print("[INFO] 종료 중...")
        if driver:
            try:
                driver.quit()
            except WebDriverException as exc:
                print(f"[WARN] 브라우저 종료 중 오류: {exc}")
        mitmproxy_process.terminate()
        mitmproxy_process.wait()
        print("[INFO] 종료 완료")


if __name__ == "__main__":
    main()
