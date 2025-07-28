# pylint: disable= too-many-branches,too-many-statements
"""스마트 웹 퍼저의 시작점 모듈
동작 순서:
1. 인프라 실행 (docker-compose up)
2. DB 초기화
3. Redis DB 초기화
4. Celery 워커 실행
5. 프록시 서버 실행 (mitmproxy)
6. 셀레니움 브라우저 실행
"""

import os
import time
import urllib.parse
import threading
import subprocess
import argparse
from selenium.common.exceptions import WebDriverException
from InquirerPy import inquirer
from db_init import initialize_databases
import proxy
from scanner_trigger import ScannerTrigger
from fuzzing_scheduler.fuzzing_scheduler import start_celery_workers, set_rps
from scanners import _REGISTRY

# ASCII 아트 상수
ASCII_ART = """
╔───────────────────────────────────────────────────╗
│                                                   │
│     ███████╗██╗   ██╗███████╗███████╗██╗  ██╗     │
│     ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██║ ██╔╝     │
│     █████╗  ██║   ██║  ███╔╝   ███╔╝ █████╔╝      │
│     ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔═██╗      │
│     ██║     ╚██████╔╝███████╗███████╗██║  ██╗     │
│     ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝     │
│                                                   │
╚───────────────────────────────────────────────────╝
"""


def parse_arguments():
    """명령줄 인자를 파싱합니다."""
    parser = argparse.ArgumentParser(
        description=f"{ASCII_ART}\n\nFuzzk SmartWebFuzzer - 웹 취약점 스캐너",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-url",
        "--url",
        type=str,
        help="타겟 URL (쉼표로 구분하여 여러 개 지정 가능)",
        metavar="URL",
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=4,
        help="퍼징 요청을 보내는 워커 수 (기본값: 4)",
        metavar="NUM",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=8,
        help="스레드 수 (기본값: 8)",
        metavar="NUM",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="상세한 로그 출력")
    parser.add_argument(
        "-rps",
        "--rate-limit",
        type=float,
        default=None,
        help="초당 요청 수 제한 (RPS, 기본값: 제한 없음)",
        metavar="NUM",
    )

    return parser.parse_args()


def main():
    """스마트 웹 퍼저 메인 함수"""
    args = parse_arguments()

    print(ASCII_ART)  # 일반 실행 시 ASCII 아트만 표시

    # URL 처리
    if args.url:
        urls = [u.strip() for u in args.url.split(",") if u.strip()]
    else:
        input_urls = inquirer.text(
            message="타겟 URL을 입력하세요.\n(예시: https://naver.com,http://testphp.vulnweb.com)\n▶",
            validate=lambda text: bool(text.strip())
            or "URL을 1개 이상 입력해야 합니다.",
            qmark="",
        ).execute()
        urls = [u.strip() for u in input_urls.split(",") if u.strip()]

    if not urls:
        print("[MAIN] ERROR! URL이 입력되지 않았습니다. 종료합니다.")
        return

    # --- 스캐너 선택 UI (InquirerPy) ---
    scanner_names = list(_REGISTRY.keys())
    choices = [{"name": name, "value": name, "enabled": True} for name in scanner_names]
    print(
        "\n활성화할 스캐너를 선택하세요 (스페이스: 선택/해제, ↑/↓: 이동, 엔터: 완료)\n"
    )
    selected = inquirer.checkbox(
        message="[스캐너 목록]",
        choices=choices,
        instruction="- 스페이스: 선택/해제, ↑/↓: 이동, 엔터: 완료",
        cycle=True,
        pointer="→",
        qmark="",
    ).execute()
    if not selected:
        print("[MAIN] ERROR! 스캐너를 1개 이상 선택해야 합니다. 종료합니다.")
        return

    # 선택된 스캐너만 _REGISTRY에 남기고 나머지는 삭제
    for name in list(_REGISTRY.keys()):
        if name not in selected:
            del _REGISTRY[name]
    print(f"[MAIN] 활성화된 스캐너: {', '.join(selected)}")
    print(
        f"[MAIN] 비활성화된 스캐너: {', '.join([s for s in scanner_names if s not in selected])}"
    )

    # 워커 및 성능 설정
    print(f"[MAIN] 퍼징 요청 워커 수: {args.workers}")
    print(f"[MAIN] 스레드 수: {args.threads}")

    if args.verbose:
        print("[MAIN] 상세 로그 모드 활성화")

    domains = [urllib.parse.urlparse(url).netloc for url in urls]
    os.environ["TARGET_DOMAINS"] = ",".join(domains)

    # 데이터베이스 초기화
    db = initialize_databases()

    # Celery 워커 시작
    celery_workers = start_celery_workers(workers=args.workers)
    # 워커 시작 확인
    while True:
        if all(worker.poll() is None for worker in celery_workers):
            break
        print("[MAIN] Celery 워커 시작 중...")

    print("[MAIN] 스캐너 트리거 시작 중...")
    threading.Thread(
        target=ScannerTrigger(max_workers=args.threads).run, daemon=True
    ).start()

    time.sleep(1)
    print("[MAIN] mitmproxy 시작 중...")
    mitmproxy_process = proxy.run_mitmproxy()
    time.sleep(5)
    # rps 설정
    if args.rate_limit is not None:
        set_rps(args.rate_limit)

    driver = None
    try:
        print("[MAIN] Selenium 브라우저 시작")
        driver = proxy.start_browser_and_browse()

        for url in urls:
            print(f"[MAIN] 접속 중: {url}")
            try:
                driver.get(url)
                print(f"[MAIN] SUCCESS! {url} 접속 성공!")
            except WebDriverException:
                print(f"[MAIN] ERROR! {url} 접속 실패!")
            time.sleep(3)

        input("[MAIN] 아무 키나 누르면 종료됩니다...")

    except (OSError, KeyboardInterrupt):
        print("[MAIN] ERROR! 메인 프로세스 중 오류 발생")

    finally:
        # DB 백업
        print("[MAIN] DB 백업 시작...")
        db.backup_database()

        print("[MAIN] 종료 중...")

        # Celery 워커들 종료
        for worker in celery_workers:
            worker.terminate()
            worker.wait(timeout=10)

        if driver:
            try:
                driver.quit()
            except WebDriverException:
                print("[MAIN] ERROR! 브라우저 종료 중 오류")

        try:
            mitmproxy_process.terminate()
            mitmproxy_process.wait()
        except (subprocess.SubprocessError, OSError):
            print("[MAIN] ERROR! mitmproxy 종료 중 오류")

        print("[MAIN] 종료 완료")


if __name__ == "__main__":
    main()
