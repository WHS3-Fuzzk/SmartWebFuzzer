"""스마트 웹 퍼저의 시작점 모듈

동작 순서:
1. 인프라 실행 (docker-compose up)
2. DB 초기화
3. Celery 워커 실행
4. 프록시 서버 실행 (mitmproxy)
5. 셀레니움 브라우저 실행
6. 대시보드 모듈 실행
"""

import os
import time
import urllib.parse
import threading
import subprocess
import argparse
from selenium.common.exceptions import WebDriverException
from db_init import DBInit
import proxy
from scanner_trigger import ScannerTrigger
from fuzzing_scheduler.fuzzing_scheduler import start_celery_workers


def parse_arguments():
    """명령줄 인자를 파싱합니다."""
    parser = argparse.ArgumentParser(
        description="Fuzzk SmartWebFuzzer - 웹 취약점 스캐너",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,  # 기본 help를 비활성화
    )

    parser.add_argument(
        "-url",
        "--url",
        type=str,
        help="타겟 URL (쉼표로 구분하여 여러 개 지정 가능)",
        metavar="URL",
    )

    parser.add_argument(
        "--enable",
        type=str,
        help="활성화할 스캐너 목록 (쉼표로 구분)",
        metavar="SCANNERS",
    )

    parser.add_argument(
        "--disable",
        type=str,
        help="비활성화할 스캐너 목록 (쉼표로 구분)",
        metavar="SCANNERS",
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

    parser.add_argument("-h", "--help", action="store_true", help="이 도움말 표시")

    return parser.parse_args()


def main():
    """스마트 웹 퍼저 메인 함수"""
    args = parse_arguments()

    # help 옵션 처리
    if args.help:
        ascii_art(show_manual=True)
        return

    ascii_art()  # 일반 실행 시 ASCII 아트만 표시

    # URL 처리
    if args.url:
        urls = [u.strip() for u in args.url.split(",") if u.strip()]
    else:
        input_urls = input(
            "타겟 URL을 쉼표로 구분해서 입력하세요 (예: https://naver.com,http://testphp.vulnweb.com):\n> "
        )
        urls = [u.strip() for u in input_urls.split(",") if u.strip()]

    if not urls:
        print("URL이 입력되지 않았습니다. 종료합니다.")
        return

    # 활성화/비활성화할 스캐너 처리 (실제 구현은 하지 않음)
    if args.enable:
        enabled_scanners = [s.strip() for s in args.enable.split(",")]
        print(f"[INFO] 활성화된 스캐너: {', '.join(enabled_scanners)}")

    if args.disable:
        disabled_scanners = [s.strip() for s in args.disable.split(",")]
        print(f"[INFO] 비활성화된 스캐너: {', '.join(disabled_scanners)}")

    # 워커 및 성능 설정
    print(f"[INFO] 퍼징 요청 워커 수: {args.workers}")
    print(f"[INFO] 스레드 수: {args.threads}")

    if args.verbose:
        print("[INFO] 상세 로그 모드 활성화")

    domains = [urllib.parse.urlparse(url).netloc for url in urls]
    os.environ["TARGET_DOMAINS"] = ",".join(domains)

    # TODO: 인프라 docker-compose 실행

    # DB 초기화
    db = DBInit()
    db.create_database_if_not_exists()
    db.create_tables()

    # Celery 워커 시작
    # TODO: 퍼징 워커 설정값들(workers, threads)을 전달하도록 구현 필요
    celery_workers = start_celery_workers()

    # TODO: 대시보드 모듈 실행

    print("[INFO] 스캐너 트리거 시작 중...")
    threading.Thread(target=ScannerTrigger().run, daemon=True).start()

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
        # DB 백업
        print("[INFO] DB 백업 시작...")
        db.backup_database()

        print("[INFO] 종료 중...")

        # Celery 워커들 종료
        for worker in celery_workers:
            worker.terminate()
            worker.wait(timeout=10)

        if driver:
            try:
                driver.quit()
            except WebDriverException as exc:
                print(f"[WARN] 브라우저 종료 중 오류: {exc}")

        try:
            mitmproxy_process.terminate()
            mitmproxy_process.wait()
        except (subprocess.SubprocessError, OSError) as exc:
            print(f"[WARN] mitmproxy 종료 중 오류: {exc}")

        print("[INFO] 종료 완료")


def ascii_art(show_manual=False):
    # pylint: disable=line-too-long
    """아스키 아트 출력 (선택적으로 매뉴얼 포함)"""
    art_lines = [
        "                                                 ▓▓█▓                                                ",
        "                                               ▓▓████▓█                                              ",
        "                                             ▓███▒▒▒▒███▓                                            ",
        "                                        █▓▓███▓▒▓▓▓▓▓▓▒▓███▓▓█                                       ",
        "                          ▓███▓▓▓▓▓▓██████▓▒▒▓█▓▓████▓▓█▓▒▒▓██████▓▓▓▓▓▓████                         ",
        "                          ██▒░░░░░░░░░░▒▓███▓▓████▓▓████▓▓███▓▒░░░░░░░░░░▒█▓                         ",
        "                          ██▒▓▓▓▓▓▓▓▓▓▓▓▓█████▓▓▓▒▒▒▒▒▓▓█████▓▓▓▓▓▓▓▓▓▓▓█▒█▓                         ",
        "                          ██▒▓▓███████████▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓██████████▓█▒█▓                         ",
        "                          ██▒▓▓██▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒  ░ ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓██▓█▒█▓                         ",
        "                          ██▒▓▓██▓▒▒░░░░░░▒▒░▒▒▓ ▓██▓░▓▒▒▒▒▒░░░░░▒▒▒▓██▓█▒█▓                         ",
        "                          ██▒▓▓██▓▒▒░▒▒▒▒▒▒▒▒▓█        █▒▒░░░░▒░▒░░▒▓██▓█▒█▓                         ",
        "                          ▓█▒▓▓██▓▒▒▒░░▒▒▒▒▒▓▓█  ░██░  █▒▒▒▒▒▒░░░▒▒▒▓██▓█▒█▓                         ",
        "             ███████████████▒▓▓██▓▓▒▒▒▓▒▒▒░▒▓▓█   ▒▓   █▒▒▒▒▒▒▒▒▒▒░▒▓██▓█▒███▓                       ",
        "             ██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▒▒▒▒▒▒▒▒▒▓▓█   ▒▒   █▓▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓█▓                       ",
        "             ██▓▓█▒          ░█▓█▓▓▓▒▒▒▒▒▒▒▒▓▓██████████▓▒▒▓▒▒▒▒▒▒▓▓█▓   ▓▓██████████████            ",
        "             ██▓▓█▒          ░█▓█▓▓▓▓▓▓▓▓▒▓▓▓▓█████████▓▓▓▓▓▓▓▓▓▓▓▓▓█▒   ▓▓▓▓▓▓▓▓▓▓▓████             ",
        "             ██▓▓█▒   ▓█████████████▓▓████████▓▓▓▓▓▓▓▓▓███▓▓▓▓▓▓▓▓▓██▒   ▓█████▓███▓███              ",
        "             ██▓▓█▒   ▓████████▓   ████▒   ██▓         ▓█▓         ▒█▓   ▓██   ▒██▓███               ",
        "             ██▓▓█▒   ▓▓▓▓▓▓███▓   ████▒   ███████▓   ▓███████▓   ▒██▓   ▓▒   ▒█▓▓███                ",
        "             ██▓▓█▒         ▒██▓   ████▒   ███▓██▒   ▓█▓▓▓▓██▓   ▓███▓       ▓█▓████                 ",
        "             ██▓▓█▒   ▒▓▓▓▓▓███▓   ████▒   █▓▓██░   ██▓███▓█▒   ▓█▓▓█▒       ██▓███                  ",
        "             ██▓▓█▒   ▓████████▓   ████▒   ████░  ░██▓▓█▓██░   ██▓▓▓█▒   ░░   ▓█▓███                 ",
        "             ▓█▓▓█▒   ▓████████▓   ▓███    ███   ▒████████   ░███████▒   ▓█▒   ▓█▓███                ",
        "             ██▓▓█▒   ▓███▓█▓▓██▒          ██           █░          █▒   ▓██▓   ▓█▓███               ",
        "             ██▓▓█████████▓█▓▓▓███▓▓▒▓███▓████▓▓▓▓▓▓▓▓▓███▓▓▓▓▓▓▓▓▓████████████████▓███              ",
        "            █▓█▓▓█████▓▓██▓█▓█████████████████████████████████████████████▓▓██████▓▓▓███             ",
        "            ██████████████▒█▓█▓██████▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▓█▓▓█▓▓▓█▓▓██████▓█▓███████████████            ",
        "                          ▓█▓▒█▓████▓▓▓▒▒▒▓▓▒▓▒▒▓▒▓▒▒▒▒▓▓▓▒▒▒▓▓▒▓▓████▓█▒▓█▓                         ",
        "                           ▓██▒▒█▓████▓▓▒▒▒▓▒▒▒▒▒▒▓▒▒▒▒▓▒▓▒▒▒▓▒▓▓███▓█▓▒██▓                          ",
        "                            ▓▓██▒▓█▓████▓▓▒▓▒▒▒▒▒▓▓▒▒▒▒▓▒▓▓▓▓▓████▓█▓▒██▓▒                           ",
        "                              ▓███▒▓█▓████▓▓▓▓▓▓▓▒▓▒▒▓▒▓▓▓▓▓████▓█▓▒██▓▓                             ",
        "                                ████▒▓█▓████▓▓▓▒▒▒▓▓▒▓▒▒▓▓████▓█▓▒███▓                               ",
        "                                  ▓███▓▒██▓████▓▓▒▓▓▓▓▓████▓██▒▓████                                 ",
        "                                     ███▓░▓█▓█████▓▓█████▓█▓░▓██▓                                    ",
        "                                       ▓███▒▒██▓██████▓██▒▒███▓                                      ",
        "                                          ████▒▓██████▓▒█████                                        ",
        "                                            ▓███▓▒▓▓▒▓███▓                                           ",
        "                                              ████████                                              ",
        "                                                 ██                                                 ",
    ]

    if not show_manual:
        # ASCII 아트만 출력
        for art_line in art_lines:
            print(art_line)
        print()  # 마지막에 빈 줄 추가
        return

    # ASCII 아트와 매뉴얼을 함께 출력
    manual_lines = [
        "",
        "Fuzzk SmartWebFuzzer - 웹 취약점 스캐너",
        "",
        "사용법:",
        "  python main.py [옵션]",
        "",
        "타겟 설정:",
        "  -url URL          타겟 URL (쉼표로 구분하여 여러 개 지정)",
        "",
        "스캐너 제어:",
        "  --enable MODULES  활성화할 모듈 (쉼표로 구분)",
        "  --disable MODULES 비활성화할 모듈 (쉼표로 구분)",
        "",
        "성능 옵션:",
        "  -w, --workers NUM 퍼징 요청 워커 수 (기본값: 4)",
        "  -t, --threads NUM 스레드 수 (기본값: 8)",
        "",
        "기타 옵션:",
        "  -v, --verbose     상세한 로그 출력",
        "  -h, --help        이 도움말 표시",
        "",
        "취약점 스캔 모듈:",
        "  xss-reflected    Reflected XSS 스캔",
        "  xss-dom          DOM-based XSS 스캔",
        "  xss-stored       Stored XSS 스캔",
        "  sqli             SQL Injection 스캔",
        "  cmdi             Command Injection 스캔",
        "  ssrf             SSRF 스캔",
        "  file-upload      File Upload 취약점 스캔",
        "  file-download    File Download 취약점 스캔",
        "",
        "사용 예시:",
        "  python main.py -url https://example.com",
        "  python main.py -url https://example.com --enable xss-reflected,sqli",
        "  python main.py -url https://example.com  --workers 6 --threads 12",
        "",
        "",
        "",
        "",
    ]

    # 두 리스트의 최대 길이 계산
    max_lines = max(len(art_lines), len(manual_lines))

    # 빈 라인으로 패딩
    while len(art_lines) < max_lines:
        art_lines.append(" " * 100)  # ASCII 아트 너비만큼 공백
    while len(manual_lines) < max_lines:
        manual_lines.append("")

    # 나란히 출력
    for art_line, manual_line in zip(art_lines, manual_lines):
        print(f"{art_line}  {manual_line}")

    print()  # 마지막에 빈 줄 추가


if __name__ == "__main__":
    main()
