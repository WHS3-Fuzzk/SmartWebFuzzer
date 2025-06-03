"""
이 모듈은 mitmproxy를 새 터미널에서 실행하고,
Selenium Chrome 브라우저를 mitmproxy 프록시를 통해 실행하여
사용자가 입력한 URL에 접속하는 기능을 제공합니다.
"""

import os
import time
import platform
import subprocess
import urllib.parse

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

from traffic_filter import build_view_filter


PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080

traffic_filter_path = os.path.abspath("traffic_filter.py")


def run_mitmproxy_in_new_terminal(view_filter: str) -> subprocess.Popen:
    """
    OS별로 mitmproxy를 새 터미널에서 실행한다.

    Args:
        view_filter (str): mitmproxy view-filter 문자열

    Returns:
        subprocess.Popen: mitmproxy 프로세스 객체
    """
    system = platform.system()
    env = os.environ.copy()
    cmd = (
        f'mitmproxy -s "{traffic_filter_path}" '
        f'--view-filter "{view_filter}" --no-http2 -v'
    )

    if system == "Windows":
        powershell_cmd = [
            "powershell",
            "-Command",
            f"Start-Process cmd -ArgumentList '/k {cmd}' -Verb RunAs",
        ]
        return subprocess.Popen(powershell_cmd, env=env)

    if system == "Darwin":
        cmd = [
            "mitmproxy",
            "-s",
            traffic_filter_path,
            "--view-filter",
            view_filter,
            "--no-http2",
            "-v",
        ]
        return subprocess.Popen(cmd, env=env)

    if system == "Linux":
        return subprocess.Popen(
            ["gnome-terminal", "--", "bash", "-c", f"sudo {cmd}; exec bash"], env=env
        )

    raise OSError("이 운영체제에서는 관리자 권한 새 터미널 실행이 지원되지 않습니다.")


def start_browser_and_browse() -> webdriver.Chrome:
    """
    Selenium Chrome 브라우저를 mitmproxy 프록시로 실행한다.

    Returns:
        webdriver.Chrome: Selenium 드라이버 객체
    """
    chrome_options = Options()
    chrome_options.add_argument(f"--proxy-server={PROXY_HOST}:{PROXY_PORT}")
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--remote-allow-origins=*")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()), options=chrome_options
    )
    return driver


def main():
    """
    메인 함수:
    1. 사용자로부터 타겟 URL 리스트 입력 받음
    2. mitmproxy를 새 터미널에서 실행
    3. Selenium 브라우저를 mitmproxy 프록시로 실행 후 각 URL 접속
    """
    input_urls = input(
        "타겟 URL들을 쉼표로 구분해서 입력하세요 (예: https://naver.com,http://testphp.vulnweb.com): "
    )
    urls = [u.strip() for u in input_urls.split(",") if u.strip()]
    if not urls:
        print("URL이 입력되지 않았습니다. 종료합니다.")
        return

    domains = [urllib.parse.urlparse(url).netloc for url in urls]
    view_filter = build_view_filter(domains)
    print(f"[INFO] mitmproxy view filter: {view_filter}")

    print("[INFO] mitmproxy 새 터미널에서 시작 중...")
    run_mitmproxy_in_new_terminal(view_filter)
    time.sleep(5)

    driver = None
    try:
        print("[INFO] Selenium 브라우저 시작")
        driver = start_browser_and_browse()

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
        print("[INFO] 종료 중...")
        if driver:
            try:
                driver.quit()
            except WebDriverException as exc:
                print(f"[WARN] 브라우저 종료 중 오류: {exc}")
        print("[INFO] mitmproxy는 새 터미널에서 수동으로 종료해야 합니다.")


if __name__ == "__main__":
    main()
