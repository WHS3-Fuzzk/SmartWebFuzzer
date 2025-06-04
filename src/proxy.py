"""
[프록시 모듈]
이 모듈은 mitmproxy 프록시 서버를 서브 프로세스로 실행하고,
프록시 서버에 연결한 Selenium Chrome 브라우저를 실행하여
사용자가 입력한 URL에 접속하는 기능을 제공합니다.
"""

import os
import platform
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager


PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080

traffic_filter_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "traffic_filter.py"
)


def run_mitmproxy() -> subprocess.Popen:
    """
    OS별로 mitmproxy를 서브 프로세스로 실행한다.

    Returns:
        subprocess.Popen: mitmproxy 프로세스 객체
    """
    system = platform.system()
    env = os.environ.copy()
    cmd = (
        f'mitmdump -s "{traffic_filter_path}" '
        f"--no-http2 -q --set console_eventlog_verbosity=error"
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
            "mitmdump",
            "-s",
            traffic_filter_path,
            "--no-http2",
            "-q",  # quiet 모드
            "--set",
            "console_eventlog_verbosity=error",
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
