"""
dom_xss.py

Dom XSS 취약점 스캐너 모듈입니다.
BaseScanner를 상속받아 요청 변조 및 결과 분석 기능을 구현합니다.
"""

# 1. 표준 라이브러리
import atexit
import copy
import threading
from datetime import datetime
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse, urlencode

# 2. 서드파티 라이브러리
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import InvalidCookieDomainException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException

# 3. 자체 모듈 (로컬)
from db_writer import (
    insert_fuzzed_request,
    insert_fuzzed_response,
    insert_vulnerability_scan_result,
)
from scanners.base import BaseScanner
from scanners.utils import to_fuzzed_request_dict
from typedefs import RequestData


class DomXss(BaseScanner):
    """
    BaseScanner를 상속받는 예시 취약점 스캐너
    """

    @property
    def vulnerability_name(self) -> str:
        return "Dom_XSS"

    def __init__(self):
        """
        페이로드 불러오기
        """
        self.payloads = [
            "'\"fake=whs3fuzzk><whs3fuzzk>"
        ]  # 한 개 페이로드를 리스트로 만들어서 할당
        self.driver = None  # 분석 시 최초 1회만 생성
        self._driver_lock = threading.Lock()  # 🔒 락 생성
        atexit.register(self.close_driver)  # 종료 시 자동 실행 등록

    def close_driver(self):
        """
        메인 종료시 DOM 셀레니움 WebDriver 종료
        """
        if self.driver:
            print("[INFO] Dom 분석 드라이버 종료 중...")
            self.driver.quit()
            self.driver = None

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """
        이 스캐너가 해당 요청을 퍼징할 가치가 있는지 판단
        예시: GET 요청 또는 application/x-www-form-urlencoded POST만 대상으로 함
        """
        method = request["meta"]["method"]
        headers = request["headers"]
        content_type = ""
        if headers is not None:
            for header in headers:
                if header.get("key", "").lower() == "Content-Type".lower():
                    content_type = header.get("value", "")

        if method == "GET":
            return True
        if method == "POST" and "application/x-www-form-urlencoded" in content_type:
            return True
        return False  # super().is_target(request)는 호출할 필요 없음

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """
        주어진 요청에서 각 쿼리 파라미터에 대해 페이로드를 삽입한 변조 요청 생성기
        """
        query_params = request.get("query_params") or []
        for payload in self.payloads:
            for i in range(len(query_params)):
                original_request = copy.deepcopy(request)  # ✅ request 전체 깊은 복사
                fuzzed_params = original_request["query_params"] or []
                fuzzed_params[i]["value"] = payload

                original_request["extra"] = {
                    "fuzzed_param": fuzzed_params[i]["key"],
                    "payload": payload,
                }

                print(
                    "[+] Generated fuzzing request with payload on "
                    f"{fuzzed_params[i]['key']}: {payload}"
                )

                yield original_request

    def inject_cookies(self, driver, url: str, cookies: List[Dict[str, str]] = None):
        """
        셀레니움 WebDriver에 대상 URL의 도메인 쿠키를 삽입합니다.
        """
        if not cookies:
            return
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.hostname}/"
        driver.get(base_url)
        for cookie in cookies:
            cookie_to_add = cookie.copy()
            try:
                driver.add_cookie(cookie_to_add)
            except (InvalidCookieDomainException, WebDriverException) as e:
                print(f"[WARN] Failed to add cookie: {cookie_to_add} — {e}")

    def analyze_dom_with_selenium(
        self, url: str, cookies: List[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        셀레니움을 이용해 해당 URL의 DOM을 분석해 XSS 페이로드가 반영되었는지 확인
        """
        driver = self.driver

        # ✅ 2. 쿠키 삽입
        self.inject_cookies(driver, url, cookies)

        # ✅ 3. 실제 URL 접근
        print(f"[INFO] Accessing target: {url}")
        driver.get(url)
        # ✅ WebDriverWait으로 <html> 태그 로드 대기
        try:
            WebDriverWait(driver, 3).until(
                EC.presence_of_element_located((By.TAG_NAME, "html"))
            )
        except TimeoutException:
            print("[WARN] Timeout while waiting for page HTML to load")

        # ✅ 3.5. 에러 페이지 감지
        has_error_div = driver.execute_script(
            """
            return document.querySelector("div.error-code") !== null;
        """
        )
        if has_error_div:
            print("[INFO] 에러 페이지 감지됨 — DOM 분석 스킵")
            return {
                "xss_detected": False,
                "url": url,
                "error_detected": True,
                "error_reason": "Browser error page detected (div.error-code)",
            }

        # ✅ 4. 위험한 DOM 메서드 목록
        dangerous_methods = [
            "document.write",
            "document.writeln",
            "document.domain",
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "onerror",
            "onload",
            "eval",
            "Function",
            "setTimeout",
            "setInterval",
            "location.href",
            "location.assign",
            "location.replace",
            "window.name",
            "window.location",
            "document.location",
            "window.open",
            "window.postMessage",
            "localStorage",
            "sessionStorage",
            "createElement",
            "appendChild",
            "insertBefore",
            "replaceChild",
            "removeChild",
            "cloneNode",
            "setAttribute",
            "addEventListener",
            "attachEvent",
            "document.cookie",
            "document.referrer",
            "navigator.userAgent",
            "navigator.clipboard",
        ]

        # ✅ 5. 스크립트 태그 내 코드 수집
        script_contents = driver.execute_script(
            """
            let scripts = document.getElementsByTagName('script');
            let result = [];
            for (let s of scripts) {
                if (s.innerText) {
                    result.push(s.innerText);
                }
            }
            return result;
        """
        )

        # ✅ 6. 스크립트 코드에 위험한 메서드가 포함되어 있는지 검사
        detected_dangerous_usage = False
        for script in script_contents:
            for method in dangerous_methods:
                if method in script:
                    detected_dangerous_usage = True
                    print(f"[!] 위험 메서드 감지: {method}")
                    break
            if detected_dangerous_usage:
                break

        # ✅ 7. 실제 DOM 삽입 여부 확인 (조건부 실행)
        xss_detected = False
        injected_context = None
        if detected_dangerous_usage:
            xss_detected = driver.execute_script(
                """
                return document.getElementsByTagName('whs3fuzzk').length > 0;
            """
            )
            if xss_detected:
                injected_context = driver.execute_script(
                    """
                    const elem = document.getElementsByTagName('whs3fuzzk')[0];
                    if (elem && elem.parentElement) {
                        return elem.parentElement.outerHTML;
                    }
                    return null;
                """
                )
        return {
            "xss_detected": xss_detected,
            "url": url,
            "error_detected": False,
            "injected_context": injected_context,
        }

    def ensure_driver_initialized(self, request: RequestData = None):
        """
        요청 최초 1회 DOM 셀레니움 WebDriver 실행 기능
        """
        if self.driver:
            return
        with self._driver_lock:
            if self.driver:
                return
            print("[INFO] Dom 분석 브라우저 최초 실행")
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")
            self.driver = webdriver.Chrome(options=options)
            scheme = "http://" if request["meta"].get("is_http", 1) == 1 else "https://"
            domain = request["meta"]["domain"]
            base_path = "/" + "/".join(
                request["meta"].get("path", "/").strip("/").split("/")[:2]
            )
            base_url = f"{scheme}{domain}{base_path}/"
            if base_url:
                print(f"[INFO] Accessing base (driver initialized): {base_url}")
                self.driver.get(base_url)

    def run(self, request_id: int, request: RequestData) -> List[Dict[str, Any]]:
        """
        DOM XSS 스캐너의 메인 실행 함수.
        1. 드라이버 초기화
        2. 변조 요청 생성 및 비동기 전송
        3. 응답 수집 후 URL 구성 및 분석
        4. XSS 결과 저장
        """
        print(f"[{self.vulnerability_name}] 요청 ID: {request_id}")
        if not self.is_target(request_id, request):
            return []
        self.ensure_driver_initialized(
            request
        )  # ✅ 드라이버가 없다면 최초 한 번만 실행

        results = []
        for fuzz_request in self.generate_fuzzing_requests(request):
            # 3️⃣ URL 구성
            full_url = self._build_full_url(fuzz_request)
            print(f"[DEBUG] Full URL for analysis: {full_url}")

            # 4️⃣ 쿠키 파싱
            cookies = self._parse_cookies(fuzz_request)

            # 5️⃣ 셀레니움으로 분석
            dom_result = self.analyze_dom_with_selenium(full_url, cookies=cookies)

            # 6️⃣ 결과 정리
            result_data = {
                "url": full_url,
                "fuzzed_param": fuzz_request["extra"]["fuzzed_param"],
                "payload": fuzz_request["extra"]["payload"],
                "xss_detected": dom_result["xss_detected"],
            }
            results.append(result_data)

            # 7️⃣ XSS가 감지된 경우 DB 저장
            if dom_result["xss_detected"]:
                print(f"[!] DOM-XSS 감지됨 → {full_url}")
                self._handle_scan_result(
                    request_id, fuzz_request, dom_result.get("injected_context")
                )
            else:
                print(f"[-] DOM-XSS 없음 → {full_url}")

        return results

    def _build_full_url(self, fuzz_request: RequestData) -> str:
        """
        fuzz_request에서 메타데이터를 기반으로 전체 분석 대상 URL을 생성
        예: http://domain/path?key=val
        """
        scheme = "http" if fuzz_request["meta"].get("is_http", 1) == 1 else "https"
        domain = fuzz_request["meta"]["domain"]
        path = fuzz_request["meta"]["path"]
        query_params = fuzz_request.get("query_params", [])

        query_string = (
            urlencode({qp["key"]: qp["value"] for qp in query_params})
            if query_params
            else ""
        )
        return (
            f"{scheme}://{domain}{path}?{query_string}"
            if query_string
            else f"{scheme}://{domain}{path}"
        )

    def _parse_cookies(self, fuzz_request: RequestData) -> List[Dict[str, str]]:
        """
        fuzz_request의 헤더에서 쿠키 값을 파싱하여 Selenium 쿠키 리스트로 변환
        """
        cookie_header = next(
            (
                h["value"]
                for h in fuzz_request.get("headers", [])
                if h["key"].lower() == "cookie"
            ),
            "",
        )
        cookies = []
        for pair in cookie_header.split(";"):
            if "=" in pair:
                name, value = pair.strip().split("=", 1)
                cookies.append({"name": name, "value": value})
        return cookies

    def _handle_scan_result(
        self, request_id: int, fuzz_request: RequestData, injected_context: str = None
    ):
        """
        XSS가 감지된 경우, DB에 관련 요청/응답/취약점 정보를 저장하는 처리
        """
        payload = fuzz_request.get("extra", {}).get("payload", "")

        # 1. 변조 요청 저장
        fuzzed_request_id = insert_fuzzed_request(
            to_fuzzed_request_dict(
                fuzz_request,
                original_request_id=request_id,
                scanner=self.vulnerability_name,
                payload=payload,
            )
        )

        # 2. 응답 저장 (빈 응답으로 처리)
        insert_fuzzed_response({}, fuzzed_request_id)

        # 3. 취약점 결과 저장
        result_id = insert_vulnerability_scan_result(
            {
                "vulnerability_name": self.vulnerability_name,
                "original_request_id": request_id,
                "fuzzed_request_id": fuzzed_request_id,
                "domain": fuzz_request.get("meta", {}).get("domain", ""),
                "endpoint": fuzz_request.get("meta", {}).get("path", ""),
                "method": fuzz_request.get("meta", {}).get("method", ""),
                "payload": payload,
                "parameter": fuzz_request.get("extra", {}).get("fuzzed_param", ""),
                "extra": {
                    "confidence": 0.9,
                    "details": "DOM XSS 감지됨",
                    "details2": [
                        "=== <whs3fuzzk> 태그가 생성됨 ===",
                        f"[커스텀 태그 발견] {injected_context}",
                    ],
                    "timestamp": datetime.now().isoformat(),
                },
            }
        )
        print(f"✅ DOM XSS 스캔 결과 저장 완료: {result_id}")
