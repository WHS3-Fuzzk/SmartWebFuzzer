# pylint: disable=duplicate-code
"""
reflected_xss.py

Reflected XSS 취약점 스캐너 모듈입니다.
BaseScanner를 상속받아 요청 변조 및 결과 분석 기능을 구현합니다.
"""

# ✅ 표준 라이브러리
import json
import copy
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List

# ✅ 서드파티
import quickjs
from bs4 import BeautifulSoup
from celery import chain

# ✅ 자체 모듈
from db_writer import (
    insert_fuzzed_request,
    insert_fuzzed_response,
    insert_vulnerability_scan_result,
)
from scanners.base import BaseScanner
from scanners.utils import to_fuzzed_request_dict, to_fuzzed_response_dict
from fuzzing_scheduler.fuzzing_scheduler import celery_app, send_fuzz_request
from typedefs import RequestData


def append_custom_tag_surrounding_info(results: list, custom_tag) -> None:
    """
    커스텀 태그 주변 정보(부모, 이전/다음 형제 태그) 결과 리스트에 추가
    """
    results.append(f"[커스텀 태그 발견] <{custom_tag.name}> → {str(custom_tag)}")

    parent = custom_tag.parent
    if parent:
        results.append(f"  - 부모 태그: <{parent.name}> → {str(parent)}")

    for sibling, desc in [
        (custom_tag.previous_sibling, "이전"),
        (custom_tag.next_sibling, "다음"),
    ]:
        if sibling and getattr(sibling, "name", None):
            results.append(f"  - {desc} 형제 태그: <{sibling.name}> → {str(sibling)}")

    results.append("")


def inspect_custom_tag_attributes(soup, markers, payload) -> List[str]:
    """
    whs3fuzzk 태그가 생성되었을 때 해당 속성 및 주변 정보를 수집
    """
    results = []
    found_in_attr = False

    results.append("=== <whs3fuzzk> 태그가 생성됨 → 모든 태그에서 속성 검사 시작 ===")
    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            # str, list 아닌 애들은 무시
            if not isinstance(value, (str, list)):
                continue

            if isinstance(value, str):
                if any(m in value for m in markers):
                    found_in_attr = True
                    results.append(
                        f"<{tag.name}> 태그의 '{attr}' 속성에서 발견 → {value}"
                    )
                    results.append(f"→ (테스트 페이로드: '{payload}')")
                    results.append(f"→ 해당 태그 전체: {str(tag)}")
                    continue

            if isinstance(value, list):
                # markers 중 하나라도 포함된 항목들 필터링
                matched_items = [
                    item for item in value if any(m in item for m in markers)
                ]
                if matched_items:
                    found_in_attr = True
                    for item in matched_items:
                        results.append(
                            f"<{tag.name}> 태그의 '{attr}' 속성(list)에서 발견 → {item}"
                        )
                        results.append(f"→ (테스트 페이로드: '{payload}')")
                        results.append(f"→ 해당 태그 전체: {str(tag)}")
                    continue

    # 속성에서 발견 못했을 경우, 커스텀 태그 주변 정보 출력
    if not found_in_attr:
        custom_tags = soup.find_all(markers)
        for ctag in custom_tags:
            append_custom_tag_surrounding_info(results, ctag)

    return results


def check_payload_in_attributes(html_text, payload):
    """
    HTML 내에서 페이로드가 속성(attribute) 값에 반영됐는지 검사
    """
    results = []
    soup = BeautifulSoup(html_text, "html.parser")
    markers = ["whs3fuzzk"]

    custom_tags = soup.find_all(markers)
    if custom_tags:
        results += inspect_custom_tag_attributes(soup, markers, payload)
    else:
        print(f"[rXSS] <whs3fuzzk> 태그는 생성되지 않음. 속성 검사 생략됨.")

    return results


def analyze_script_payload(html: str, payload: str):
    """
    HTML에서 <script> 태그를 추출하고, 내부에 페이로드가 포함된 JS 코드만 실행하여
    문법 오류(SyntaxError) 여부를 판단합니다.

    Args:
        html (str): HTML 원본 문자열
        payload (str): 삽입한 XSS 테스트 페이로드
    """
    results = []
    # 1. HTML 파싱
    soup = BeautifulSoup(html, "html.parser")
    script_tags = soup.find_all("script")

    results.append(f"[+] <script> 태그 개수: {len(script_tags)}")

    ctx = quickjs.Context()

    if not script_tags:
        results.append("❌ <script> 태그가 아예 없습니다!")
        return results

    for idx, tag in enumerate(script_tags):
        script_code = tag.get_text() if hasattr(tag, "get_text") else str(tag)

        if script_code and payload in script_code:
            results.append(
                f"[{idx}] 🎯 내 페이로드 포함된 <script> 내용:{script_code.strip()}"
            )
            try:
                ctx.eval(script_code)
                results.append(f"[{idx}] ✅ 정상 실행됨")
            except quickjs.JSException as e:  # 구체적인 예외만 잡음
                err_msg = str(e)
                if (
                    "SyntaxError" in err_msg
                    or "Unknown JavaScript error during parse" in err_msg
                ):
                    results.append(
                        f"[{idx}] ❌ JS 문법 오류 발생 (취약점 의심): {err_msg}"
                    )
                else:
                    results.append(f"[{idx}] ⚠️ 기타 JS 실행 오류: {err_msg}")
        else:
            results.append(f"[{idx}] ⏭️ 페이로드 미포함 또는 이스케이프. 스킵됨.")

    return results


class ReflectedXss(BaseScanner):
    """
    BaseScanner를 상속받는 reflected-xss 취약점 스캐너
    """

    @property
    def vulnerability_name(self) -> str:
        return "rXSS"

    def __init__(self):
        # base_dir = os.path.dirname(os.path.abspath(__file__))  # src/scanners 폴더 경로
        # payload_file = os.path.join(base_dir, "payloads", "xss.txt")  # payloads/xss.txt 경로

        # with open(payload_file, 'r', encoding='utf-8') as f:
        #     self.payloads = [line.strip() for line in f if line.strip()]
        """
        페이로드 불러오기
        """
        self.payloads = [
            "'\"fake=whs3fuzzk><whs3fuzzk>"
        ]  # 한 개 페이로드를 리스트로 만들어서 할당

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """
        이 스캐너가 해당 요청을 퍼징할 가치가 있는지 판단
        예시: GET 요청 또는 application/x-www-form-urlencoded POST만 대상으로 함
        """
        method = request["meta"]["method"]
        headers = request.get("headers") or []
        content_type = ""
        for header in headers:
            if header.get("key", "").lower() == "content-type":
                content_type = header.get("value", "")
        if method == "GET":
            return True
        if method == "POST" and "application/x-www-form-urlencoded" in content_type:
            return True
        return False

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

                # print(
                #     "[+] Generated fuzzing request with payload on "
                #     f"{fuzzed_params[i]['key']}: {payload}"
                # )

                yield original_request

    def handle_completed_tasks(
        self,
        async_results: List[Any],
        request_id: int,
    ) -> None:  # 반환 타입 표기를 한 줄 내려서 시도
        """
        완료된 비동기 작업을 처리하고, 결과를 DB에 저장
        """
        pending = list(async_results)

        while pending:
            # print(f"[{self.vulnerability_name}] 대기 중인 작업 수: {len(pending)}")
            for res in pending[:]:
                if res.ready():
                    result = res.get()
                    # print(
                    #     f"[{self.vulnerability_name}] 완료된 작업: {res.id}"
                    # )  # result 결과 보기 생략 (너무 길어짐)
                    # 추가 동작
                    if result and res.parent is not None:

                        # print(
                        #     f"요청: {res.parent.get().get('request_data')}\n"
                        #     f"응답: {res.parent.get()}\n"
                        #     f"분석 결과: {result}\n"
                        # )

                        fuzzed_request: RequestData = res.parent.get().get(
                            "request_data"
                        )  # 퍼징 요청

                        fuzzed_request_dict = to_fuzzed_request_dict(
                            fuzzed_request,
                            original_request_id=request_id,
                            scanner=self.vulnerability_name,
                            payload=fuzzed_request.get("extra", {}).get("payload", ""),
                        )

                        fuzzed_response = res.parent.get()  # 퍼징 응답
                        fuzzed_response = to_fuzzed_response_dict(fuzzed_response)

                        # 퍼징 요청과 응답을 DB에 저장

                        fuzzed_request_id = insert_fuzzed_request(fuzzed_request_dict)
                        insert_fuzzed_response(fuzzed_response, fuzzed_request_id)

                        # 취약점이 발견된 경우에만 vulnerability_scan_results에 저장
                        if result and result != {}:
                            # print(f"취약점 발견: {result}")
                            scan_result = {
                                "vulnerability_name": self.vulnerability_name,
                                "original_request_id": request_id,
                                "fuzzed_request_id": fuzzed_request_id,
                                "domain": fuzzed_request.get("meta", {}).get(
                                    "domain", ""
                                ),
                                "endpoint": fuzzed_request.get("meta", {}).get(
                                    "path", ""
                                ),
                                "method": fuzzed_request.get("meta", {}).get(
                                    "method", ""
                                ),
                                "payload": fuzzed_request.get("extra", {}).get(
                                    "payload", ""
                                ),
                                "parameter": fuzzed_request.get("extra", {}).get(
                                    "fuzzed_param", ""
                                ),
                                "extra": {
                                    "confidence": 0.9,
                                    "details": result.get("evidence", "취약점 발견"),
                                    "details2": result.get("attribute_check", "없음"),
                                    "details3": result.get("script_check", "없음"),
                                    "timestamp": datetime.now().isoformat(),
                                },
                            }
                            # 취약점 스캔 결과를 DB에 저장
                            insert_vulnerability_scan_result(scan_result)
                            print(f"[{self.vulnerability_name}] 취약점 스캔 결과 저장 완료")
                        else:
                            print(f"[{self.vulnerability_name}] 취약점이 발견되지 않았습니다.")

                        print(f"[{self.vulnerability_name}] 퍼징 요청 저장 완료")
                    else:
                        print(f"[{self.vulnerability_name}] 취약점 없음")

                    pending.remove(res)
            time.sleep(0.5)

    def run(
        self,
        request_id: int,
        request: RequestData,
    ) -> List[Dict[str, Any]]:
        """
        해당 요청을 변조하여 퍼징 요청 생성 및 전송, 결과 수집
        """
        # print(f"[{self.vulnerability_name}]\n요청 ID: {request_id}\n")
        # if not self.is_target(request_id, request): # vul.py로 테스트할거면 이거 주석 처리하면됨
        #     return []

        async_results = []

        for fuzz_request in self.generate_fuzzing_requests(request):
            task_chain = chain(
                send_fuzz_request.s(fuzz_request) | analyze_response_reflected_xss.s()
            )
            result = task_chain.apply_async()
            async_results.append(result)

        # ⏳ 결과를 전부 모아서 수집

        results = []
        for async_result in async_results:
            output = async_result.get(timeout=30)
            # print(
            #     "[{self.vulnerability_name}] 페이로드 포함 여부 결과:\n"
            #     + json.dumps(output, indent=2, ensure_ascii=False)
            # )
            results.append(output)

        # ✅ 완료된 비동기 작업의 결과를 수집
        self.handle_completed_tasks(async_results, request_id)

        return results


@celery_app.task(name="tasks.analyze_response_reflected_xss", queue="analyze_response")
def analyze_response_reflected_xss(response: dict) -> dict:
    """
    응답을 분석해 취약점을 발견하면 Finding 리스트 반환
    - 페이로드가 응답 본문에 반영되면 취약점으로 판단
    - 변조된 파라미터명을 findings['param']에 기록
    """
    vulnerability = {}
    payload = "'\"fake=whs3fuzzk><whs3fuzzk>"
    response_text = response.get("text", "")

    if "whs3fuzzk" in response_text:
        # 속성 검사
        attr_results = check_payload_in_attributes(response_text, payload)
        # 스크립트 내부 JS 검사
        script_results = analyze_script_payload(response_text, payload)
        vulnerability = {
            "payload": payload,
            "evidence": "응답에 페이로드가 반영됨",
            "url": response.get("url"),
            "attribute_check": attr_results,
            "script_check": script_results,
        }

        # print(f"[rXSS] 취약점 발견! URL: {vulnerability['url']}")
        return vulnerability

    print("[rXSS] 페이로드가 응답에 없음")
    return vulnerability
