# src/scanners/file_download.py

"""
FileDownloadScanner: 파일 다운로드 취약점 탐지 스캐너

- Content-Disposition: attachment 확인
- 경로 우회(payload)를 통한 파일 다운로드 시도
- 분석 결과 취약 증거가 존재할 경우 기록
"""
import copy
import os
import hashlib
from typing import Any, Dict, Iterable, List, Optional, cast

# from celery import chain

from typedefs import QueryParam, RequestData
from fuzzing_scheduler.fuzzing_scheduler import celery_app, send_fuzz_request
from db_writer import (
    insert_fuzzed_request,
    insert_fuzzed_response,
    insert_vulnerability_scan_result,
)
from db_reader import DBReader
from scanners.base import BaseScanner
from scanners.utils import to_fuzzed_request_dict, to_fuzzed_response_dict


class FileDownloadScanner(BaseScanner):
    """
    파일 다운로드 취약점을 탐지하기 위한 스캐너 클래스.
    """

    def __init__(self):
        super().__init__()
        self.base_dir = os.path.dirname(__file__)
        self.request_id: int = -1
        self.original_body: Optional[str] = None  # 해시값으로 저장
        self.current_stage: int = 1  # 현재 퍼징 단계 (1: 초기, 2: 경로 우회)

    @property
    def vulnerability_name(self) -> str:
        """
        취약점 이름 반환 (대시보드 기록용)
        """
        return "File Download"

    def is_target(self, _request_id: int, request: RequestData) -> bool:
        """
        파일 다운로드 관련 요청인지 확인하는 함수.
        - Content-Disposition 헤더에 attachment가 포함되어 있는지 확인
        - 쿼리 파라미터에 filename, file, filepath, download, host 등의 키가 있는지 확인
        """

        # 원본 요청에 응답을 request_id로 파싱, 헤더에서 Content-Disposition이 있는 지 확인.
        db_reader = DBReader()
        original_response = db_reader.select_filtered_response(_request_id)

        # headers를 딕셔너리로 변환
        headers_list = original_response.get("headers", []) or []
        headers = {}
        for header in headers_list:
            if isinstance(header, dict) and "key" in header and "value" in header:
                headers[header["key"]] = header["value"]

        content_disp = headers.get("Content-Disposition", "").lower()
        if "attachment" not in content_disp:
            print(f"[{self.vulnerability_name}] Content-Disposition 없음 → 퍼징 생략")
            return False
        print(f"[{self.vulnerability_name}] Content-Disposition 있음 -> 퍼징 시작")

        query_params = request.get("query_params") or []
        target_keys = {"filename", "file", "filepath", "download", "host"}
        if not any(
            param.get("key", "").lower() in target_keys for param in query_params
        ):
            return False
        # 원본 바디 저장
        body_data = original_response.get("body", {}) or {}
        if isinstance(body_data, dict) and "body" in body_data:
            body_content = body_data["body"]
        else:
            body_content = body_data

        content_encoding = body_data["content_encoding"]
        if isinstance(body_content, str):
            body_content = body_content.encode(
                content_encoding if content_encoding != "identity" else "utf-8",
                errors="replace",
            )
            # 처음 1000바이트만 해시 처리하여 저장
            self.original_body = hashlib.sha256(body_content[:1000]).hexdigest()

        return True

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """
        단계별 경로 우회 페이로드를 삽입한 변조 요청을 생성.
        self.current_stage에 따라 payload 선택.
        """
        query_params = cast(List[QueryParam], request.get("query_params") or [])

        param_key_set = {"filename", "file", "filepath"}

        payloads_by_stage = {
            1: ["/", "/./"],
            2: ["/../"],
        }

        for payload in payloads_by_stage.get(self.current_stage, []):
            mutated_params = self._build_mutated_params(
                query_params, param_key_set, payload
            )

            # 변조된 요청 생성
            mutated = copy.deepcopy(request)
            mutated["query_params"] = mutated_params

            # extra 정보 설정
            mutated["extra"] = {
                "payload": payload,
                "stage": self.current_stage,
                "payload_type": "path_traversal",
                "param_key": next(
                    (
                        p["key"]
                        for p in mutated_params
                        if p["key"].lower() in param_key_set
                    ),
                    "",
                ),
            }

            # print(f"[GEN] STAGE {self.current_stage} → payload: {payload}")
            yield mutated

    def _build_mutated_params(
        self, query_params: List[QueryParam], target_keys: set[str], payload: str
    ) -> List[QueryParam]:
        """
        지정된 키에 대해서만 페이로드를 삽입한 새로운 쿼리 파라미터 리스트를 생성.
        """
        return [
            {
                "key": p["key"],
                "value": (
                    f"{payload.rstrip('/')}/{p['value'].lstrip('/')}"
                    if p["key"].lower() in target_keys
                    else p["value"]
                ),
                "source": p.get("source", "fuzz"),
            }
            for p in query_params
        ]

    def run(self, request_id: int, request: RequestData) -> List[Dict[str, Any]]:
        """
        메인 실행 함수.
        """
        self.request_id = request_id
        # print(f"[{self.vulnerability_name}]\n요청 ID: {request_id}")

        if not self.is_target(request_id, request):
            print(f"[{self.vulnerability_name}] is_target 조건 불충족")
            return []

        for stage in [1, 2]:
            print(f"\n[{self.vulnerability_name}]=== [STAGE {stage}] 퍼징 시작 ===")
            self.current_stage = stage
            self._run_stage_fuzzing(request)

        return []

    def _run_stage_fuzzing(self, request: RequestData):
        """
        퍼징 실행 함수
        """

        for fuzz_request in self.generate_fuzzing_requests(request):

            # Celery 태스크를 비동기로 실행
            async_result = send_fuzz_request.delay(fuzz_request)
            fuzz_response = async_result.get(timeout=30)

            # 비교 및 성공 여부 판단
            is_same = False  # STAGE 1용

            # print(f"[{self.vulnerability_name}] 현재 stage 값: {self.current_stage}")
            if self.current_stage == 1:
                print(
                    f"[{self.vulnerability_name}] STAGE 1 → 파일 다운로드 기반 비교 진입"
                )

                # HTTP 응답 body를 직접 비교
                fuzz_body = fuzz_response.get("body", b"")
                if isinstance(fuzz_body, str):
                    fuzz_body = fuzz_body.encode("utf-8", errors="replace")

                # 원본 파일과 직접 비교 (처음 1000바이트만)
                fuzz_hash = hashlib.sha256(fuzz_body[:1000]).hexdigest()
                is_same = fuzz_hash == self.original_body

            elif self.current_stage == 2:
                fuzz_body = fuzz_response.get("body", b"")
                if isinstance(fuzz_body, str):
                    fuzz_body = fuzz_body.encode("utf-8", errors="replace")
                if fuzz_body and len(fuzz_body) > 0:
                    print(
                        f"[{self.vulnerability_name}] STAGE {self.current_stage} → 다운로드 응답 감지됨"
                    )

            # Celery 분석 요청

            extra = {
                **fuzz_request.get("extra", {}),
                "is_same_file": is_same,  # ✅ STAGE 1 판단용
            }

            async_result = analyze_file_download_response.apply_async(
                args=[{**fuzz_response, "extra": extra}]
            )
            result = async_result.get()
            payload = fuzz_request.get("extra", {}).get("payload", "")

            req_dict = to_fuzzed_request_dict(
                fuzz_request,
                self.request_id,
                self.vulnerability_name,
                payload,
            )
            resp_dict = to_fuzzed_response_dict(fuzz_response, remove_null=True)

            fuzzed_request_id = insert_fuzzed_request(req_dict)
            insert_fuzzed_response(resp_dict, fuzzed_request_id)

            if result:

                if result.get("evidence"):
                    insert_vulnerability_scan_result(
                        {
                            "vulnerability_name": self.vulnerability_name,
                            "original_request_id": self.request_id,
                            "fuzzed_request_id": fuzzed_request_id,
                            "domain": req_dict.get("domain", ""),
                            "endpoint": req_dict.get("path", ""),
                            "method": req_dict.get("method", ""),
                            "payload": payload,
                            "parameter": fuzz_request.get("extra", {}).get(
                                "param_key", "-"
                            ),
                            "extra": {
                                "confidence": 0.9,
                                "details": result.get("evidence"),
                                "type": "File Download",
                            },
                        }
                    )
                    print(f"[{self.vulnerability_name}] 취약점 스캔 결과 저장 완료")


@celery_app.task(name="tasks.analyze_file_download_response", queue="analyze_response")
def analyze_file_download_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    퍼징 응답을 분석하는 Celery 태스크 함수.
    - STAGE 1: 동일 파일 여부 기반 판단
    - STAGE 2: 상위 경로 접근으로 다른 파일 응답 여부 확인
    """

    extra = response.get("extra", {}) or {}

    payload = extra.get("payload", "")
    stage = extra.get("stage", 0)
    is_same_file = extra.get("is_same_file", False)
    headers = response.get("headers", {}) or {}
    content_disposition = headers.get("Content-Disposition", "").lower()

    evidence = None

    body = response.get("body", b"")

    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")

    if stage == 1:
        if is_same_file:

            evidence = f"1단계: 경로 조작 '{payload}' 사용 시 동일 파일 다운로드됨. 취약점 가능성 ⬆️"
        else:
            evidence = (
                f"1단계: 경로 조작 '{payload}' 사용 시 다른 응답 반환됨 (파일 다름)"
            )

    if stage == 2:
        if "attachment" in content_disposition and body and len(body) > 0:
            evidence = (
                f"2단계: 경로 우회('{payload}') 시 파일 다운로드 성공 → 취약점 가능성 ⬆️"
            )
        else:
            evidence = "파일 다운로드 실패 → 취약 가능성 낮음"

    return {
        "evidence": evidence,
    }
