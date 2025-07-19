# src/scanners/file_download.py
# pylint: skip-file
"""
FileDownloadScanner: 파일 다운로드 취약점 탐지 스캐너

- Content-Disposition: attachment 확인
- 경로 우회(payload)를 통한 파일 다운로드 시도
- 분석 결과 취약 증거가 존재할 경우 기록
"""

# 1. 표준 라이브러리
from datetime import datetime
import glob
import hashlib
import json
import copy
import os
import time
from typing import Any, Dict, Iterable, List, Optional, cast, Tuple, Set

# 2. 써드파티 라이브러리
from celery import chain
from celery.exceptions import TimeoutError as CeleryTimeoutError, TaskRevokedError
from requests.exceptions import RequestException

# 3. 프로젝트 내부 모듈
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


def remove_nul(text: Any) -> Any:
    """
    문자열 또는 바이트 내에 포함된 널 문자(NUL)를 제거.
    """
    if isinstance(text, str):
        return text.replace("\x00", "")
    if isinstance(text, bytes):
        return text.replace(b"\x00", b"")
    return text


def get_latest_downloaded_file(download_dir: str) -> Optional[str]:
    """
    다운로드 디렉토리에서 가장 마지막에 생성된 파일을 반환.
    (다운로드 응답 감지 시 비교용)
    """
    try:
        files = glob.glob(os.path.join(download_dir, "*"))
        files = [f for f in files if os.path.isfile(f)]
        if not files:
            return None
        latest_file = max(files, key=os.path.getctime)
        return latest_file
    except Exception as e:
        print(f"[ERROR] 최신 파일 탐색 실패: {e}")
        return None


def is_same_file_by_hash(file1: str, file2: str) -> bool:
    """
    두 파일을 읽어 각각의 해시값을 비교하여 동일 파일 여부를 판단.
    """
    try:

        def file_hash(path: str) -> str:
            with open(path, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()

        return file_hash(file1) == file_hash(file2)
    except Exception as e:
        print(f"[ERROR] 파일 해시 비교 실패: {e}")
        return False


class FileDownloadScanner(BaseScanner):
    """
    파일 다운로드 취약점을 탐지하기 위한 스캐너 클래스.
    """

    def __init__(self):
        super().__init__()
        self.base_dir = os.path.dirname(__file__)
        self.request_id: int = -1
        self.body: Optional[bytes] = None

    @property
    def vulnerability_name(self) -> str:
        """
        취약점 이름 반환 (대시보드 기록용)
        """
        return "File Download"

    def is_target(self, _request_id: int, request: RequestData) -> bool:
        """
        요청의 파라미터 중 다운로드 관련 키가 있는지 확인.
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
            print("[SKIPPED] Content-Disposition 없음 → 퍼징 생략\n")
            return False
        print("[OK] Content-Disposition 있음")

        query_params = request.get("query_params") or []
        target_keys = {"filename", "file", "filepath", "download", "host"}
        if not any(
            param.get("key", "").lower() in target_keys for param in query_params
        ):
            return False

        # 원본 파일 저장
        body_data = original_response.get("body", {}) or {}
        if isinstance(body_data, dict) and "body" in body_data:
            body_content = body_data["body"]
        else:
            body_content = body_data

        self.save_original_file(
            body_content,
            headers.get(body_data["content_encoding"], "utf-8"),
        )
        return True

    def generate_fuzzing_requests(
        self, request: RequestData, stage: int
    ) -> Iterable[RequestData]:
        """
        단계별 경로 우회 페이로드를 삽입한 변조 요청을 생성.
        self.current_stage에 따라 payload 선택.
        """
        query_params = cast(List[QueryParam], request.get("query_params") or [])
        base_path = request.get("path", "").split("?")[0]
        param_key_set = {"filename", "file", "filepath"}

        payloads_by_stage = {
            1: ["/", "/./"],
            2: ["/../"],
            3: ["..%2f", "..%252f", "..%c0%af", "..%e0%80%af"],
        }

        for payload in payloads_by_stage.get(stage, []):
            mutated_params = self._build_mutated_params(
                query_params, param_key_set, payload
            )
            query_str = "&".join(f"{p['key']}={p['value']}" for p in mutated_params)
            new_path = f"{base_path}?{query_str}"

            mutated = copy.deepcopy(request)
            mutated["query_params"] = cast(List[QueryParam], mutated_params)
            mutated["extra"] = {
                "payload": payload,
                "stage": stage,
                "fuzzed_path": new_path,
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
            mutated["meta"]["path"] = new_path

            # ✅ 요청 본문 설정 (Body 타입에 맞게 구성)
            body_payload = json.dumps(
                {
                    "fuzzing_stage": stage,
                    "fuzzing_payload": payload,
                    "target_param_keys": list(param_key_set),
                }
            )
            body_bytes = body_payload.encode("utf-8")

            mutated["body"] = {
                "id": 0,
                "request_id": self.request_id,
                "content_type": "application/json",
                "charset": "utf-8",
                "content_length": len(body_bytes),
                "content_encoding": "identity",
                "body": body_payload,
            }

            print(f"[GEN] STAGE {stage} → payload: {payload}, path: {new_path}")
            yield mutated

    def save_original_file(self, body: str, content_encoding: str = "utf-8"):
        """
        body를 파일로 저장하는 함수.
        """
        # body str을 bytes로 변환
        if isinstance(body, str):
            body = body.encode(content_encoding, errors="replace")
            self.body = body

        # ✅ 정상 응답 파일 저장
        try:
            download_dir = os.path.expanduser("~/Downloads")
            os.makedirs(download_dir, exist_ok=True)
            file_path = os.path.join(download_dir, f"original_{self.request_id}.bin")
            with open(file_path, "wb") as f:
                f.write(body)
            print(f"정상 응답 파일 저장됨 → {file_path}")
        except Exception as e:
            print(f"[ERROR] 정상 응답 파일 저장 실패: {e}")

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
        print(f"[{self.vulnerability_name}]\n요청 ID: {request_id}")

        if not self.is_target(request_id, request):
            print("[SKIPPED] is_target 조건 불충족")
            return []

        results = []

        for stage in [1, 2, 3]:
            print(f"\n=== [STAGE {stage}] 퍼징 시작 ===")
            stage_success, stage_results, seen_pairs = self._run_stage_fuzzing(
                request, stage, self.body
            )
            results.extend(stage_results)

            if stage == 1 and not stage_success:
                print(f"[!] STAGE 1에서 유의미한 결과 없음 → 이후 단계 진행")
                continue

            if stage == 2 and stage_success:
                print(f"[+] STAGE 2에서 파일 다운로드 성공 → STAGE 3 생략")
                break

        return results

    def _run_stage_fuzzing(
        self, request: RequestData, stage: int, normal_body: Optional[bytes] = None
    ) -> Tuple[bool, List[Dict[str, Any]], Set[Tuple[str, str]]]:
        """
        퍼징 실행 함수
        """
        results: List[Dict[str, Any]] = []
        seen_pairs: Set[Tuple[str, str]] = set()
        success = False

        for fuzz_request in self.generate_fuzzing_requests(request, stage):
            payload = fuzz_request.get("extra", {}).get("payload", "")
            domain = fuzz_request.get("meta", {}).get("domain", "")
            path = fuzz_request.get("meta", {}).get("path", "")
            url = f"{domain}{path}"

            print(f"[RUN] 퍼징 요청 전송 준비 → payload: {payload}")
            print(f"[RUN] 요청 URL: {url}")

            try:
                fuzz_response = send_fuzz_request(fuzz_request)
                print(
                    f"퍼징 응답 수신 성공 → status: {fuzz_response.get('status_code')}"
                )
            except (RequestException, Exception) as e:
                print(f"[ERROR] 퍼징 요청 실패 (예외: {type(e).__name__}): {e}")
                continue

            # 비교 및 성공 여부 판단
            is_same = False  # STAGE 1용

            print(f"현재 stage 값: {stage}")
            if stage == 1:
                print(f"STAGE 1 → 파일 다운로드 기반 비교 진입함")

                download_dir = os.path.expanduser("~/Downloads")
                original_file_path = os.path.join(
                    download_dir, f"original_{self.request_id}.bin"
                )

                if not os.path.exists(original_file_path):
                    print(f"[ERROR] 정상 파일 없음 → {original_file_path}")
                    continue

                print(f"[INFO] 최신 다운로드 파일 비교 중 → 기준: {original_file_path}")
                time.sleep(2)

                latest_file = get_latest_downloaded_file(download_dir)
                if not latest_file:
                    print(f"[WARN] 다운로드된 파일을 찾을 수 없음")
                    continue

                is_same = is_same_file_by_hash(original_file_path, latest_file)
                if is_same:
                    print(f"[MATCH] 동일 파일 다운로드됨 → payload: {payload}")
                    success = True
                else:
                    print(f"[DIFF] 다운로드된 파일이 다름 → payload: {payload}")

            elif stage in [2, 3]:
                fuzz_body = fuzz_response.get("body", b"")
                if isinstance(fuzz_body, str):
                    fuzz_body = fuzz_body.encode("utf-8", errors="replace")
                if fuzz_body and len(fuzz_body) > 0:
                    print(f"STAGE {stage} → 다운로드 응답 감지됨")
                    success = True

            # Celery 분석 요청
            result = {}
            try:
                extra = {
                    **fuzz_request.get("extra", {}),
                    "is_same_file": is_same,  # ✅ STAGE 1 판단용
                }

                async_result = analyze_file_download_response.apply_async(
                    args=[{**fuzz_response, "extra": extra}]
                )
                result = async_result.get()
            except (CeleryTimeoutError, TaskRevokedError) as e:
                print(f"[!] 분석 태스크 시간 초과 또는 취소됨 → payload: {payload}")
                result = {}
            except Exception as e:
                print(f"[!] 분석 중 예외 발생: {e}")
                result = {}

            if result:
                processed = self._handle_fuzz_result(fuzz_request, result, seen_pairs)
                if processed:
                    results.append(result)
                    success = True
            else:
                print(f"[NO RESULT] → payload: {payload}")

        return success, results, seen_pairs

    def _handle_fuzz_result(
        self,
        fuzz_request: RequestData,
        result: Dict[str, Any],
        seen_pairs: Set[Tuple[str, str]],
    ) -> bool:
        """
        Celery 분석 결과를 처리하여 중복 여부를 확인하고,
        DB에 요청/응답/취약점 결과를 저장한 뒤 성공 여부를 반환한다.
        """
        scan_url = str(result.get("scan_url") or "unknown")
        result_payload = str(result.get("payload") or "")
        if (scan_url, result_payload) in seen_pairs:
            print(f"[DUPLICATE] → {scan_url} / {result_payload}")
            return False
        seen_pairs.add((scan_url, result_payload))

        req_dict = to_fuzzed_request_dict(
            fuzz_request,
            self.request_id,
            self.vulnerability_name,
            result_payload,
        )
        res_dict = to_fuzzed_response_dict(result, remove_null=True)

        fuzzed_request_id = insert_fuzzed_request(req_dict)
        insert_fuzzed_response(res_dict, fuzzed_request_id)

        if result.get("evidence"):
            print(f"[+] 의심 응답 감지됨 → 증거: {result['evidence']}")
            insert_vulnerability_scan_result(
                {
                    "vulnerability_name": self.vulnerability_name,
                    "original_request_id": self.request_id,
                    "fuzzed_request_id": fuzzed_request_id,
                    "domain": req_dict.get("domain", ""),
                    "endpoint": req_dict.get("path", ""),
                    "method": req_dict.get("method", ""),
                    "payload": result_payload,
                    "parameter": fuzz_request.get("extra", {}).get("param_key", "-"),
                    "extra": {
                        "confidence": 0.9,
                        "details": result.get("evidence"),
                        "timestamp": datetime.now().isoformat(),
                        "type": result.get("type", "File Download"),
                    },
                }
            )

        return result.get("success", False)


@celery_app.task(name="tasks.analyze_file_download_response", queue="analyze_response")
def analyze_file_download_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    퍼징 응답을 분석하는 Celery 태스크 함수.
    - STAGE 1: 동일 파일 여부 기반 판단
    - STAGE 2: 상위 경로 접근으로 다른 파일 응답 여부 확인
    - STAGE 3: Content-Disposition 없이도 파일이 응답되는지 확인
    """
    headers = response.get("headers", {}) or {}
    extra = response.get("extra", {}) or {}

    scan_url = response.get("url", "unknown")
    payload = extra.get("payload", "")
    stage = extra.get("stage", 0)
    is_same_file = extra.get("is_same_file", False)  # ✅ STAGE 2~3에도 사용 가능

    evidence = None
    success = False

    disp = headers.get("Content-Disposition", "").lower()

    if stage == 1:
        if is_same_file:
            success = True
            evidence = f"1단계: 경로 조작 '{payload}' 사용 시 동일 파일 다운로드됨. 취약점 가능성 ⬆️"
        else:
            evidence = (
                f"1단계: 경로 조작 '{payload}' 사용 시 다른 응답 반환됨 (파일 다름)"
            )

    elif stage == 2:
        if is_same_file:
            success = True
            evidence = f"2단계: 상위 경로 우회('{payload}') 시 동일 파일 다운로드됨 → 취약점 가능성 ⬆️"
        else:
            # 동일하지 않지만 다운로드는 되었음 (즉, 상위 디렉터리 접근된 것일 수 있음)
            body = response.get("body", b"")
            if isinstance(body, str):
                body = body.encode("utf-8", errors="replace")

            if body and len(body) > 0:
                success = True
                evidence = f"2단계: 상위 디렉터리로 접근하여 다른 파일 다운로드됨 → 취약점 가능성 ⬆️"
            else:
                evidence = f"2단계: 다운로드 실패 또는 응답 없음 → 취약 가능성 ⬇️"

    elif stage == 3:
        body = response.get("body", b"")
        if isinstance(body, str):
            body = body.encode("utf-8", errors="replace")
        if "attachment" in disp:
            success = True
            evidence = f"3단계: Content-Disposition 포함된 응답 수신"
        elif len(body) > 0:
            success = True
            evidence = f"3단계: Content-Disposition 없이도 다운로드 응답 수신됨"

    if "attachment" not in disp:
        print(f"[WARN] Content-Disposition 없음 → stage {stage}, url: {scan_url}")

    return {
        "scan_url": scan_url,
        "payload": payload,
        "evidence": evidence,
        "success": success,
    }
