# src/scanners/file_download.py
# pylint: disable=invalid-name, arguments-differ, arguments-renamed
"""
FileDownloadScanner: 파일 다운로드 취약점 탐지 스캐너

- Content-Disposition: attachment 확인
- 경로 우회(payload)를 통한 파일 다운로드 시도
- 분석 결과 취약 증거가 존재할 경우 기록
"""

# 1. 표준 라이브러리
from datetime import datetime
import hashlib
import json
import copy
import os
import time
import traceback
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
from scanners.base import BaseScanner


def remove_nul(text: Any) -> Any:
    if isinstance(text, str):
        return text.replace("\x00", "")
    if isinstance(text, bytes):
        return text.replace(b"\x00", b"")
    return text


def _body_hash(data: Optional[bytes]) -> str:
    if data is None:
        return ""
    return hashlib.md5(data).hexdigest()


class FileDownloadScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.base_dir = os.path.dirname(__file__)
        self.request_id: int = -1

    @property
    def vulnerability_name(self) -> str:
        return "File Download"

    def is_target(self, _request_id: int, request: RequestData) -> bool:
        query_params = request.get("query_params") or []
        target_keys = {"filename", "file", "filepath", "download", "host"}
        return any(
            param.get("key", "").lower() in target_keys for param in query_params
        )

    def generate_fuzzing_requests(
        self, request: RequestData, stage: int
    ) -> Iterable[RequestData]:
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

            print(f"[GEN] STAGE {stage} → payload: {payload}, path: {new_path}")
            yield mutated

    def _build_mutated_params(
        self, query_params: List[QueryParam], target_keys: set[str], payload: str
    ) -> List[QueryParam]:
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
        self.request_id = request_id
        print(f"[{self.vulnerability_name}]\n요청 ID: {request_id}")

        try:
            normal_response = send_fuzz_request(request)
            print(f"[DEBUG] 정상 응답 상태코드: {normal_response.get('status_code')}")
            print(f"[DEBUG] 정상 응답 바디 타입: {type(normal_response.get('body'))}")
            print(f"[DEBUG] 정상 응답 바디 내용: {normal_response.get('body')}")
        except Exception as e:
            print(f"[ERROR] 정상 요청 실패: {e}")
            return []

        headers = normal_response.get("headers", {}) or {}
        content_disp = headers.get("Content-Disposition", "").lower()

        if "attachment" not in content_disp:
            print("[SKIPPED] Content-Disposition 없음 → 퍼징 생략\n")
            return []

        if not self.is_target(request_id, request):
            print("[SKIPPED] is_target 조건 불충족")
            return []

        print("[OK] Content-Disposition 있음 → 퍼징 진행")

        normal_body = normal_response.get("body", b"")
        if isinstance(normal_body, str):
            normal_body = normal_body.encode("utf-8", errors="replace")

        print(
            f"[DEBUG] 정상 응답 해시: {_body_hash(normal_body)} / 길이: {len(normal_body)}"
        )

        results = []
        seen = set()

        for stage in [1, 2, 3]:
            print(f"\n=== [STAGE {stage}] 퍼징 시작 ===")
            stage_success, stage_results, seen_pairs = self._run_stage_fuzzing(
                request, stage, normal_body
            )
            results.extend(stage_results)

            # ✅ STAGE 1 실패 → STAGE 2로 진행
            if stage == 1 and not stage_success:
                print(f"[!] STAGE 1에서 유의미한 결과 없음 → 이후 단계 진행")
                continue

            # ✅ STAGE 2에서 성공 → 더 이상 퍼징할 필요 없음 → 종료
            if stage == 2 and stage_success:
                print(f"[+] STAGE 2에서 파일 다운로드 성공 → STAGE 3 생략")
                break

            # STAGE 3은 무조건 끝까지 진행

        return results

    def _run_stage_fuzzing(
        self, request: RequestData, stage: int, normal_body: Optional[bytes] = None
    ) -> Tuple[bool, List[Dict[str, Any]], Set[Tuple[str, str]]]:
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

            # 퍼징 응답 수신 후
            try:
                fuzz_response = send_fuzz_request(fuzz_request)
                print(
                    f"[DEBUG] 퍼징 응답 수신 성공 → status: {fuzz_response.get('status_code')}"
                )
            except (RequestException, Exception) as e:
                print(f"[ERROR] 퍼징 요청 실패 (예외: {type(e).__name__}): {e}")
                continue

            # ⬇️ 비교 코드 시작
            print(f"[DEBUG] 현재 stage 값: {stage}")
            if stage == 1:
                print(f"[DEBUG] STAGE 1 → 비교 로직 진입함")

                fuzz_body = fuzz_response.get("body", b"")

                if not normal_body:
                    print(f"[WARN] 정상 응답 본문이 비어 있음 → 비교 불가")
                if not fuzz_body:
                    print(f"[WARN] 퍼징 응답 본문이 비어 있음 → payload: {payload}")

                if fuzz_body is None:
                    print(
                        f"[WARN] fuzz_response body가 None입니다 → payload: {payload}"
                    )
                    continue

                if isinstance(fuzz_body, str):
                    fuzz_body = fuzz_body.encode("utf-8", errors="replace")

                print(f"[DEBUG] normal_body hash: {_body_hash(normal_body)}")
                print(f"[DEBUG] fuzz_body hash: {_body_hash(fuzz_body)}")

                if not normal_body:
                    print(f"[WARN] 정상 응답 본문이 비어 있음 → 비교 불가")
                if not fuzz_body:
                    print(f"[WARN] fuzz 응답 본문이 비어 있음 → payload: {payload}")

                print(f"[DEBUG] normal_body hash: {_body_hash(normal_body)}")
                print(f"[DEBUG] fuzz_body hash: {_body_hash(fuzz_body)}")

                if _body_hash(fuzz_body) == _body_hash(normal_body):
                    print(f"[MATCH] 동일 응답 바디 (해시 기준) → payload: {payload}")
                    success = True
                else:
                    print(f"[DIFF] 응답 바디 달라짐 → payload: {payload}")

                print(
                    f"[DEBUG] 퍼징 응답 바디 내용 (디코딩): {fuzz_body.decode(errors='replace')}"
                )

            elif stage == 2:
                # Stage 2: 파일 다운로드만 성공하면 취약 가능성 있다고 판단
                fuzz_body = fuzz_response.get("body", b"")

                if fuzz_body and isinstance(fuzz_body, str):
                    fuzz_body = fuzz_body.encode("utf-8", errors="replace")

                if fuzz_body and len(fuzz_body) > 0:
                    fuzz_body_hash = _body_hash(fuzz_body)
                    print(f"[DEBUG] STAGE 2 → 다운로드 응답 해시: {fuzz_body_hash}")
                    success = True

            elif stage == 3:
                # Stage 3: 이중 인코딩 우회 시도 → 다운로드 응답이 있으면 success
                fuzz_body = fuzz_response.get("body", b"")

                if fuzz_body and isinstance(fuzz_body, str):
                    fuzz_body = fuzz_body.encode("utf-8", errors="replace")

                if fuzz_body and len(fuzz_body) > 0:
                    fuzz_body_hash = _body_hash(fuzz_body)
                    print(f"[DEBUG] STAGE 3 → 다운로드 응답 해시: {fuzz_body_hash}")
                    success = True

            result = {}
            try:
                async_result = analyze_file_download_response.apply_async(
                    args=[{
                        **fuzz_response,
                        "extra": fuzz_request.get("extra", {}),
                        "normal_body_hash": _body_hash(normal_body),
                    }]
                )
                result = async_result.get()
                print(f"[DEBUG] Celery 분석 결과 수신 완료 → {result}")


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
        scan_url = str(result.get("scan_url") or "unknown")
        result_payload = str(result.get("payload") or "")
        if (scan_url, result_payload) in seen_pairs:
            print(f"[DUPLICATE] → {scan_url} / {result_payload}")
            return False
        seen_pairs.add((scan_url, result_payload))

        print(f"[RESULT] 분석 결과:\n{json.dumps(result, indent=2, ensure_ascii=False)}")

        req_dict = to_fuzzed_request_dict(
            fuzz_request,
            self.request_id,
            self.vulnerability_name,
            result_payload,
        )
        res_dict = to_fuzzed_response_dict(result)

        fuzzed_request_id = insert_fuzzed_request(req_dict)
        insert_fuzzed_response(res_dict, fuzzed_request_id)

        if result.get("evidence"):
            print(f"[+] 의심 응답 감지됨 → 증거: {result['evidence']}")
            insert_vulnerability_scan_result({
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
            })

        return result.get("success", False)


@celery_app.task(name="tasks.analyze_file_download_response", queue="analyze_response")
def analyze_file_download_response(response: Dict[str, Any]) -> Dict[str, Any]:
    import hashlib

    headers = response.get("headers", {}) or {}
    body = response.get("body", "")
    extra = response.get("extra", {}) or {}

    scan_url = response.get("url", "unknown")
    payload = extra.get("payload", "")
    stage = extra.get("stage", 0)

    # decode body if needed
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            body = str(body)

    disp = headers.get("Content-Disposition", "").lower()

    # 기본 응답 정보
    normal_body_hash = response.get("normal_body_hash", "")
    fuzz_body_hash = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()

    evidence = None
    success = False

    # 분석 로직
    if "attachment" not in disp:
        evidence = "Content-Disposition 없음"
    elif "<html" in body.lower():
        evidence = "응답이 HTML 페이지입니다."
    elif stage == 1:
        if fuzz_body_hash == normal_body_hash:
            evidence = f"1단계: 경로 조작 '{payload}' 사용 시 동일 파일 다운로드됨"
            success = True
        else:
            evidence = f"1단계: 경로 조작 '{payload}' 사용 시 다른 응답 반환됨"
    elif stage > 1:
        evidence = f"{stage}단계: Content-Disposition 포함된 응답 수신"
        success = True

    return {
        "scan_url": scan_url,
        "payload": payload,
        "evidence": evidence,
        "success": success,
    }



def to_fuzzed_request_dict(
    fuzzing_request: RequestData,
    original_request_id: int,
    scanner: str,
    payload: str,
) -> dict:
    """
    변조된 요청 정보를 DB에 저장 가능한 딕셔너리 형태로 변환합니다.

    - 원본 요청 ID, 스캐너 이름, 페이로드, 메타 정보, 헤더, 쿼리, 바디 포함
    """
    meta = fuzzing_request["meta"]
    headers = fuzzing_request.get("headers") or []
    headers_dict = {h["key"]: h["value"] for h in headers}
    return {
        "original_request_id": original_request_id,
        "scanner": scanner,
        "payload": payload,
        "is_http": meta.get("is_http"),
        "http_version": meta.get("http_version"),
        "domain": meta.get("domain"),
        "path": meta.get("path"),
        "method": meta.get("method"),
        "timestamp": meta.get("timestamp"),
        "headers": headers_dict,
        "query": fuzzing_request.get("query_params"),
        "body": fuzzing_request.get("body"),
    }


def to_fuzzed_response_dict(fuzzed_response: dict) -> dict:
    """
    변조된 응답 정보를 DB에 저장 가능한 딕셔너리 형태로 변환합니다.

    - Content-Type, 인코딩, 길이 등 응답 헤더 정보 및 본문 내용을 포함
    - 널 문자 제거 후 body 필드 포함
    """
    headers = fuzzed_response.get("headers", {}) or {}
    content_type = headers.get("Content-Type", "")
    charset = None
    if "charset=" in content_type:
        charset = content_type.split("charset=")[-1].strip()
    return {
        "http_version": fuzzed_response.get("http_version"),
        "status_code": fuzzed_response.get("status_code"),
        "timestamp": fuzzed_response.get("timestamp"),
        "headers": headers,
        "body": {
            "content_type": content_type,
            "charset": charset,
            "content_length": headers.get("Content-Length"),
            "content_encoding": headers.get("Content-Encoding"),
            "body": remove_nul(fuzzed_response.get("body")),
        },
    }
