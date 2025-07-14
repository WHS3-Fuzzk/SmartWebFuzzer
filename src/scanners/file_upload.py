# pylint: skip-file
"""
file_upload scanner module for detecting file upload vulnerabilities.
This module defines the FileUploadScanner class, which extends BaseScanner.
"""

import copy
import uuid
import re
import logging
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List
import requests

from celery.result import AsyncResult
from celery import chain
from scanners.base import BaseScanner
from typedefs import RequestData
from fuzzing_scheduler.fuzzing_scheduler import celery_app, send_fuzz_request
from db_writer import (
    insert_fuzzed_request,
    insert_fuzzed_response,
    insert_vulnerability_scan_result,
)

logger = logging.getLogger(__name__)


def get_full_base_url(meta: Dict[str, Any]) -> str:
    """scheme, domain 정보를 조합해 base URL을 반환"""
    scheme = meta.get("scheme", "http")
    domain = meta.get("domain")
    if not domain:
        return None
    return f"{scheme}://{domain}"


def sanitize_filename(filename: str) -> str:
    """파일명에서 특수문자를 제거하여 안전한 파일명 생성"""
    sanitized = re.sub(r'[<>:"/\\|?*\s+]', "_", filename)
    sanitized = re.sub(r"_+", "_", sanitized)
    sanitized = sanitized.strip("_")

    if len(sanitized) > 50:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:40] + ext
    return sanitized if sanitized else "upload_file"


def parse_and_modify_multipart(
    original_body: str, filename: str, file_content: str, content_type: str
) -> str:
    """원본 multipart 데이터에서 파일 필드를 찾아 수정"""
    if not original_body:
        return original_body

    boundary_match = re.search(r"--+([a-zA-Z0-9]+)", original_body)
    if not boundary_match:
        return original_body

    boundary = boundary_match.group(1)
    full_boundary = f"------{boundary}"

    part_pattern = f"{re.escape(full_boundary)}(.*?)(?={re.escape(full_boundary)}|$)"
    parts = re.findall(part_pattern, original_body, re.DOTALL)

    modified_lines = []
    file_field_found = False

    for part in parts:
        part = part.strip()
        if not part or part == "--":
            continue

        disposition_match = re.search(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"', part, re.I
        )
        if not disposition_match:
            continue

        field_name = disposition_match.group(1)
        modified_lines.append(full_boundary)

        filename_match = re.search(r'filename="[^"]*"', part, re.I)

        if filename_match:
            # 파일 필드 발견 - 새로운 파일로 교체
            file_field_found = True
            modified_lines.append(
                f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'
            )
            modified_lines.append(f"Content-Type: {content_type}")
            modified_lines.append("")
            modified_lines.append(file_content)
        else:
            # 일반 필드 - 원본 내용 유지
            lines = part.split("\n")
            headers = []
            content_started = False
            field_value = ""

            for line in lines:
                line = line.strip()
                if not line and not content_started:
                    content_started = True
                    continue
                elif not content_started:
                    headers.append(line)
                else:
                    if field_value:
                        field_value += "\n"
                    field_value += line

            for header in headers:
                if header:
                    modified_lines.append(header)
            modified_lines.append("")
            modified_lines.append(field_value)

    # 파일 필드가 없었다면 기본 파일 필드 추가
    if not file_field_found:
        modified_lines.append(full_boundary)
        modified_lines.append(
            f'Content-Disposition: form-data; name="uploaded"; filename="{filename}"'
        )
        modified_lines.append(f"Content-Type: {content_type}")
        modified_lines.append("")
        modified_lines.append(file_content)

    modified_lines.append(f"{full_boundary}--")
    return "\r\n".join(modified_lines)


def generate_payload_cases():
    """파일 업로드 우회 페이로드 생성"""
    shell_templates = {
        "php": "<?php echo 'vuln_test_' . date('Y-m-d_H-i-s'); ?>",
        "jsp": '<% out.print("vuln_test_" + new java.util.Date()); %>',
        "asp": '<% Response.Write "vuln_test_" & Now() %>',
    }

    content_type_map = {
        "php": "application/x-php",
        "jsp": "text/plain",
        "asp": "application/x-asp",
    }

    base_name = uuid.uuid4().hex[:8]

    for ext, shell in shell_templates.items():
        content_type = content_type_map.get(ext, "application/octet-stream")

        # 기본 확장자
        yield ext, shell, f"{base_name}.{ext}", content_type

        # 이중 확장자
        yield ext, shell, f"{base_name}.{ext}.jpg", content_type

        # %00 널 바이트 우회
        yield ext, shell, f"{base_name}.{ext}%00.jpg", content_type

        # Content-Type 조작
        yield ext, shell, f"{base_name}.{ext}", "image/jpeg"


def send_file_upload_request(
    url: str,
    field_name: str,
    filename: str,
    shell_content: str,
    content_type: str = None,
    cookies: dict = None,
) -> dict:
    """실제 파일 업로드를 requests 라이브러리로 수행"""
    try:
        safe_filename = sanitize_filename(filename)

        if content_type is None:
            content_type_map = {
                "php": "application/x-php",
                "jsp": "text/plain",
                "asp": "application/x-asp",
                "jpg": "image/jpeg",
                "png": "image/png",
                "txt": "text/plain",
            }
            file_ext = (
                safe_filename.split(".")[-1].lower() if "." in safe_filename else "txt"
            )
            content_type = content_type_map.get(file_ext, "application/octet-stream")

        # 핵심 업로드 방식들만 유지
        upload_attempts = [
            # 1. DVWA 스타일 (가장 일반적)
            {
                "files": {
                    field_name: (
                        safe_filename,
                        shell_content.encode("utf-8"),
                        content_type,
                    )
                },
                "data": {"MAX_FILE_SIZE": "100000", "Upload": "Upload"},
                "headers": {"Referer": url},
                "description": "DVWA style",
            },
            # 2. 기본 파일 업로드
            {
                "files": {
                    field_name: (
                        safe_filename,
                        shell_content.encode("utf-8"),
                        content_type,
                    )
                },
                "data": {},
                "headers": {},
                "description": "Standard upload",
            },
            # 3. 일반적인 폼 제출
            {
                "files": {
                    field_name: (
                        safe_filename,
                        shell_content.encode("utf-8"),
                        content_type,
                    )
                },
                "data": {"submit": "Submit"},
                "headers": {},
                "description": "Form submission",
            },
            # 4. 일반적인 file 필드명
            {
                "files": {
                    "file": (safe_filename, shell_content.encode("utf-8"), content_type)
                },
                "data": {"submit": "1"},
                "headers": {},
                "description": "Generic file field",
            },
        ]

        for i, attempt in enumerate(upload_attempts, 1):
            try:
                response = requests.post(
                    url,
                    files=attempt["files"],
                    data=attempt["data"],
                    headers=attempt["headers"],
                    cookies=cookies,
                    timeout=15,
                    allow_redirects=True,
                    verify=False,
                )

                if 200 <= response.status_code < 300:
                    response_text = response.text.lower()

                    # 실패 패턴 확인
                    fail_patterns = [
                        "error",
                        "failed",
                        "invalid",
                        "not allowed",
                        "forbidden",
                        "rejected",
                    ]
                    has_error = any(
                        pattern in response_text for pattern in fail_patterns
                    )

                    if not has_error:
                        return {
                            "status_code": response.status_code,
                            "text": response.text,
                            "headers": dict(response.headers),
                            "uploaded_filename": safe_filename,
                            "upload_method": attempt["description"],
                            "success": True,
                        }

            except Exception as e:
                continue

        return {"success": False, "error": "All upload methods failed"}

    except Exception as e:
        return {"success": False, "error": str(e)}


class FileUploadScanner(BaseScanner):
    """파일 업로드 취약점 스캐너"""

    @property
    def vulnerability_name(self) -> str:
        return "file_upload"

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """파일업로드 관련 요청 여부 판별"""
        method = request["meta"]["method"].upper()
        headers = {h["key"].lower(): h["value"] for h in (request.get("headers") or [])}
        content_type = headers.get("content-type", "")
        path = request["meta"].get("path", "").lower()

        is_multipart = method == "POST" and "multipart/form-data" in content_type
        upload_keywords = ["upload", "file", "attach", "media"]
        path_has_upload = any(keyword in path for keyword in upload_keywords)

        is_target = is_multipart or (method == "POST" and path_has_upload)

        if is_target:
            print(f"[{self.vulnerability_name}] ✅ 파일 업로드 대상 확인")

        return is_target

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """원본 요청을 기반으로 퍼징 요청 생성"""
        upload_fields = self._get_upload_field_names(request)

        body = request.get("body", {})
        original_body = body.get("body", "") if body else ""

        payload_count = 0
        for ext, shell, filename, content_type in generate_payload_cases():
            for field in upload_fields:
                payload_count += 1
                fuzzing_request = copy.deepcopy(request)

                # multipart 본문 수정
                if original_body and "multipart/form-data" in str(
                    request.get("headers", [])
                ):
                    modified_body = parse_and_modify_multipart(
                        original_body, filename, shell, content_type
                    )
                    fuzzing_request["body"]["body"] = modified_body

                    # Content-Length 업데이트
                    for header in fuzzing_request.get("headers", []):
                        if header["key"].lower() == "content-length":
                            header["value"] = str(len(modified_body))
                            break

                # 변조 정보 기록
                fuzzing_request["extra"] = {
                    "fuzzed_param": "file_upload",
                    "payload": filename,
                    "shell_type": ext,
                    "shell_content": shell,
                    "field_name": field,
                    "content_type": content_type,
                }

                yield fuzzing_request

    def _get_upload_field_names(self, request: RequestData) -> List[str]:
        """HTTP 요청 본문에서 업로드 필드명을 추출"""
        body = request.get("body", {})
        raw_body = body.get("body", "") if body else ""

        if not raw_body:
            return ["uploaded", "file"]

        pattern = re.compile(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"\s*;\s*filename="[^"]*"',
            re.I,
        )
        matches = pattern.findall(raw_body)

        return list(set(matches)) if matches else ["uploaded", "file"]

    def _extract_cookies_from_request(self, request: RequestData) -> dict:
        """원본 요청에서 쿠키를 추출"""
        cookies = {}
        headers = request.get("headers", [])

        for header in headers:
            if header.get("key", "").lower() == "cookie":
                cookie_value = header.get("value", "")
                for cookie_pair in cookie_value.split(";"):
                    cookie_pair = cookie_pair.strip()
                    if "=" in cookie_pair:
                        name, value = cookie_pair.split("=", 1)
                        cookies[name.strip()] = value.strip()
                break

        return cookies

    def run(self, request_id: int, request: RequestData) -> List[Dict[str, Any]]:
        """취약점 스캐너 메인 엔트리포인트"""
        print(f"\n[{self.vulnerability_name}] 🚀 스캔 시작 (요청 ID: {request_id})")

        if not self.is_target(request_id, request):
            return []

        meta = request.get("meta", {})
        base_url = get_full_base_url(meta)
        if not base_url:
            return []

        async_results: List[AsyncResult] = []
        findings = []

        # 퍼징 요청 생성 및 비동기 전송
        fuzzing_requests = list(self.generate_fuzzing_requests(request))
        print(
            f"[{self.vulnerability_name}] 📋 총 {len(fuzzing_requests)}개 퍼징 요청 생성"
        )

        if not fuzzing_requests:
            return []

        for fuzzing_request in fuzzing_requests:
            async_result = chain(
                send_fuzz_request.s(request_data=fuzzing_request),
                analyze_file_upload_response.s(),
            ).apply_async(queue="fuzz_request")

            if async_result:
                async_results.append(async_result)

        # 비동기 응답 수집 및 처리
        pending = list(async_results)
        processed_count = 0

        while pending:
            for res in pending[:]:
                if res.ready():
                    try:
                        upload_result = res.get()
                        processed_count += 1

                        # DB 저장 로직
                        if res.parent:
                            fuzzed_request_data = res.parent.get().get("request_data")
                            fuzzed_response = res.parent.get()
                            payload_info = fuzzed_request_data.get("extra", {})
                            payload = payload_info.get("payload", "")

                            # DB 저장
                            fuzzed_request_dict = to_fuzzed_request_dict(
                                fuzzed_request_data,
                                request_id,
                                self.vulnerability_name,
                                payload,
                            )
                            fuzzed_response_dict = to_fuzzed_response_dict(
                                fuzzed_response
                            )

                            fuzzed_request_id = insert_fuzzed_request(
                                fuzzed_request_dict
                            )
                            insert_fuzzed_response(
                                fuzzed_response_dict, fuzzed_request_id
                            )

                            # 취약점 발견 시 처리
                            if upload_result and upload_result.get("success"):
                                print(
                                    f"[{self.vulnerability_name}] 🚨 취약점 발견: {upload_result.get('uploaded_filename')}"
                                )

                                scan_result = {
                                    "vulnerability_name": self.vulnerability_name,
                                    "original_request_id": request_id,
                                    "fuzzed_request_id": fuzzed_request_id,
                                    "domain": fuzzed_request_data.get("meta", {}).get(
                                        "domain", ""
                                    ),
                                    "endpoint": fuzzed_request_data.get("meta", {}).get(
                                        "path", ""
                                    ),
                                    "method": fuzzed_request_data.get("meta", {}).get(
                                        "method", ""
                                    ),
                                    "payload": payload,
                                    "parameter": "file_upload",
                                    "extra": {
                                        "confidence": upload_result.get(
                                            "confidence", 0.8
                                        ),
                                        "details": upload_result.get(
                                            "evidence", "파일 업로드 취약점"
                                        ),
                                        "status_code": upload_result.get(
                                            "status_code", 200
                                        ),
                                        "uploaded_filename": upload_result.get(
                                            "uploaded_filename", ""
                                        ),
                                        "shell_type": payload_info.get(
                                            "shell_type", ""
                                        ),
                                        "timestamp": datetime.now().isoformat(),
                                    },
                                }

                                insert_vulnerability_scan_result(scan_result)
                                findings.append(upload_result)

                    except Exception as e:
                        print(f"[{self.vulnerability_name}] ❌ 처리 오류: {e}")
                        processed_count += 1

                    pending.remove(res)

            if pending:
                time.sleep(0.5)

        print(
            f"[{self.vulnerability_name}] 🎉 스캔 완료! {len(findings)}개 취약점 발견"
        )
        return findings


@celery_app.task(name="tasks.analyze_file_upload_response", queue="analyze_response")
def analyze_file_upload_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """파일 업로드 응답을 분석해 취약점 여부 판단"""
    text = response.get("text", "")
    status = response.get("status_code", 0)
    request_data = response.get("request_data", {})
    payload_info = request_data.get("extra", {})
    filename = payload_info.get("payload", "")

    # 성공 패턴
    success_patterns = [
        r"upload(ed)?",
        r"success",
        r"successfully",
        r"완료",
        r"성공",
        r"업로드",
        r"저장",
        r"done",
        r"file.*saved",
        r"vuln_test_",
    ]

    # 실행 확인 패턴
    execution_patterns = [r"vuln_test_\d{4}-\d{2}-\d{2}", r"vuln_test_"]

    # 에러 패턴
    error_patterns = [
        r"error",
        r"failed",
        r"invalid",
        r"not allowed",
        r"forbidden",
        r"rejected",
        r"denied",
        r"cannot",
        r"unable",
        r"오류",
        r"실패",
    ]

    text_lower = text.lower()

    has_error = any(re.search(pat, text_lower, re.I) for pat in error_patterns)
    has_success = any(re.search(pat, text_lower, re.I) for pat in success_patterns)
    execution_confirmed = any(
        re.search(pat, text_lower, re.I) for pat in execution_patterns
    )

    # 취약점 판정
    if status == 200 and not has_error:
        if execution_confirmed:
            evidence = "파일 업로드 및 코드 실행 확인됨"
            confidence = 0.95
        elif has_success:
            evidence = "파일 업로드 성공 패턴 감지됨"
            confidence = 0.8
        else:
            evidence = "파일 업로드 가능성 - 추가 확인 필요"
            confidence = 0.6

        return {
            "success": True,
            "evidence": evidence,
            "status_code": status,
            "uploaded_filename": filename,
            "upload_confirmed": has_success or execution_confirmed,
            "execution_confirmed": execution_confirmed,
            "confidence": confidence,
        }

    return {
        "success": False,
        "evidence": f"업로드 실패 - 상태: {status}",
        "status_code": status,
        "uploaded_filename": filename,
    }


def to_fuzzed_request_dict(
    fuzzing_request: RequestData, original_request_id: int, scanner: str, payload: str
) -> dict:
    """RequestData 구조를 DB 저장용 딕셔너리로 변환"""
    meta = fuzzing_request["meta"]
    headers = fuzzing_request.get("headers")

    headers_dict = {}
    if headers:
        for h in headers:
            headers_dict[h["key"]] = h["value"]

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
        "query": fuzzing_request.get("query_params", []),
        "body": fuzzing_request.get("body"),
    }


def to_fuzzed_response_dict(fuzzed_response: dict) -> dict:
    """응답 데이터를 DB 저장용 딕셔너리로 변환"""
    headers = fuzzed_response.get("headers", {})
    content_type = headers.get("Content-Type", "")

    charset = None
    if "charset=" in content_type.lower():
        charset = content_type.split("charset=")[-1].strip()

    body_dict = {
        "content_type": content_type,
        "charset": charset,
        "content_length": headers.get("Content-Length"),
        "content_encoding": headers.get("Content-Encoding"),
        "body": fuzzed_response.get("text", ""),
    }

    return {
        "http_version": fuzzed_response.get("http_version"),
        "status_code": fuzzed_response.get("status_code"),
        "timestamp": fuzzed_response.get("timestamp"),
        "headers": headers,
        "body": body_dict,
    }
