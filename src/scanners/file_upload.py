# pylint: skip-file
"""
File Upload 취약점 스캐너 모듈 (원본 방식 기반 수정)
원본 RequestData를 그대로 활용하되 필요한 부분만 변조
실제 파일 생성 및 업로드 기능 추가
"""

import copy
import uuid
import re
import logging
import time
import os
from datetime import datetime
from typing import Any, Dict, Iterable, List
import requests
from io import BytesIO

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
    """
    scheme, domain 정보를 조합해 base URL을 반환합니다.
    """
    scheme = meta.get("scheme", "http")
    domain = meta.get("domain")
    if not domain:
        return None
    return f"{scheme}://{domain}"


def sanitize_filename(filename: str) -> str:
    """
    파일명에서 특수문자를 제거하여 안전한 파일명을 생성합니다.
    """
    # 특수문자 제거 및 공백을 언더스코어로 치환
    sanitized = re.sub(r'[<>:"/\\|?*\s+]', "_", filename)
    # 연속된 언더스코어를 하나로 치환
    sanitized = re.sub(r"_+", "_", sanitized)
    # 앞뒤 언더스코어 제거
    sanitized = sanitized.strip("_")
    # 파일명이 너무 길면 자르기
    if len(sanitized) > 50:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:40] + ext
    return sanitized if sanitized else "upload_file"


def parse_and_modify_multipart(
    original_body: str, filename: str, file_content: str, content_type: str
) -> str:
    """
    원본 multipart 데이터에서 파일 필드를 찾아 수정합니다.
    개행 문자와 boundary를 정확히 처리하여 올바른 multipart 구조 유지
    """
    if not original_body:
        return original_body

    # boundary 추출
    boundary_match = re.search(r"--+([a-zA-Z0-9]+)", original_body)
    if not boundary_match:
        print("[MULTIPART] ❌ boundary를 찾을 수 없음")
        return original_body

    boundary = boundary_match.group(1)
    full_boundary = f"------{boundary}"

    print(f"[MULTIPART] 🔍 boundary 발견: {boundary}")
    print(f"[MULTIPART] 📄 원본 본문 미리보기:\n{original_body[:200]}...")

    # 정규식으로 각 파트를 추출 (더 정확한 방법)
    # boundary로 분리된 각 파트를 개별적으로 처리
    part_pattern = f"{re.escape(full_boundary)}(.*?)(?={re.escape(full_boundary)}|$)"
    parts = re.findall(part_pattern, original_body, re.DOTALL)

    print(f"[MULTIPART] 📋 발견된 파트 수: {len(parts)}")

    # 수정된 multipart 본문 구성
    modified_lines = []

    file_field_found = False

    for i, part in enumerate(parts):
        part = part.strip()
        if not part or part == "--":
            continue

        print(f"[MULTIPART] 🔍 파트 {i+1} 분석: {part[:50]}...")

        # Content-Disposition 헤더 찾기
        disposition_match = re.search(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"', part, re.I
        )
        if not disposition_match:
            print(f"[MULTIPART] ⚠️ 파트 {i+1}: Content-Disposition을 찾을 수 없음")
            continue

        field_name = disposition_match.group(1)
        print(f"[MULTIPART] 📝 파트 {i+1}: 필드명 = {field_name}")

        # boundary 추가
        modified_lines.append(full_boundary)

        # filename이 있는지 확인 (파일 필드인지)
        filename_match = re.search(r'filename="[^"]*"', part, re.I)

        if filename_match:
            # 파일 필드 발견 - 새로운 파일 필드로 교체
            print(f"[MULTIPART] 🎯 파일 필드 발견: {field_name}")
            file_field_found = True

            modified_lines.append(
                f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'
            )
            modified_lines.append(f"Content-Type: {content_type}")
            modified_lines.append("")  # 빈 줄
            modified_lines.append(file_content)

            print(f"[MULTIPART] ✅ 파일 필드 수정: {filename} ({content_type})")
        else:
            # 일반 필드 - 원본 내용 유지
            print(f"[MULTIPART] 📝 일반 필드 유지: {field_name}")

            # 헤더와 값 부분 분리
            lines = part.split("\n")
            headers = []
            content_started = False
            field_value = ""

            for line in lines:
                line = line.strip()
                if not line and not content_started:
                    # 빈 줄 발견 - 헤더 끝, 내용 시작
                    content_started = True
                    continue
                elif not content_started:
                    # 헤더 부분
                    headers.append(line)
                else:
                    # 내용 부분
                    if field_value:
                        field_value += "\n"
                    field_value += line

            # 헤더 부분 추가
            for header in headers:
                if header:
                    modified_lines.append(header)

            # 빈 줄 추가
            modified_lines.append("")

            # 값 부분 추가
            modified_lines.append(field_value)

    # 파일 필드가 없었다면 기본 파일 필드 추가
    if not file_field_found:
        print("[MULTIPART] ⚠️ 파일 필드가 없음 - 기본 파일 필드 추가")
        modified_lines.append(full_boundary)
        modified_lines.append(
            'Content-Disposition: form-data; name="uploaded"; filename="'
            + filename
            + '"'
        )
        modified_lines.append(f"Content-Type: {content_type}")
        modified_lines.append("")
        modified_lines.append(file_content)

    # 마지막 boundary 추가
    modified_lines.append(f"{full_boundary}--")

    # 줄들을 \r\n으로 연결
    modified_body = "\r\n".join(modified_lines)

    print(f"[MULTIPART] ✅ multipart 수정 완료: {len(modified_body)} bytes")
    print(f"[MULTIPART] 📋 생성된 줄 수: {len(modified_lines)}")
    print(f"[MULTIPART] 🔍 수정된 본문 미리보기:\n{modified_body[:300]}...")

    return modified_body


def generate_payload_cases():
    """
    대표적인 우회 기법을 사용한 페이로드를 생성합니다.
    """
    shell_templates = {
        "php": "<?php echo 'vuln_test_' . date('Y-m-d_H-i-s'); ?>",
        "jsp": '<% out.print("vuln_test_" + new java.util.Date()); %>',
        "asp": '<% Response.Write "vuln_test_" & Now() %>',
        "aspx": '<%@ Page Language="C#" %><% Response.Write("vuln_test_" + DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss")); %>',
    }

    # 기본 파일명 생성용
    base_name = uuid.uuid4().hex[:8]

    for ext, shell in shell_templates.items():
        # Content-Type 매핑
        content_type_map = {
            "php": "application/x-php",
            "jsp": "text/plain",
            "asp": "application/x-asp",
            "aspx": "text/plain",
        }
        content_type = content_type_map.get(ext, "application/octet-stream")

        # 1. 기본 확장자
        yield ext, shell, f"{base_name}.{ext}", content_type

        # 2. 대소문자 변조
        mixed_ext = "".join(
            c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(ext)
        )
        yield ext, shell, f"{base_name}.{mixed_ext}", content_type

        # 3. 이중 확장자
        for safe_ext in ["jpg", "png", "txt"]:
            yield ext, shell, f"{base_name}.{ext}.{safe_ext}", content_type

        # 4. %00 널 바이트 우회
        for safe_ext in ["jpg", "png"]:
            yield ext, shell, f"{base_name}.{ext}%00.{safe_ext}", content_type

        # 5. Content-Type 조작
        yield ext, shell, f"{base_name}.{ext}", "image/jpeg"
        yield ext, shell, f"{base_name}.{ext}", "text/plain"


class FileUploadScanner(BaseScanner):
    """
    파일 업로드 취약점 스캐너 (원본 방식 기반)
    """

    @property
    def vulnerability_name(self) -> str:
        return "file_upload"

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """
        파일업로드 관련 요청 여부 판별
        """
        method = request["meta"]["method"].upper()
        headers = {h["key"].lower(): h["value"] for h in (request.get("headers") or [])}
        content_type = headers.get("content-type", "")
        path = request["meta"].get("path", "").lower()

        is_multipart = method == "POST" and "multipart/form-data" in content_type
        upload_keywords = ["upload", "file", "attach", "media", "document", "image"]
        path_has_upload = any(keyword in path for keyword in upload_keywords)

        upload_param_keys = {
            "filename",
            "file",
            "ext",
            "path",
            "upload_dir",
            "save_path",
            "upload",
            "attach",
        }
        query_keys = {p["key"].lower() for p in request.get("query_params", [])}
        query_has_upload = bool(upload_param_keys & query_keys)

        is_target = is_multipart or (
            method == "POST" and (path_has_upload or query_has_upload)
        )

        if is_target:
            print(f"[{self.vulnerability_name}] ✅ 파일 업로드 대상으로 판별됨")
            print(f"[{self.vulnerability_name}] Method: {method}")
            print(f"[{self.vulnerability_name}] Content-Type: {content_type}")
            print(f"[{self.vulnerability_name}] Path: {path}")

        return is_target

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """
        원본 요청을 기반으로 퍼징 요청 생성 (원본 방식 유지)
        """
        upload_fields = self._get_upload_field_names(request)
        print(f"[{self.vulnerability_name}] 📁 업로드 필드명: {upload_fields}")
        payload_count = 0

        # 원본 본문 가져오기 (SSRF 등 다른 스캐너의 변조가 없는 순수한 원본)
        body = request.get("body", {})
        original_body = body.get("body", "") if body else ""

        print(
            f"[{self.vulnerability_name}] 📄 원본 본문 길이: {len(original_body)} bytes"
        )

        # SSRF 페이로드가 섞인 경우 감지 및 정리
        if "@198.51.100.42" in original_body or "file:///" in original_body:
            print(
                f"[{self.vulnerability_name}] 🔧 SSRF 페이로드 감지 - 원본 복원 중..."
            )
            original_body = self._restore_original_multipart(original_body)
            print(
                f"[{self.vulnerability_name}] ✅ 원본 복원 완료: {len(original_body)} bytes"
            )

        for ext, shell, filename, content_type in generate_payload_cases():
            for field in upload_fields:
                payload_count += 1

                # 기본 요청 복사 (원본 방식)
                fuzzing_request = copy.deepcopy(request)

                # multipart 본문이 있으면 수정
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

                # 변조 정보 기록 (원본 방식 유지)
                fuzzing_request["extra"] = {
                    "fuzzed_param": "file_upload",
                    "payload": filename,
                    "payload_id": payload_count,
                    "shell_type": ext,
                    "shell_content": shell,
                    "field_name": field,
                    "content_type": content_type,
                }

                print(
                    f"[{self.vulnerability_name}] 📁 퍼징 요청 생성: {filename} (Content-Type: {content_type})"
                )
                yield fuzzing_request

    def _restore_original_multipart(self, corrupted_body: str) -> str:
        """
        다른 스캐너에 의해 변조된 multipart 데이터를 원본으로 복원
        """
        if not corrupted_body:
            return corrupted_body

        # boundary 추출
        boundary_match = re.search(r"--+([a-zA-Z0-9]+)", corrupted_body)
        if not boundary_match:
            return corrupted_body

        boundary = boundary_match.group(1)
        full_boundary = f"------{boundary}"

        # 각 파트로 분리
        parts = corrupted_body.split(full_boundary)

        # 새로운 파트들을 저장할 리스트
        restored_parts = []
        restored_parts.append(parts[0])  # 첫 번째 빈 부분

        for i, part in enumerate(parts[1:-1], 1):
            if not part.strip():
                continue

            # Content-Disposition 헤더 찾기
            disposition_match = re.search(
                r'Content-Disposition:\s*form-data;\s*name="([^"]+)"', part, re.I
            )
            if not disposition_match:
                restored_parts.append(part)
                continue

            field_name = disposition_match.group(1)

            # SSRF 페이로드가 주입된 필드들 복원
            if field_name == "MAX_FILE_SIZE":
                # MAX_FILE_SIZE는 항상 100000으로 복원
                restored_part = f'\r\nContent-Disposition: form-data; name="MAX_FILE_SIZE"\r\n\r\n100000'
                restored_parts.append(restored_part)
                print(f"[RESTORE] ✅ MAX_FILE_SIZE 복원: 100000")

            elif field_name == "Upload":
                # Upload 버튼은 항상 Upload로 복원
                restored_part = (
                    f'\r\nContent-Disposition: form-data; name="Upload"\r\n\r\nUpload'
                )
                restored_parts.append(restored_part)
                print(f"[RESTORE] ✅ Upload 버튼 복원: Upload")

            elif "filename=" in part:
                # 파일 필드는 기본 더미 파일로 복원
                restored_part = f'\r\nContent-Disposition: form-data; name="{field_name}"; filename="test.py"\r\n'
                restored_part += f"Content-Type: text/x-python\r\n\r\n"
                restored_part += "dd"  # 기본 더미 내용
                restored_parts.append(restored_part)
                print(f"[RESTORE] ✅ 파일 필드 복원: {field_name}")

            else:
                # 기타 필드는 그대로 유지 (SSRF 페이로드가 없는 경우)
                if "@198.51.100.42" not in part and "file:///" not in part:
                    restored_parts.append(part)
                else:
                    # SSRF 페이로드가 있으면 빈 값으로 복원
                    field_value = ""
                    restored_part = f'\r\nContent-Disposition: form-data; name="{field_name}"\r\n\r\n{field_value}'
                    restored_parts.append(restored_part)
                    print(f"[RESTORE] ✅ 일반 필드 복원: {field_name}")

        # 마지막 종료 부분
        restored_parts.append(parts[-1])

        # 다시 조립
        restored_body = full_boundary.join(restored_parts)

        return restored_body

    def _get_upload_field_names(self, request: RequestData) -> List[str]:
        """
        HTTP 요청 본문에서 업로드 필드명을 추출합니다.
        """
        body = request.get("body", {})
        raw_body = body.get("body", "") if body else ""

        print(f"[{self.vulnerability_name}] 🔍 본문 분석 중... (길이: {len(raw_body)})")

        if not raw_body:
            print(
                f"[{self.vulnerability_name}] ⚠️ 본문이 비어있음 - 기본 필드명 'uploaded' 사용"
            )
            return ["uploaded"]  # DVWA에서는 'uploaded' 필드 사용

        pattern = re.compile(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"\s*;\s*filename="[^"]*"',
            re.I,
        )
        matches = pattern.findall(raw_body)
        print(f"[{self.vulnerability_name}] 🔍 정규식 매칭 결과: {matches}")

        if matches:
            field_names = list(set(matches))
            print(f"[{self.vulnerability_name}] ✅ 추출된 필드명: {field_names}")
            return field_names
        else:
            # 매칭되지 않으면 일반적인 필드명들 시도
            common_fields = ["uploaded", "file", "attachment", "document"]
            print(
                f"[{self.vulnerability_name}] ⚠️ 매칭 실패 - 일반적인 필드명 사용: {common_fields}"
            )
            return common_fields

    def _extract_cookies_from_request(self, request: RequestData) -> dict:
        """
        원본 요청에서 쿠키를 추출합니다.
        """
        cookies = {}
        headers = request.get("headers", [])

        for header in headers:
            if header.get("key", "").lower() == "cookie":
                cookie_value = header.get("value", "")
                print(f"[COOKIE] 🍪 원본 요청에서 쿠키 발견: {cookie_value[:50]}...")

                # 쿠키 파싱: "name1=value1; name2=value2" 형태
                for cookie_pair in cookie_value.split(";"):
                    cookie_pair = cookie_pair.strip()
                    if "=" in cookie_pair:
                        name, value = cookie_pair.split("=", 1)
                        cookies[name.strip()] = value.strip()

                if cookies:
                    cookie_names = list(cookies.keys())
                    print(f"[COOKIE] 📝 파싱된 쿠키: {cookie_names}")
                    print(
                        f"[{self.vulnerability_name}] 🔐 쿠키 사용 ({len(cookies)}개)"
                    )

                break

        return cookies

    def run(self, request_id: int, request: RequestData) -> List[Dict[str, Any]]:
        """
        취약점 스캐너 메인 엔트리포인트
        """
        print(f"\n[{self.vulnerability_name}] 🚀 스캔 시작")
        print(f"[{self.vulnerability_name}] 요청 ID: {request_id}")
        print(
            f"[{self.vulnerability_name}] 시작 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        if not self.is_target(request_id, request):
            print(f"[{self.vulnerability_name}] ❌ 업로드 대상이 아님")
            return []

        # URL 정보 확인
        meta = request.get("meta", {})
        base_url = get_full_base_url(meta)

        if not base_url:
            print(f"[{self.vulnerability_name}] ❌ 기본 URL을 구성할 수 없음")
            return []

        upload_url = f"{base_url}{meta.get('path', '')}"
        print(f"[{self.vulnerability_name}] 🎯 타겟 URL: {upload_url}")

        # 쿠키 추출
        cookies = self._extract_cookies_from_request(request)

        async_results: List[AsyncResult] = []
        real_upload_results = []
        findings = []

        # 퍼징 요청 생성 및 비동기 전송
        print(f"[{self.vulnerability_name}] 📋 퍼징 요청 생성 시작...")
        fuzzing_requests = list(self.generate_fuzzing_requests(request))
        print(
            f"[{self.vulnerability_name}] 📋 총 {len(fuzzing_requests)}개 퍼징 요청 생성됨"
        )

        if len(fuzzing_requests) == 0:
            print(f"[{self.vulnerability_name}] ❌ 생성된 퍼징 요청이 없음")
            return []

        for fuzzing_request in fuzzing_requests:
            extra = fuzzing_request.get("extra", {})
            filename = extra.get("payload", "")
            shell_content = extra.get("shell_content", "vuln_test!")
            field_name = extra.get("field_name", "file")
            content_type = extra.get("content_type")

            # 실제 파일 업로드 수행 (중요: 이 부분이 실제 취약점 확인)
            upload_result = send_real_file_upload(
                upload_url, field_name, filename, shell_content, content_type, cookies
            )

            if upload_result.get("success", False):
                real_upload_results.append(upload_result)
                print(
                    f"[{self.vulnerability_name}] ✅ 실제 업로드 성공: {upload_result.get('uploaded_filename')}"
                )

                # 즉시 취약점으로 간주
                finding = {
                    "evidence": "File upload successful - Vulnerability detected",
                    "status_code": upload_result.get("status_code"),
                    "payload_filename": upload_result.get("uploaded_filename"),
                    "upload_confirmed": True,
                    "content_type": upload_result.get("content_type"),
                    "original_filename": filename,
                }
                findings.append(finding)
            else:
                print(f"[{self.vulnerability_name}] ❌ 실제 업로드 실패: {filename}")

            # Celery 비동기 퍼징 요청도 병행 (원본 방식)
            async_result = chain(
                send_fuzz_request.s(request_data=fuzzing_request),
                analyze_file_upload_response.s(),
            ).apply_async(queue="fuzz_request")

            if async_result is not None:
                async_results.append(async_result)

        # 비동기 응답 수집 및 DB 저장
        pending = list(async_results)
        processed_count = 0
        total_count = len(async_results)

        print(
            f"\n[{self.vulnerability_name}] 📊 총 {total_count}개 비동기 요청 처리 중..."
        )

        while pending:
            print(f"[{self.vulnerability_name}] ⏳ 대기 중인 작업: {len(pending)}개")

            for res in pending[:]:
                if res.ready():
                    try:
                        result = res.get()
                        processed_count += 1

                        print(
                            f"[{self.vulnerability_name}] 📈 진행률: {processed_count}/{total_count}"
                        )

                        # DB 저장 로직
                        if res.parent is not None:
                            fuzzed_request_data: RequestData = res.parent.get().get(
                                "request_data"
                            )
                            fuzzed_response = res.parent.get()

                            payload_info = fuzzed_request_data.get("extra", {})
                            payload = payload_info.get("payload", "")

                            # DB 저장용 데이터 변환
                            fuzzed_request_dict = to_fuzzed_request_dict(
                                fuzzed_request_data,
                                original_request_id=request_id,
                                scanner=self.vulnerability_name,
                                payload=payload,
                            )

                            fuzzed_response_dict = to_fuzzed_response_dict(
                                fuzzed_response
                            )

                            # 퍼징 요청과 응답을 DB에 저장
                            fuzzed_request_id = insert_fuzzed_request(
                                fuzzed_request_dict
                            )
                            insert_fuzzed_response(
                                fuzzed_response_dict, fuzzed_request_id
                            )
                            print(
                                f"[{self.vulnerability_name}] 💾 DB 저장 완료 (ID: {fuzzed_request_id})"
                            )

                            # 취약점 발견 시 처리
                            if result and result != {}:
                                print("=" * 60)
                                print(
                                    f"[{self.vulnerability_name}] 🚨 파일업로드 취약점 발견!"
                                )
                                print(
                                    f"요청 URL: {fuzzed_request_data['meta']['path']}"
                                )
                                print(
                                    f"업로드 파일명: {result.get('payload_filename', '-')}"
                                )
                                print(f"증거: {result.get('evidence', '취약점 발견')}")
                                print(f"상태 코드: {result.get('status_code', 'N/A')}")
                                print("=" * 60)

                                # 취약점 스캔 결과 생성
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
                                    "parameter": payload_info.get(
                                        "fuzzed_param", "file"
                                    ),
                                    "extra": {
                                        "confidence": 0.9,
                                        "details": result.get(
                                            "evidence", "파일 업로드 취약점 발견"
                                        ),
                                        "status_code": result.get("status_code", 200),
                                        "payload_filename": result.get(
                                            "payload_filename", ""
                                        ),
                                        "shell_type": payload_info.get(
                                            "shell_type", ""
                                        ),
                                        "timestamp": datetime.now().isoformat(),
                                        "upload_confirmed": result.get(
                                            "upload_confirmed", False
                                        ),
                                    },
                                }

                                # DB에 취약점 저장
                                vulnerability_result_id = (
                                    insert_vulnerability_scan_result(scan_result)
                                )
                                print(
                                    f"[{self.vulnerability_name}] 💾 취약점 스캔 결과 저장 완료 (ID: {vulnerability_result_id})"
                                )

                                findings.append(result)
                            else:
                                print(
                                    f"[{self.vulnerability_name}] ✅ 완료 - 취약점 없음: {payload}"
                                )

                    except Exception as e:
                        print(f"[{self.vulnerability_name}] ❌ 처리 중 오류: {e}")
                        processed_count += 1

                    pending.remove(res)

            if pending:
                time.sleep(0.5)

        # 실제 업로드 결과를 별도로 DB 저장
        for upload_result in real_upload_results:
            try:
                scan_result = {
                    "vulnerability_name": self.vulnerability_name,
                    "original_request_id": request_id,
                    "fuzzed_request_id": None,
                    "domain": meta.get("domain", ""),
                    "endpoint": meta.get("path", ""),
                    "method": "POST",
                    "payload": upload_result.get("uploaded_filename", ""),
                    "parameter": "file_upload",
                    "extra": {
                        "confidence": 0.95,
                        "details": "실제 파일 업로드 성공 - 취약점 확인",
                        "status_code": upload_result.get("status_code", 200),
                        "payload_filename": upload_result.get("uploaded_filename", ""),
                        "content_type": upload_result.get("content_type", ""),
                        "timestamp": datetime.now().isoformat(),
                        "real_file_uploaded": True,
                        "upload_confirmed": True,
                    },
                }

                vulnerability_result_id = insert_vulnerability_scan_result(scan_result)
                print(
                    f"[{self.vulnerability_name}] 💾 실제 업로드 취약점 저장 완료 (ID: {vulnerability_result_id})"
                )

            except Exception as e:
                print(f"[{self.vulnerability_name}] ❌ 실제 업로드 결과 저장 실패: {e}")

        print(f"\n[{self.vulnerability_name}] 🎉 스캔 완료!")
        print(f"[{self.vulnerability_name}] 📊 총 {len(findings)}개 취약점 발견")
        print(
            f"[{self.vulnerability_name}] 📁 실제 업로드 성공: {len(real_upload_results)}개"
        )
        print(
            f"[{self.vulnerability_name}] ⏰ 종료 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        return findings


def send_real_file_upload(
    url: str,
    field_name: str,
    filename: str,
    shell_content: str,
    content_type: str = None,
    cookies: dict = None,
) -> dict:
    """
    실제 파일 업로드를 requests 라이브러리로 수행합니다.
    다양한 업로드 방식을 시도하여 범용성을 높입니다.
    """
    try:
        # 안전한 파일명 생성
        safe_filename = sanitize_filename(filename)

        # Content-Type 자동 감지 또는 지정된 타입 사용
        if content_type is None:
            content_type_map = {
                "php": "application/x-php",
                "jsp": "text/plain",
                "asp": "application/x-asp",
                "aspx": "text/plain",
                "py": "text/x-python",
                "jpg": "image/jpeg",
                "jpeg": "image/jpeg",
                "png": "image/png",
                "gif": "image/gif",
                "txt": "text/plain",
                "html": "text/html",
                "pdf": "application/pdf",
            }

            file_ext = (
                safe_filename.split(".")[-1].lower() if "." in safe_filename else "txt"
            )
            content_type = content_type_map.get(file_ext, "application/octet-stream")

        print(f"[REAL UPLOAD] 파일 업로드 시도: {safe_filename} -> {url}")
        print(f"[REAL UPLOAD] 파일 크기: {len(shell_content)} bytes")
        print(f"[REAL UPLOAD] Content-Type: {content_type}")

        # 쿠키 정보 출력
        if cookies:
            print(f"[REAL UPLOAD] 🍪 쿠키 사용: {len(cookies)}개")
            for key, value in cookies.items():
                print(
                    f"[REAL UPLOAD] 🔐 쿠키: {key}={value[:20]}..."
                    if len(value) > 20
                    else f"[REAL UPLOAD] 🔐 쿠키: {key}={value}"
                )

        # 여러 업로드 방식을 순차적으로 시도
        upload_attempts = [
            # 1. DVWA 스타일 (많은 오래된 PHP 애플리케이션에서 사용)
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
                "description": "DVWA/Legacy PHP style",
            },
            # 2. 기본 파일 업로드 (가장 일반적)
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
                "description": "Standard file upload",
            },
            # 3. 일반적인 폼 데이터와 함께
            {
                "files": {
                    field_name: (
                        safe_filename,
                        shell_content.encode("utf-8"),
                        content_type,
                    )
                },
                "data": {"submit": "Submit", "upload": "true"},
                "headers": {"Referer": url},
                "description": "Form submission style",
            },
            # 4. WordPress/CMS 스타일
            {
                "files": {
                    field_name: (
                        safe_filename,
                        shell_content.encode("utf-8"),
                        content_type,
                    )
                },
                "data": {"action": "upload", "submit": "Upload File"},
                "headers": {"X-Requested-With": "XMLHttpRequest"},
                "description": "CMS/WordPress style",
            },
            # 5. 일반적인 웹 애플리케이션 스타일
            {
                "files": {
                    "file": (safe_filename, shell_content.encode("utf-8"), content_type)
                },
                "data": {"submit": "1"},
                "headers": {},
                "description": "Generic web app style",
            },
            # 6. Node.js/Express 스타일
            {
                "files": {
                    field_name: (
                        safe_filename,
                        shell_content.encode("utf-8"),
                        content_type,
                    )
                },
                "data": {},
                "headers": {"Content-Type": None},  # multipart/form-data 자동 설정
                "description": "Node.js/Express style",
            },
        ]

        last_response = None
        last_error = None

        for i, attempt in enumerate(upload_attempts, 1):
            try:
                print(f"[REAL UPLOAD] 시도 {i}: {attempt['description']}")

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

                last_response = response

                print(f"[REAL UPLOAD] 응답 코드: {response.status_code}")
                print(f"[REAL UPLOAD] 응답 크기: {len(response.text)} bytes")

                # 성공 판정 (상태 코드가 200대이고 에러 메시지가 없으면 성공으로 간주)
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
                        "denied",
                        "cannot",
                        "unable",
                        "오류",
                        "실패",
                    ]

                    has_error = any(
                        pattern in response_text for pattern in fail_patterns
                    )

                    if not has_error:
                        print(
                            f"[REAL UPLOAD] ✅ 업로드 성공: {safe_filename} (방식: {attempt['description']})"
                        )

                        return {
                            "status_code": response.status_code,
                            "text": response.text,
                            "headers": dict(response.headers),
                            "url": response.url,
                            "uploaded_filename": safe_filename,
                            "original_filename": filename,
                            "file_size": len(shell_content),
                            "content_type": content_type,
                            "upload_method": attempt["description"],
                            "attempt_number": i,
                            "success": True,
                        }
                    else:
                        print(f"[REAL UPLOAD] ⚠️ 시도 {i} 실패: 에러 메시지 감지")
                else:
                    print(f"[REAL UPLOAD] ⚠️ 시도 {i} 실패: HTTP {response.status_code}")

            except Exception as e:
                last_error = str(e)
                print(f"[REAL UPLOAD] ❌ 시도 {i} 오류: {e}")
                continue

        # 모든 시도가 실패한 경우
        print(f"[REAL UPLOAD] ❌ 모든 업로드 방식 실패: {safe_filename}")

        return {
            "status_code": last_response.status_code if last_response else 0,
            "text": last_response.text if last_response else "",
            "headers": dict(last_response.headers) if last_response else {},
            "error": last_error or "All upload methods failed",
            "uploaded_filename": safe_filename,
            "original_filename": filename,
            "total_attempts": len(upload_attempts),
            "success": False,
        }

    except Exception as e:
        print(f"[REAL UPLOAD ERROR] {filename} -> Error: {str(e)}")
        return {
            "error": str(e),
            "uploaded_filename": (
                sanitize_filename(filename) if filename else "upload_file"
            ),
            "original_filename": filename,
            "success": False,
        }


@celery_app.task(name="tasks.analyze_file_upload_response", queue="analyze_response")
def analyze_file_upload_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    파일 업로드 응답을 분석해 취약점 여부 판단
    """
    text = response.get("text", "")
    status = response.get("status_code", 0)
    request_data = response.get("request_data", {})
    payload_info = request_data.get("extra", {})
    filename = payload_info.get("payload", "")

    # 업로드 성공 패턴
    success_patterns = [
        r"upload(ed)?",
        r"success",
        r"완료",
        r"성공",
        r"successfully",
        r"업로드",
        r"저장",
        r"done",
        r"file.*saved",
        r"file.*uploaded",
        r"vuln_test_",
    ]

    # 패턴 매칭
    found = False
    if filename:
        found = any(re.search(pat, text, re.I) for pat in success_patterns if pat)

    # 업로드 성공 판정
    if status == 200 and found:
        return {
            "evidence": "Upload success pattern detected in response",
            "status_code": status,
            "payload_filename": filename,
            "upload_confirmed": True,
        }
    elif status == 200:
        return {
            "evidence": "Potential upload vulnerability - 200 response received",
            "status_code": status,
            "payload_filename": filename,
            "upload_confirmed": False,
        }

    return {}


def to_fuzzed_request_dict(
    fuzzing_request: RequestData,
    original_request_id: int,
    scanner: str,
    payload: str,
) -> dict:
    """RequestData 구조를 DB 저장용 딕셔너리로 변환"""
    meta = fuzzing_request["meta"]
    headers = fuzzing_request.get("headers")

    # headers를 딕셔너리로 변환
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

    # Content-Type에서 charset 추출
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
