"""
File Upload 취약점 스캐너 모듈 (example.py 구조 기반)
BaseScanner/RequestData 템플릿 구조 준수 (SmartWebFuzzer 개발 가이드 예시)
DB 저장 기능 추가 (vulnerability_scan_results 포함)
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
        # 1. 기본 확장자
        yield ext, shell, f"{base_name}.{ext}", None

        # 2. 대소문자 변조
        mixed_ext = "".join(
            c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(ext)
        )
        yield ext, shell, f"{base_name}.{mixed_ext}", None

        # 3. 이중 확장자
        for safe_ext in ["jpg", "png", "txt"]:
            yield ext, shell, f"{base_name}.{ext}.{safe_ext}", None

        # 4. %00 널 바이트 우회
        for safe_ext in ["jpg", "png"]:
            yield ext, shell, f"{base_name}.{ext}%00.{safe_ext}", None

        # 5. Content-Type 조작
        yield ext, shell, f"{base_name}.{ext}", "image/jpeg"
        yield ext, shell, f"{base_name}.{ext}", "text/plain"


class FileUploadScanner(BaseScanner):
    """
    파일 업로드 취약점 스캐너 (example.py 구조 기반)
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

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """
        다양한 페이로드로 변조된 업로드 요청을 생성
        """
        upload_fields = self._get_upload_field_names(request)
        print(f"[{self.vulnerability_name}] 📁 업로드 필드명: {upload_fields}")
        payload_count = 0

        for ext, shell, filename, content_type in generate_payload_cases():
            for field in upload_fields:
                payload_count += 1

                # 기본 요청 복사
                fuzzing_request = copy.deepcopy(request)

                # 변조 정보 기록
                fuzzing_request["extra"] = {
                    "fuzzed_param": "file_upload",
                    "payload": filename,
                    "payload_id": payload_count,
                    "shell_type": ext,
                    "shell_content": shell,
                    "field_name": field,
                    "content_type": content_type,
                }

                print(f"[{self.vulnerability_name}] 📁 퍼징 요청 생성: {filename}")
                yield fuzzing_request

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

        for fuzzing_request in fuzzing_requests:
            extra = fuzzing_request.get("extra", {})
            filename = extra.get("payload", "")
            shell_content = extra.get("shell_content", "vuln_test!")
            field_name = extra.get("field_name", "file")
            content_type = extra.get("content_type")

            # 실제 파일 업로드 수행
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

            # Celery 비동기 퍼징 요청도 병행
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
    """RequestData 구조를 DB 저장용 딕셔너리로 변환 (example.py 참고)"""
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
    """응답 데이터를 DB 저장용 딕셔너리로 변환 (example.py 참고)"""
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
