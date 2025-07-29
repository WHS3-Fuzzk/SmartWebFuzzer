# pylint: skip-file
"""
FileUploadScanner: 파일 업로드 취약점 탐지 스캐너

- multipart/form-data 요청을 분석하여 파일 업로드 취약점 탐지
- 파일 업로드 필드에 대해 다양한 페이로드로 퍼징
- 퍼징 요청을 Celery를 통해 비동기적으로 전송
- 응답 상태 코드와 에러 패턴을 분석하여 취약점 여부 판단
"""

import copy
from typing import Any, Dict, Iterable, List
import re
import time
from celery import chain
from scanners.base import BaseScanner
from scanners.utils import to_fuzzed_response_dict
from typedefs import RequestData
from fuzzing_scheduler.fuzzing_scheduler import celery_app, send_fuzz_request
from db_writer import (
    insert_fuzzed_request,
    insert_fuzzed_response,
    insert_vulnerability_scan_result,
)


@celery_app.task(name="tasks.analyze_file_upload_response", queue="analyze_response")
def analyze_file_upload_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """파일 업로드 응답을 분석해 취약점 여부 판단"""
    status = response.get("status_code", 0)
    text = response.get("text", "")
    request_data = response.get("request_data", {})
    payload_info = request_data.get("extra", {})
    filename = payload_info.get("payload", "")
    file_extension = payload_info.get("file_extension", "")
    fuzzed_request_id = request_data.get("fuzzed_request_id")

    # 퍼징 응답을 DB에 저장
    # utils.py의 to_fuzzed_response_dict 함수를 사용하여 응답 데이터 변환
    fuzzed_response_data = to_fuzzed_response_dict(response, remove_null=True)

    # 퍼징 응답을 DB에 저장
    insert_fuzzed_response(fuzzed_response_data, fuzzed_request_id)

    # 에러 패턴 확인 (200이어도 실제로는 실패일 수 있음)
    error_patterns = [
        r"(?<!\.)error(?!\s*\{|\s*:)",  # .error 클래스나 error: 속성 제외
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
        r"업로드.*실패",
        r"파일.*거부",
    ]

    text_lower = text.lower()
    has_error = any(re.search(pat, text_lower, re.I) for pat in error_patterns)

    # 응답 코드와 에러 패턴을 모두 고려한 판단
    if status == 200 and not has_error:
        return {
            "success": True,
            "evidence": f"파일 업로드 성공 - 상태 코드: {status}",
            "status_code": status,
            "uploaded_filename": filename,
            "detected_language": file_extension,
            "confidence": 0.8,
            "fuzzed_request_id": fuzzed_request_id,
        }
    else:
        error_reason = f"업로드 실패 - 상태 코드: {status}"
        if has_error:
            error_reason += " (에러 패턴 감지됨)"

        return {
            "success": False,
            "evidence": error_reason,
            "status_code": status,
            "uploaded_filename": filename,
            "fuzzed_request_id": fuzzed_request_id,
        }


class FileUploadScanner(BaseScanner):
    """파일 업로드 취약점 스캐너"""

    @property
    def vulnerability_name(self) -> str:
        return "File_Upload"

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """파일업로드 관련 요청 여부 판별 (RFC 2046 표준 준수)"""
        method = request["meta"]["method"].upper()
        headers = {h["key"].lower(): h["value"] for h in (request.get("headers") or [])}
        content_type = headers.get("content-type", "")

        # RFC 2046: multipart/form-data 확인
        is_multipart = method == "POST" and "multipart/form-data" in content_type

        return is_multipart

    def _update_content_length_header(
        self, fuzzing_request: RequestData, modified_body: str
    ) -> None:
        """헤더의 Content-Length를 수정된 본문 길이에 맞게 업데이트"""
        headers = fuzzing_request.get("headers", [])

        # Content-Length 헤더 찾기
        content_length_updated = False
        for header in headers:
            if header["key"].lower() == "content-length":
                header["value"] = str(len(modified_body))
                content_length_updated = True

                break

        # Content-Length 헤더가 없으면 추가
        if not content_length_updated:
            headers.append({"key": "Content-Length", "value": str(len(modified_body))})

    def _extract_file_content_type_from_multipart(self, request: RequestData) -> str:
        """multipart/form-data에서 파일 필드의 Content-Type 추출"""
        body = request.get("body", {})
        raw_body = body.get("body", "") if body else ""

        if not raw_body:
            return ""

        # filename이 있는 부분의 Content-Type 찾기 (권장 정규식)
        pattern = r'filename="[^"]*".*?Content-Type:\s*([^\r\n]+)'
        matches = re.findall(pattern, raw_body, re.I | re.DOTALL)

        if matches:

            return matches[0].strip()

        return ""

    def _modify_multipart_file_content(
        self,
        original_body: str,
        filename: str,
        content: str,
        content_type: str,
        target_field_name: str = None,
    ) -> str:
        """multipart 본문에서 특정 파일 업로드 부분만 수정"""
        if not original_body:
            return original_body

        # boundary 추출 (WebKitFormBoundary 패턴 우선)
        boundary_match = re.search(
            r"------(WebKitFormBoundary[a-zA-Z0-9_-]+)", original_body
        )

        full_boundary = boundary_match.group(0)  # 전체 매칭된 boundary

        # boundary 기준으로 본문 분할 (정확한 boundary 패턴 사용)
        boundary_pattern = full_boundary + r"\r\n"
        parts = re.split(boundary_pattern, original_body)

        # 첫 번째 빈 part 제거
        if parts and parts[0].strip() == "":
            parts = parts[1:]

        modified_parts = []

        for part in parts:

            # 종료 boundary가 포함된 part 처리
            if part.endswith(f"{full_boundary}--\r\n"):
                # 종료 boundary 제거
                part = part[: -len(f"{full_boundary}--\r\n")]
                part = part.strip()
                if not part:
                    continue
            else:
                part = part.strip()
                if not part:
                    continue

            # 파일 업로드 부분인지 확인 (filename이 있는지)

            if 'filename="' in part:
                # 필드명 추출
                field_match = re.search(r'name="([^"]+)"', part)
                if field_match:
                    field_name = field_match.group(1)

                    # 특정 필드명이 지정되었고, 일치하지 않으면 수정하지 않음
                    if target_field_name and field_name != target_field_name:
                        modified_parts.append(part)
                        continue

                    # 파일 업로드 부분 수정
                    lines = part.split("\n")
                    modified_lines = []

                    for line in lines:
                        line = line.strip()
                        if (
                            line.startswith("Content-Disposition:")
                            and 'filename="' in line
                        ):
                            # filename 수정
                            modified_line = re.sub(
                                r'filename="[^"]*"', f'filename="{filename}"', line
                            )
                            modified_lines.append(modified_line)
                        elif line.startswith("Content-Type:"):
                            # Content-Type 수정
                            modified_lines.append(f"Content-Type: {content_type}")
                        elif line == "":
                            # 빈 줄 다음에 파일 내용 추가
                            modified_lines.append("")
                            modified_lines.append(content)
                            break
                        else:
                            modified_lines.append(line)

                    modified_parts.append("\n".join(modified_lines))
                else:
                    modified_parts.append(part)
            else:
                # 파일 업로드가 아닌 부분은 그대로 유지
                modified_parts.append(part)

                # 수정된 본문 재조합 (HTTP multipart 표준 준수)
        if not modified_parts:
            return original_body

        # 첫 번째 part 앞에 boundary 추가 (표준 준수)
        result = f"{full_boundary}\r\n{modified_parts[0]}"

        # 나머지 part들은 \r\n------boundary\r\n으로 시작
        for part in modified_parts[1:]:
            # 일반 part
            result += f"\r\n{full_boundary}\r\n{part}"

        # 마지막에 종료 boundary 추가
        result += f"\r\n{full_boundary}--\r\n"

        # Content-Length 업데이트 (RFC 7230 표준 준수)
        result = re.sub(
            r"Content-Length:\s*\d+", f"Content-Length: {len(result)}", result
        )

        return result

    def _get_file_upload_fields(self, request: RequestData) -> List[str]:
        """multipart 본문에서 모든 파일 업로드 필드명 추출"""
        body = request.get("body", {})
        raw_body = body.get("body", "") if body else ""

        if not raw_body:

            return []

        # filename이 있는 모든 필드명 추출 (권장 정규식)
        pattern = (
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)";\s*filename="[^"]*"'
        )
        matches = re.findall(pattern, raw_body, re.I)

        # # 백업 패턴 (표준을 벗어나는 형식에 대한 호환성)
        # if not matches:
        #     backup_pattern = r'name="([^"]+)"[^"]*filename="[^"]*"'
        #     matches = re.findall(backup_pattern, raw_body, re.I)

        unique_fields = list(set(matches))

        return unique_fields

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """원본 요청을 기반으로 퍼징 요청 생성"""
        # 고유 문자열 생성
        timestamp = int(time.time())
        unique_string = f"fuzzk_upload_{timestamp}"

        # 언어별 응답 템플릿
        response_templates = {
            "php": {
                "code": f"<?php echo '{unique_string}'; ?>",
                "content_type": "application/x-php",
            },
            "jsp": {
                "code": f'<% out.print("{unique_string}"); %>',
                "content_type": "application/x-jsp",
            },
            "asp": {
                "code": f'<% Response.Write "{unique_string}" %>',
                "content_type": "application/x-asp",
            },
            "aspx": {
                "code": f'<% Response.Write("{unique_string}"); %>',
                "content_type": "application/x-aspx",
            },
        }

        # 원본 요청 본문
        body = request.get("body", {})
        original_body = body.get("body", "") if body else ""

        # 모든 파일 업로드 필드명 추출
        file_upload_fields = self._get_file_upload_fields(request)

        # multipart에서 파일 필드의 content_type 추출
        original_file_content_type = self._extract_file_content_type_from_multipart(
            request
        )

        payload_count = 0

        for ext, template in response_templates.items():
            code = template["code"]
            template_content_type = template["content_type"]

            # 기본 파일명
            filename = f"fuzzk.{ext}"

            # content_type 옵션들
            content_types = [
                template_content_type,  # 확장자에 맞는 content_type
            ]

            # 원본 파일 content_type이 있으면 추가
            if original_file_content_type:
                content_types.append(original_file_content_type)

            for field_name in file_upload_fields:
                for content_type in content_types:
                    payload_count += 1
                    fuzzing_request = copy.deepcopy(request)

                    # multipart 본문 수정 (특정 필드만)
                    if original_body:
                        modified_body = self._modify_multipart_file_content(
                            original_body, filename, code, content_type, field_name
                        )
                        fuzzing_request["body"]["body"] = modified_body

                        # 헤더의 Content-Length 업데이트
                        self._update_content_length_header(
                            fuzzing_request, modified_body
                        )

                    # 변조 정보 기록
                    fuzzing_request["extra"] = {
                        "fuzzed_param": "file_upload",
                        "payload": filename,
                        "file_extension": ext,
                        "shell_content": code,
                        "field_name": field_name,  # 실제 필드명 사용
                        "content_type": content_type,
                    }

                    yield fuzzing_request

    def run(self, request_id: int, request: RequestData) -> List[Dict[str, Any]]:
        """취약점 스캐너 메인 엔트리포인트"""

        if not self.is_target(request_id, request):
            return []
        print(f"[{self.vulnerability_name}] 퍼징 시작")
        # 퍼징 요청 생성
        fuzzing_requests = list(self.generate_fuzzing_requests(request))

        # 퍼징 요청 DB 저장 및 Celery chain 생성
        async_results = []

        for fuzzing_request in fuzzing_requests:

            # 퍼징 요청을 DB에 저장
            fuzzed_request_data = {
                "original_request_id": request_id,
                "scanner": self.vulnerability_name,
                "payload": fuzzing_request.get("extra", {}).get("payload", ""),
                "is_http": fuzzing_request["meta"]["is_http"],
                "http_version": fuzzing_request["meta"].get("http_version", ""),
                "domain": fuzzing_request["meta"]["domain"],
                "path": fuzzing_request["meta"]["path"],
                "method": fuzzing_request["meta"]["method"],
                "timestamp": fuzzing_request["meta"].get("timestamp"),
                "headers": {
                    h["key"]: h["value"] for h in (fuzzing_request.get("headers") or [])
                },
                "query": fuzzing_request.get("query_params", []),
                "body": fuzzing_request.get("body", {}),
            }

            fuzzed_request_id = insert_fuzzed_request(fuzzed_request_data)

            # fuzzing_request에 fuzzed_request_id 추가
            fuzzing_request["fuzzed_request_id"] = fuzzed_request_id

            # send_fuzz_request -> analyze_file_upload_response chain 생성
            async_result = chain(
                send_fuzz_request.s(request_data=fuzzing_request),
                analyze_file_upload_response.s(),
            ).apply_async(queue="fuzz_request")

            if async_result:
                async_results.append(async_result)

        # 비동기 결과 수집 및 처리 (ready() 확인 후 순회)
        check_interval = 1  # 확인 간격 (초)

        while True:
            completed_count = 0

            for async_result in async_results:
                if async_result.ready():

                    # 완료된 작업의 결과 가져오기
                    analysis_result = async_result.get()

                    if analysis_result and analysis_result.get("success"):
                        # 취약점 발견 시 DB에 저장
                        # fuzzing_request 정보를 가져오기 위해 async_result.parent 사용
                        fuzzing_request = None
                        if hasattr(async_result, "parent") and async_result.parent:

                            fuzz_response = async_result.parent.get()
                            fuzzing_request = fuzz_response.get("request_data", {})

                        scan_result = {
                            "vulnerability_name": self.vulnerability_name,
                            "original_request_id": request_id,
                            "fuzzed_request_id": analysis_result.get(
                                "fuzzed_request_id"
                            ),
                            "domain": request["meta"]["domain"],
                            "endpoint": request["meta"]["path"],
                            "method": request["meta"]["method"],
                            "payload": analysis_result.get("uploaded_filename", ""),
                            "parameter": (
                                fuzzing_request.get("extra", {}).get(
                                    "field_name", "none"
                                )
                                if fuzzing_request
                                else "none"
                            ),
                            "extra": {
                                "evidence": analysis_result.get("evidence", ""),
                                "confidence": analysis_result.get("confidence", 0.8),
                                "status_code": analysis_result.get("status_code", 0),
                                "detected_language": analysis_result.get(
                                    "detected_language", ""
                                ),
                            },
                        }

                        insert_vulnerability_scan_result(scan_result)

                    completed_count += 1

            # 모든 작업이 완료되었는지 확인
            if completed_count == len(async_results):
                break

            # 대기 후 다시 확인
            time.sleep(check_interval)

        return []
