"""
File Upload 취약점 스캐너 모듈
BaseScanner/RequestData 템플릿 구조 준수 (SmartWebFuzzer 개발 가이드 예시)
"""

import copy
import uuid
import re
import logging
import time
from typing import Any, Dict, Iterable, List
import requests

from celery.result import AsyncResult
from celery import chain
from scanners.base import BaseScanner
from typedefs import RequestData
from fuzzing_scheduler.fuzzing_scheduler import celery_app, send_fuzz_request

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


def build_multipart_body(field, filename, shell, boundary):
    """
    multipart/form-data 요청 본문을 생성합니다.
    """
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"{shell}\r\n"
        f"--{boundary}--"
    )


def build_base_request(base, opts):
    """
    base request를 복사해 multipart/form-data 요청을 조립합니다.
    """
    base_req = copy.deepcopy(base)
    boundary = opts["boundary"]
    multipart_body = opts["multipart_body"]
    filename = opts["filename"]
    ext = opts["ext"]
    payload_count = opts["payload_count"]

    headers = {h["key"].lower(): h["value"] for h in (base_req.get("headers") or [])}
    headers["content-type"] = f"multipart/form-data; boundary={boundary}"
    base_req["headers"] = [{"key": k, "value": v} for k, v in headers.items()]
    base_req["body"] = {
        "content_type": headers["content-type"],
        "charset": "utf-8",
        "content_length": len(multipart_body),
        "content_encoding": "identity",
        "body": multipart_body,
    }
    base_req["extra"] = {
        "payload": filename,
        "payload_id": payload_count,
        "shell_type": ext,
    }
    return base_req


def generate_payload_cases():
    """
    확장자 우회 및 다양한 페이로드를 생성합니다.
    """
    shell_templates = {
        "php": "<?php echo 'vuln'; ?>",
        "jsp": "<% out.print('vuln!'); %>",
        "asp": '<% Response.Write "vuln" %>',
    }
    tricks = ["{}", "{}.jpg", "{}.", "{}%00.jpg", "GIF89a{}"]
    for ext, shell in shell_templates.items():
        for trick in tricks:
            yield ext, shell, trick


class FileUploadScanner(BaseScanner):
    """
    파일 업로드 취약점 스캐너 예시 (RequestData 사용)
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
        return is_target

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """
        다양한 페이로드로 변조된 업로드 요청을 생성
        """
        upload_fields = self._get_upload_field_names(request)
        path_keys = ["path", "upload_dir", "save_path", "filepath", "target_path"]
        payload_count = 0

        for ext, shell, trick in generate_payload_cases():
            for field in upload_fields:
                payload_count += 1
                context = {
                    "ext": ext,
                    "shell": shell,
                    "trick": trick,
                    "field": field,
                    "path_keys": path_keys,
                    "payload_count": payload_count,
                }
                filename, base_req, pk_list = self._gen_single_payload(request, context)
                print(f"[+] Generated fuzzing request with payload: {filename}")
                yield base_req

                for path_key in pk_list:
                    payload_count += 1
                    mod_req = copy.deepcopy(base_req)
                    mod_req.setdefault("query_params", []).append(
                        {
                            "key": path_key,
                            "value": "../../html/uploads",
                            "source": "fuzzer",
                        }
                    )
                    mod_req["extra"] = {
                        "payload": f"{filename} + {path_key}=../../html/uploads",
                        "payload_id": payload_count,
                        "shell_type": ext,
                    }
                    print(
                        "[+] Generated fuzzing request with payload: "
                        f"{mod_req['extra']['payload']}"
                    )
                    yield mod_req

    def _get_upload_field_names(self, request: RequestData) -> List[str]:
        """
        HTTP 요청 본문에서 업로드 필드명을 추출합니다.
        """
        body = request.get("body", {})
        raw_body = body.get("body", "")
        if not raw_body:
            return ["file"]
        pattern = re.compile(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"\s*;\s*filename="[^"]*"',
            re.I,
        )
        matches = pattern.findall(raw_body)
        return list(set(matches)) if matches else ["file"]

    def _gen_single_payload(self, request, context):
        """
        단일 페이로드 케이스를 생성합니다.
        """
        basename = uuid.uuid4().hex[:6]
        ext = context["ext"]
        shell = context["shell"]
        trick = context["trick"]
        field = context["field"]
        path_keys = context["path_keys"]
        payload_count = context["payload_count"]

        filename = trick.format(f"{basename}.{ext}")
        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
        multipart_body = build_multipart_body(field, filename, shell, boundary)
        opts = {
            "boundary": boundary,
            "multipart_body": multipart_body,
            "filename": filename,
            "ext": ext,
            "payload_count": payload_count,
        }
        base_req = build_base_request(request, opts)
        return filename, base_req, path_keys

    def run(self, request_id: int, request: RequestData) -> List[Dict[str, Any]]:
        """
        취약점 스캐너 메인 엔트리포인트 (Celery 비동기, DB 연동, print 출력 등 예시)
        """
        print(f"[{self.vulnerability_name}] 요청 ID: {request_id}\n")
        if not self.is_target(request_id, request):
            print(">> 업로드 대상이 아님")
            return []

        async_results: List[AsyncResult] = []
        # --- 비동기 퍼징 요청 전송 ---
        for fuzz_request in self.generate_fuzzing_requests(request):
            # DB 저장 가능: insert_fuzzed_request(fuzz_request) 등
            async_result = chain(
                send_fuzz_request.s(fuzz_request),
                analyze_upload_response_task.s(),
            ).apply_async(queue="fuzz_request")
            if async_result is not None:
                async_results.append(async_result)

        # --- 비동기 응답 수집 및 결과 print ---
        pending = list(async_results)
        findings = []
        while pending:
            for res in pending[:]:
                if res.ready():
                    result = res.get()
                    if result:
                        print("=" * 60)
                        print("[파일업로드 취약점 발견!]")
                        print(f"요청 URL: {request['meta']['path']}")
                        print(f"업로드 파일명: {result.get('payload_filename', '-')}")
                        estimate = result.get("estimated_file_location")
                        print(
                            f"추정 업로드 경로: "
                            f"{estimate if estimate else '경로 미확인'}"
                        )
                        print(f"증거: {result.get('evidence')}")
                        print("=" * 60)
                        findings.append(result)
                    else:
                        print("[완료] 취약점 없음")
                    pending.remove(res)
            time.sleep(0.5)
        return findings


def get_possible_paths(filename):
    """
    일반적으로 사용되는 업로드 경로를 리턴합니다.
    """
    return [
        f"/uploads/{filename}",
        f"/upload/{filename}",
        f"/files/{filename}",
        f"/file/{filename}",
        f"/hackable/uploads/{filename}",
    ]


def extract_uploaded_urls(text, filename, existing_paths):
    """
    응답 내에 업로드 파일 URL이 포함되어 있으면 경로 목록에 추가합니다.
    """
    upload_url_matches = re.findall(
        r"(\/[A-Za-z0-9_\-\/\.]*" + re.escape(filename) + r")", text
    )
    for u in upload_url_matches:
        if u not in existing_paths:
            existing_paths.append(u)
    return existing_paths


def find_real_uploaded_url(base_url, possible_paths, filename):
    """
    추정 업로드 경로를 직접 접근하여 파일 업로드 성공 여부를 확인합니다.
    """
    for path in possible_paths:
        url = f"{base_url}{path}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200 and (
                filename in r.text
                or r.headers.get("Content-Type", "").startswith("image")
                or len(r.content) > 10
            ):
                return True, url
        except requests.RequestException:
            continue
    return False, ""


@celery_app.task(name="tasks.analyze_upload_response", queue="analyze_response")
def analyze_upload_response_task(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    파일 업로드 성공 판정 및 분석 결과 반환 (추정 경로 포함)
    """
    text = response.get("text", "")
    status = response.get("status_code", 0)
    request_data = response.get("request_data", {})
    payload_info = request_data.get("extra", {})
    filename = payload_info.get("payload")
    meta = request_data.get("meta", {})

    patterns = [
        r"upload(ed)?",
        r"success",
        r"완료",
        r"성공",
        r"succesfully",
        r"업로드",
        r"저장",
        r"done",
        r"<img[^>]+src=[\"'][^\"'>]*" + re.escape(filename),
        re.escape(filename),
        r"/uploads?/" + re.escape(filename),
        r"/files?/" + re.escape(filename),
        r"/hackable/uploads/" + re.escape(filename),
    ]
    found = any(re.search(pat, text, re.I) for pat in patterns)
    possible_paths = get_possible_paths(filename)
    possible_paths = extract_uploaded_urls(text, filename, possible_paths)
    base_url = get_full_base_url(meta)
    real_file_found, real_url = find_real_uploaded_url(
        base_url, possible_paths, filename
    )

    if status == 200 and (found or real_file_found):
        return {
            "evidence": "Upload likely succeeded",
            "status_code": status,
            "payload_filename": filename,
            "estimated_file_location": real_url if real_file_found else None,
        }
    return {}
