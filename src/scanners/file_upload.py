"""
File Upload 취약점 스캐너 모듈
"""

import copy
import uuid
import re
import logging
from typing import Any, Dict, Iterable, List
import requests

from celery import chain
from scanners.base import BaseScanner
from fuzzing_scheduler.fuzzing_scheduler import celery_app, send_fuzz_request

logger = logging.getLogger(__name__)


def get_full_base_url(meta: Dict[str, Any]) -> str:
    """요청 메타에서 base url(scheme://domain) 생성"""
    scheme = meta.get("scheme", "http")
    domain = meta.get("domain")
    if not domain:
        return None
    return f"{scheme}://{domain}"


def build_multipart_body(field, filename, shell, boundary):
    """멀티파트 업로드 페이로드 body 생성"""
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"{shell}\r\n"
        f"--{boundary}--"
    )


def build_base_request(base, opts):
    """페이로드 변형용 base request 생성"""
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
    """파일 업로드 확장자 및 우회 트릭 조합 생성 (php, jsp, asp 등)"""
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
    """File Upload 취약점 스캐너 클래스"""

    @property
    def vulnerability_name(self) -> str:
        """취약점 스캐너명 반환"""
        return "file_upload"

    def is_target(self, request_id: int, request: Dict[str, Any]) -> bool:
        """업로드 타겟 요청 여부 판정"""
        method = request["meta"]["method"].upper()
        headers = {h["key"].lower(): h["value"] for h in (request.get("headers") or [])}
        content_type = headers.get("content-type", "")
        path = request["meta"].get("path", "").lower()

        logger.info(
            "[is_target] 요청 분석 - 메서드: %s, Content-Type: %s, 경로: %s",
            method,
            content_type,
            path,
        )

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

        logger.info("[is_target] 판별 결과:")
        logger.info("  - multipart/form-data: %s", is_multipart)
        logger.info("  - 경로 업로드 키워드: %s", path_has_upload)
        logger.info("  - 쿼리 업로드 키워드: %s", query_has_upload)
        logger.info("  - 최종 판정: %s", is_target)
        return is_target

    def _get_upload_field_names(self, request: Dict[str, Any]) -> List[str]:
        """멀티파트 body에서 파일 필드명 추출 (없으면 기본값 'file')"""
        body = request.get("body", {})
        raw_body = body.get("body", "")
        if not raw_body:
            return ["file"]
        pattern = re.compile(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"\s*;\s*filename="[^"]*"',
            re.I,
        )
        matches = pattern.findall(raw_body)
        field_names = list(set(matches)) if matches else ["file"]
        logger.info("[_get_upload_field_names] 추출된 필드명: %s", field_names)
        return field_names

    def _gen_single_payload(self, request, context):
        """단일 우회/페이로드 변형 생성"""
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

    def generate_fuzzing_requests(
        self, request: Dict[str, Any]
    ) -> Iterable[Dict[str, Any]]:
        """업로드 퍼징 요청 생성 (filename, 경로 등 우회 조합)"""
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
                logger.info("[+] Generated fuzzing request with payload: %s", filename)
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
                    logger.info(
                        "[+] Generated fuzzing request with payload: %s",
                        mod_req["extra"]["payload"],
                    )
                    yield mod_req

    def run(self, request_id: int, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """파일 업로드 취약점 스캔 전체 실행"""
        logger.info("[%s] 요청 ID: %d", self.vulnerability_name, request_id)
        if not self.is_target(request_id, request):
            logger.info(">> 스캔 대상 아님")
            return []

        results = []
        total = 0
        for fuzz_request in self.generate_fuzzing_requests(request):
            fuzz_request_dict = fuzz_request.copy()
            logger.info(
                "[+] Fuzzing request: %s", fuzz_request_dict["extra"]["payload"]
            )
            task_chain = chain(
                send_fuzz_request.s(fuzz_request_dict),
                analyze_upload_response_task.s(),
            )
            task_chain.apply_async(queue="fuzz_request")
            total += 1

            results.append(
                {
                    "payload": fuzz_request_dict["extra"]["payload"],
                    "shell_type": fuzz_request_dict["extra"]["shell_type"],
                }
            )

        logger.info("총 %d개 페이로드 체인 전송 완료", total)
        return results


def get_possible_paths(filename):
    """파일명 기준으로 흔한 업로드 경로 조합 반환"""
    return [
        f"/uploads/{filename}",
        f"/upload/{filename}",
        f"/files/{filename}",
        f"/file/{filename}",
        f"/hackable/uploads/{filename}",
    ]


def extract_uploaded_urls(text, filename, existing_paths):
    """응답 본문에서 업로드 URL 후보 추출 및 기존 리스트에 추가"""
    upload_url_matches = re.findall(
        r"(\/[A-Za-z0-9_\-\/\.]*" + re.escape(filename) + r")", text
    )
    for u in upload_url_matches:
        if u not in existing_paths:
            existing_paths.append(u)
    return existing_paths


def find_real_uploaded_url(base_url, possible_paths, filename):
    """GET 요청으로 실제 업로드된 파일 URL 존재 여부 확인"""
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
    """파일 업로드 성공 여부 응답 분석(실제 업로드 성공 여부까지 검증)"""
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
        result = {
            "evidence": "Upload likely succeeded",
            "status_code": status,
            "payload_filename": filename,
            "estimated_file_location": real_url if real_file_found else None,
        }
        url = (
            f"{base_url}{meta.get('path', '')}"
            if base_url and meta.get("path")
            else base_url
        )
        print("=" * 60)
        print("[파일업로드 취약점 발견!]")
        print(f"요청 URL: {url}")
        print(f"업로드 파일명: {filename}")
        print(f"추정 업로드 경로: {real_url if real_file_found else '경로 미확인'}")
        print(f"증거: {result['evidence']}")
        print("=" * 60)
        logger.warning("[analyze_upload_response] 취약점 발견! %s", result)
        return result

    logger.info("[analyze_upload_response] 취약점 미발견, status: %d", status)
    return {}
