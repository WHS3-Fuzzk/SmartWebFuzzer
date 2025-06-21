# src/scanners/upload.py

import copy
import logging
import uuid
import re
import time
from typing import Any, Dict, Iterable, List
from celery.result import AsyncResult
from celery import chain
from datetime import datetime

from scanners.base import BaseScanner
from fuzzing_scheduler.fuzzing_scheduler import celery_app, send_fuzz_request
from db_writer import insert_fuzzed_request, insert_fuzzed_response
from typedefs import RequestData

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def to_fuzzed_request_dict(
    fuzzing_request: RequestData,
    original_request_id: int,
    scanner: str,
    payload: str,
) -> dict:
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
        "body": fuzzed_response.get("body"),
    }
    return {
        "http_version": fuzzed_response.get("http_version"),
        "status_code": fuzzed_response.get("status_code"),
        "timestamp": fuzzed_response.get("timestamp"),
        "headers": headers,
        "body": body_dict,
    }


@celery_app.task(name="tasks.analyze_upload_response", queue="analyze_response")
def analyze_upload_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    업로드 응답을 분석해 성공으로 추정되면 finding 리턴.
    업로드된 파일의 추정 경로도 regex로 추출 시도.
    """
    text = response.get("text", "")
    status = response.get("status_code", 0)
    if 200 <= status < 300 and not any(
        err in text.lower() for err in ["not uploaded", "fail", "error"]
    ):
        match = re.search(
            r"""(['"])(/(?P<file>[\w\-/\.]+\.(php|jsp|asp|html|aspx))(\?[^'"]*)?)\1""",
            text,
            re.I,
        )
        stored_path = match.group(0) if match else None
        return {
            "evidence": "Upload likely succeeded",
            "status_code": status,
            "stored_path_hint": stored_path,
        }
    return {}


class UploadScanner(BaseScanner):
    """
    파일 업로드 취약점 스캐너 구현 (BaseScanner 상속)
    """

    @property
    def vulnerability_name(self) -> str:
        return "file_upload"

    def is_target(self, request_id: int, request: RequestData) -> bool:
        """
        Robust Content-Type 판별. multipart/form-data 만 허용.
        업로드 관련 키워드 쿼리 존재 시 타겟.
        """
        method = request["meta"]["method"].upper()
        headers = {h["key"].lower(): h["value"] for h in request.get("headers", [])}
        # Robust Content-Type 파싱
        content_type = headers.get("content-type", "").lower().replace(" ", "")
        if method != "POST":
            return False
        if not content_type.startswith("multipart/form-data"):
            return False
        keywords = {"filename", "file", "ext", "path", "upload_dir", "save_path"}
        query_keys = {p["key"].lower() for p in request.get("query_params", [])}
        return bool(keywords & query_keys)

    def generate_fuzzing_requests(self, request: RequestData) -> Iterable[RequestData]:
        """
        다양한 확장자와 경로/확장자 우회 기법을 활용해 변조된 업로드 요청 생성
        """
        shell_templates = {
            "php": "<?php echo 'vuln'; ?>",
            "jsp": "<% out.print('vuln!'); %>",
            "asp": '<% Response.Write "vuln" %>',
        }
        extensions = list(shell_templates.keys())
        tricks = ["{}", "{}.jpg", "{}.", "{}%00.jpg", "GIF89a{}"]
        boundary_base = "----WebKitFormBoundary"
        path_keys = ["path", "upload_dir", "save_path", "filepath", "target_path"]
        ext_keys = ["ext", "extension", "file_ext", "suffix"]

        for ext in extensions:
            for trick in tricks:
                basename = uuid.uuid4().hex[:6]
                payload = shell_templates[ext]
                filename = trick.format(f"{basename}.{ext}")

                boundary = f"{boundary_base}{uuid.uuid4().hex[:16]}"
                multipart_body = (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                    f"Content-Type: application/octet-stream\r\n\r\n"
                    f"{payload}\r\n"
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="submit"\r\n\r\n'
                    f"Upload\r\n"
                    f"--{boundary}--"
                )
                base_req = copy.deepcopy(request)
                headers = {
                    h["key"].lower(): h["value"] for h in base_req.get("headers", [])
                }
                headers["content-type"] = f"multipart/form-data; boundary={boundary}"
                base_req["headers"] = [
                    {"key": k, "value": v} for k, v in headers.items()
                ]
                base_req["body"] = {
                    "content_type": headers["content-type"],
                    "charset": "utf-8",
                    "content_length": len(multipart_body),
                    "content_encoding": "identity",
                    "body": multipart_body,
                }
                base_req["extra"] = {"payload": filename}
                yield base_req
                for path_key in path_keys:
                    mod = copy.deepcopy(base_req)
                    mod.setdefault("query_params", []).append(
                        {
                            "key": path_key,
                            "value": "../../html/uploads",
                            "source": "manual",
                        }
                    )
                    mod["extra"] = {"payload": f"{filename} + path={path_key}"}
                    yield mod
                for ext_key in ext_keys:
                    mod = copy.deepcopy(base_req)
                    mod.setdefault("query_params", []).append(
                        {"key": ext_key, "value": ext, "source": "manual"}
                    )
                    mod["extra"] = {"payload": f"{filename} + ext={ext_key}={ext}"}
                    yield mod

    def run(self, request_id: int, request: RequestData) -> List[Dict[str, Any]]:
        """
        퍼징 요청 생성 → 비동기 전송(chain) → 결과 분석/DB저장 → 취약점 탐지 결과 리턴
        """
        logger.info(f"[file_upload] 퍼징 시작 - 요청 ID: {request_id}")
        if not self.is_target(request_id, request):
            return []
        results: List[Dict[str, Any]] = []
        async_results: List[AsyncResult] = []

        for fuzz_req in self.generate_fuzzing_requests(request):
            async_result = chain(
                send_fuzz_request.s(request_data=fuzz_req) | analyze_upload_response.s()
            ).apply_async()
            if async_result is not None:
                async_results.append((async_result, fuzz_req))

        pending = list(async_results)
        while pending:
            for res, req in pending[:]:
                if res.ready():
                    try:
                        result = res.get()
                        response_data = res.parent.get()
                    except Exception as e:
                        logger.warning(
                            f"[file_upload] 요청 ID {request_id}, 페이로드: {req.get('extra', {}).get('payload', '')}, 오류: {e}"
                        )
                        pending.remove((res, req))
                        continue

                    # 업로드 경로 추정 성공시만 finding append 및 DB 저장
                    if result and result.get("stored_path_hint"):
                        fuzzed_request_dict = to_fuzzed_request_dict(
                            req,
                            original_request_id=request_id,
                            scanner=self.vulnerability_name,
                            payload=req.get("extra", {}).get("payload", ""),
                        )
                        fuzzed_response_dict = to_fuzzed_response_dict(response_data)
                        try:
                            fuzzed_request_id = insert_fuzzed_request(
                                fuzzed_request_dict
                            )
                            insert_fuzzed_response(
                                fuzzed_response_dict, fuzzed_request_id
                            )
                        except TypeError as e:
                            logger.warning(f"[file_upload] DB 저장 오류: {e}")
                        logger.info(
                            f"[file_upload] 취약점 탐지: {req['extra']['payload']}"
                        )
                        logger.info(
                            f"[file_upload] 저장 경로 추정: {result['stored_path_hint']}"
                        )
                        results.append(result)
                    # 탐지 안 되면 패스
                    pending.remove((res, req))
            time.sleep(0.5)
        return results
