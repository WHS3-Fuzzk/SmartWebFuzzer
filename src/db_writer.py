"""
DB 삽입 관련 함수 모듈
환경변수에서 DB 연결 정보를 불러와 PostgreSQL에 데이터를 저장함
"""

import json
import psycopg2
from psycopg2.extras import execute_values
from db_config import DB_NAME, USER, PASSWORD, HOST, PORT


def sanitize_body(body_data):
    """
    body 데이터에서 null 문자(0x00)를 치환하여 PostgreSQL 저장 오류를 방지
    #TODO: bytes로 저장하는 방식으로 변경 필요
    """
    if body_data is None:
        return None
    if isinstance(body_data, str):
        return body_data.replace("\x00", "[NULL]")
    return body_data


def insert_filtered_request(request: dict) -> int:
    """
    필터링된 요청 데이터를 DB에 저장하고 생성된 ID 반환
    """
    conn = psycopg2.connect(
        dbname=DB_NAME, user=USER, password=PASSWORD, host=HOST, port=PORT
    )
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO filtered_request 
            (is_http, http_version, domain, path, method, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                request.get("is_http"),
                request.get("http_version"),
                request.get("domain"),
                request.get("path"),
                request.get("method"),
                request.get("timestamp"),
            ),
        )
        result = cur.fetchone()
        if result is None:
            raise ValueError("No ID returned after inserting filtered_request")
        request_id = result[0]

        headers = request.get("headers")
        if headers:
            execute_values(
                cur,
                """
                INSERT INTO filtered_request_headers (request_id, key, value)
                VALUES %s
                """,
                [(request_id, k, v) for k, v in headers.items()],
            )

        query_params = request.get("query")
        if query_params:
            execute_values(
                cur,
                """
                INSERT INTO filtered_query_params (request_id, key, value, source)
                VALUES %s
                """,
                [
                    (
                        request_id,
                        param.get("key"),
                        param.get("value"),
                        param.get("source"),
                    )
                    for param in query_params
                ],
            )

        body = request.get("body")
        if isinstance(body, dict):
            cur.execute(
                """
                INSERT INTO filtered_request_body (
                    request_id, content_type, charset, 
                    content_length, content_encoding, body
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    request_id,
                    body.get("content_type"),
                    body.get("charset"),
                    body.get("content_length"),
                    body.get("content_encoding"),
                    sanitize_body(body.get("body")),
                ),
            )

        conn.commit()
        return request_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()


def insert_filtered_response(response: dict, request_id: int) -> int:
    """
    필터링된 응답 데이터를 DB에 저장하고 생성된 ID 반환

    FIXME:
    ValueError: A string literal cannot contain NUL (0x00) characters.
    응답에 Null 문자가 포함된 상태에서 필터링 없이 DB 저장 시도 시 에러 발생
    """
    conn = psycopg2.connect(
        dbname=DB_NAME, user=USER, password=PASSWORD, host=HOST, port=PORT
    )
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO filtered_response 
            (request_id, http_version, status_code, timestamp)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                request_id,
                response.get("http_version"),
                response.get("status_code"),
                response.get("timestamp"),
            ),
        )
        result = cur.fetchone()
        if result is None:
            raise ValueError("No ID returned after inserting filtered_response")
        response_id = result[0]

        headers = response.get("headers")
        if headers:
            execute_values(
                cur,
                """
                INSERT INTO filtered_response_headers (response_id, key, value)
                VALUES %s
                """,
                [(response_id, k, v) for k, v in headers.items()],
            )

        body = response.get("body")
        if isinstance(body, dict):
            cur.execute(
                """
                INSERT INTO filtered_response_body (
                    response_id, content_type, charset, 
                    content_length, content_encoding, body
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    response_id,
                    body.get("content_type"),
                    body.get("charset"),
                    body.get("content_length"),
                    body.get("content_encoding"),
                    sanitize_body(body.get("body")),
                ),
            )

        conn.commit()
        return response_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()


def insert_fuzzed_request(request: dict) -> int:
    """
    퍼징된 요청 데이터를 DB에 저장하고 생성된 ID 반환
    """
    conn = psycopg2.connect(
        dbname=DB_NAME, user=USER, password=PASSWORD, host=HOST, port=PORT
    )
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO fuzzed_request 
            (original_request_id, scanner, payload, is_http, http_version, 
             domain, path, method, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                request.get("original_request_id"),
                request.get("scanner"),
                request.get("payload"),
                request.get("is_http"),
                request.get("http_version"),
                request.get("domain"),
                request.get("path"),
                request.get("method"),
                request.get("timestamp"),
            ),
        )
        result = cur.fetchone()
        if result is None:
            raise ValueError("No ID returned after inserting fuzzed_request")
        request_id = result[0]

        headers = request.get("headers")
        if headers:
            execute_values(
                cur,
                """
                INSERT INTO fuzzed_request_headers (fuzzed_request_id, key, value)
                VALUES %s
                """,
                [(request_id, k, v) for k, v in headers.items()],
            )

        query_params = request.get("query")
        if query_params:
            execute_values(
                cur,
                """
                INSERT INTO fuzzed_query_params (fuzzed_request_id, key, value, source)
                VALUES %s
                """,
                [
                    (
                        request_id,
                        param.get("key"),
                        param.get("value"),
                        param.get("source"),
                    )
                    for param in query_params
                ],
            )

        body = request.get("body")
        if isinstance(body, dict):
            cur.execute(
                """
                INSERT INTO fuzzed_request_body (
                    fuzzed_request_id, content_type, charset, 
                    content_length, content_encoding, body
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    request_id,
                    body.get("content_type"),
                    body.get("charset"),
                    body.get("content_length"),
                    body.get("content_encoding"),
                    sanitize_body(body.get("body")),
                ),
            )

        conn.commit()
        return request_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()


def insert_fuzzed_response(response: dict, request_id: int) -> int:
    """
    퍼징된 응답 데이터를 DB에 저장하고 생성된 ID 반환
    """
    conn = psycopg2.connect(
        dbname=DB_NAME, user=USER, password=PASSWORD, host=HOST, port=PORT
    )
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO fuzzed_response 
            (fuzzed_request_id, http_version, status_code, timestamp)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                request_id,
                response.get("http_version"),
                response.get("status_code"),
                response.get("timestamp"),
            ),
        )
        result = cur.fetchone()
        if result is None:
            raise ValueError("No ID returned after inserting fuzzed_response")
        response_id = result[0]

        headers = response.get("headers")
        if headers:
            execute_values(
                cur,
                """
                INSERT INTO fuzzed_response_headers (fuzzed_response_id, key, value)
                VALUES %s
                """,
                [(response_id, k, v) for k, v in headers.items()],
            )

        body = response.get("body")
        if isinstance(body, dict):
            cur.execute(
                """
                INSERT INTO fuzzed_response_body (
                    fuzzed_response_id, content_type, charset, 
                    content_length, content_encoding, body
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    response_id,
                    body.get("content_type"),
                    body.get("charset"),
                    body.get("content_length"),
                    body.get("content_encoding"),
                    sanitize_body(body.get("body")),
                ),
            )

        conn.commit()
        return response_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()


def insert_recon(recon: dict) -> int:
    """
    탐지된 서버 정보(Wappalyzer 결과 등)를 recon 테이블에 저장
    """
    conn = psycopg2.connect(
        dbname=DB_NAME, user=USER, password=PASSWORD, host=HOST, port=PORT
    )
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO recon (domain, path, detected_at)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (
                recon.get("domain"),
                recon.get("path"),
                recon.get("detected_at"),
            ),
        )
        result = cur.fetchone()
        if result is None:
            raise ValueError("No ID returned after inserting recon")
        recon_id = result[0]

        software = recon.get("software")
        if software:
            execute_values(
                cur,
                """
                INSERT INTO recon_software (recon_id, category, name, version)
                VALUES %s
                """,
                [
                    (recon_id, s.get("category"), s.get("name"), s.get("version"))
                    for s in software
                ],
            )

        conn.commit()
        return recon_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()


def insert_vulnerability_scan_result(scan_result: dict) -> int:
    """
    취약점 스캔 결과를 vulnerability_scan_results 테이블에 저장하고 생성된 ID 반환

    Args:
        scan_result (dict): 스캔 결과 데이터
            - vulnerability_name (str): 스캔 모듈 이름
            - original_request_id (int): 원본 요청 ID
            - fuzzed_request_id (int): 퍼징된 요청 ID
            - domain (str): 도메인
            - endpoint (str): 엔드포인트
            - method (str): HTTP 메서드
            - payload (str): 페이로드
            - parameter (str): 파라미터
            - extra (dict): 추가 스캔 결과 (JSONB로 저장됨)

    Returns:
        int: 생성된 스캔 결과 ID
    """
    conn = psycopg2.connect(
        dbname=DB_NAME, user=USER, password=PASSWORD, host=HOST, port=PORT
    )
    cur = conn.cursor()
    try:
        # extra 필드를 JSON으로 변환
        extra_data = scan_result.get("extra")
        extra_json = json.dumps(extra_data) if extra_data else None

        cur.execute(
            """
            INSERT INTO vulnerability_scan_results 
            (vulnerability_name, original_request_id, fuzzed_request_id, 
             domain, endpoint, method, payload, parameter, extra)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                scan_result.get("vulnerability_name"),
                scan_result.get("original_request_id"),
                scan_result.get("fuzzed_request_id"),
                scan_result.get("domain"),
                scan_result.get("endpoint"),
                scan_result.get("method"),
                scan_result.get("payload"),
                scan_result.get("parameter"),
                extra_json,
            ),
        )
        result = cur.fetchone()
        if result is None:
            raise ValueError("No ID returned after inserting vulnerability_scan_result")
        scan_result_id = result[0]

        conn.commit()
        return scan_result_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()
