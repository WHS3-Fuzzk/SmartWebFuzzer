"""
DB 삽입 관련 함수 모듈
환경변수에서 DB 연결 정보를 불러와 PostgreSQL에 데이터를 저장함
"""

import os
import psycopg2
from psycopg2.extras import execute_values

# 환경변수에서 DB 연결 정보 읽기
DB_NAME = os.getenv("POSTGRES_DB")
USER = os.getenv("POSTGRES_USER")
PASSWORD = os.getenv("POSTGRES_PASSWORD")
HOST = os.getenv("POSTGRES_HOST")
PORT = os.getenv("POSTGRES_PORT")


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
                    body.get("body"),
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
                    body.get("body"),
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
                    body.get("body"),
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
                    body.get("body"),
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
