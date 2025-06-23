"""db_reader.py"""

import contextlib
from typing import Any, Dict, List
import psycopg2.extras as _E
import psycopg2.pool
from db_config import DB_NAME, USER, PASSWORD, HOST, PORT
from typedefs import RequestData


# 다음 3개의 메타 데이터들의 id를 기준으로 read를 진행한다.
class DBReader:
    """filtered_request, fuzzed_request,  recon 이 셋의 id를 기준으로 read를 진행.
    각 id는 DB Write 수행 시, 반환 된 것을 이용한다."""

    def __init__(self):
        dsn = (
            f"dbname={DB_NAME} user={USER} password={PASSWORD} "
            f"host={HOST} port={PORT}"
        )
        self.pool = psycopg2.pool.SimpleConnectionPool(
            1, 10, dsn, cursor_factory=_E.RealDictCursor
        )

    @contextlib.contextmanager
    def _cur(self):
        conn = self.pool.getconn()
        try:
            with conn.cursor() as c:
                yield c
            conn.commit()
        finally:
            self.pool.putconn(conn)

    def select_filtered_request(self, request_id: int) -> RequestData:
        """filtered_request_id
        -> filtered_request, filtered_headers, filtered_query_params, filtered_requests_body 읽기
        """
        with self._cur() as c:
            # request
            c.execute("SELECT * FROM filtered_request WHERE id=%s", (request_id,))
            meta = c.fetchone()
            if not meta:
                raise KeyError(f"filtered_request {request_id} not found")

            # headers
            c.execute(
                "SELECT key, value FROM filtered_request_headers WHERE request_id=%s ORDER BY id",
                (request_id,),
            )
            headers = c.fetchall()

            # query params
            c.execute(
                "SELECT key, value, source "
                "FROM filtered_query_params WHERE request_id=%s ORDER BY id",
                (request_id,),
            )
            params = c.fetchall()

            # body
            c.execute(
                "SELECT * FROM filtered_request_body WHERE request_id=%s", (request_id,)
            )
            body = c.fetchone()

        return {"meta": meta, "headers": headers, "query_params": params, "body": body}

    def select_fuzzed_request(self, request_id: int) -> Dict[str, Any]:
        """fuzzed_request_id
        -> fuzzed_request, fuzzed_headers, fuzzed_query_params, fuzzed_requests_body 읽기
        """
        with self._cur() as c:
            c.execute("SELECT * FROM fuzzed_request WHERE id=%s", (request_id,))
            meta = c.fetchone()
            if not meta:
                raise KeyError(f"fuzzed_request {request_id} not found")

            c.execute(
                "SELECT key, value "
                "FROM fuzzed_request_headers WHERE fuzzed_request_id=%s ORDER BY id",
                (request_id,),
            )
            headers = c.fetchall()

            c.execute(
                "SELECT key, value, source "
                "FROM fuzzed_query_params WHERE fuzzed_request_id=%s ORDER BY id",
                (request_id,),
            )
            params = c.fetchall()

            c.execute(
                "SELECT * FROM fuzzed_request_body WHERE fuzzed_request_id=%s",
                (request_id,),
            )
            body = c.fetchone()

        return {"meta": meta, "headers": headers, "query_params": params, "body": body}

    def select_filtered_response(self, request_id: int) -> Dict[str, Any]:
        """filtered_request_id
        -> filtered_response, filtered_response_headers, filtered_response_body 읽기
        """
        with self._cur() as c:
            c.execute(
                "SELECT * FROM filtered_response WHERE request_id=%s", (request_id,)
            )
            meta = c.fetchone()
            if not meta:
                raise KeyError(
                    f"filtered_response not found for request_id={request_id}"
                )
            response_id = meta["id"]

            c.execute(
                "SELECT key, value FROM filtered_response_headers WHERE response_id=%s ORDER BY id",
                (response_id,),
            )
            headers = c.fetchall()

            c.execute(
                "SELECT * FROM filtered_response_body WHERE response_id=%s",
                (response_id,),
            )
            body = c.fetchone()

        return {"meta": meta, "headers": headers, "body": body}

    def select_fuzzed_response(self, request_id: int) -> Dict[str, Any]:
        """fuzzed_request_id
        -> fuzzed_response, fuzzed_response_headers, fuzzed_response_body 읽기
        """
        with self._cur() as c:
            c.execute(
                "SELECT * FROM fuzzed_response WHERE fuzzed_request_id=%s",
                (request_id,),
            )
            meta = c.fetchone()
            if not meta:
                raise KeyError(
                    f"fuzzed_response not found for fuzzed_request_id={request_id}"
                )
            response_id = meta["id"]

            c.execute(
                "SELECT key, value "
                "FROM fuzzed_response_headers WHERE fuzzed_response_id=%s ORDER BY id",
                (response_id,),
            )
            headers = c.fetchall()

            c.execute(
                "SELECT * FROM fuzzed_response_body WHERE fuzzed_response_id=%s",
                (response_id,),
            )
            body = c.fetchone()

        return {"meta": meta, "headers": headers, "body": body}

    def select_recon(self, recon_id: int) -> Dict[str, Any]:
        """recon_id
        -> recon, recon_software 읽기
        """
        with self._cur() as c:
            c.execute("SELECT * FROM recon WHERE id=%s", (recon_id,))
            meta = c.fetchone()
            if not meta:
                raise KeyError(f"recon id {recon_id} not found")

            c.execute(
                """SELECT category, name, version
                     FROM recon_software
                    WHERE recon_id=%s
                    ORDER BY id""",
                (recon_id,),
            )
            software = c.fetchall()

        return {"meta": meta, "software": software}

    def get_recon_id_by_domain_path(self, domain: str, path: str) -> int:
        """
        domain, path로 recon 테이블에서 id를 조회
        """
        with self._cur() as c:
            c.execute(
                "SELECT id FROM recon WHERE domain=%s AND path=%s "
                "ORDER BY detected_at DESC LIMIT 1",
                (domain, path),
            )
            row = c.fetchone()
            if row:
                return row["id"]
            return -1

    def fetch_ids(self, start_id: int, limit: int) -> List[int]:
        """
        start_id 이상부터 limit개까지의 id를 오름차순으로 반환
        """
        query = (
            "SELECT id FROM filtered_request WHERE id >= %s ORDER BY id ASC LIMIT %s"
        )

        try:
            with self._cur() as cur:
                cur.execute(query, (start_id, limit))
                return [row["id"] for row in cur.fetchall()]
        except psycopg2.DatabaseError as e:
            # DB 관련 예외만 감싸서 올림
            raise RuntimeError(f"DB fetch_ids error: {e}") from e
