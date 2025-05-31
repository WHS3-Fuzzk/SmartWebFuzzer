"""db_reader.py  —  단일 클래스·4개 공개 메서드 버전"""

from typing import Any, Dict
import contextlib
import psycopg2.extras as _E
import psycopg2.pool


# 다음 3개의 메타 데이터들의 id를 기준으로 read를 진행한다.
class DBReader:
    """filtered_request, fuzzed_request,  recon 이 셋의 id를 기준으로 read를 진행.
    각 id는 DB Write 수행 시, 반환 된 것을 이용한다."""

    def __init__(self, dsn: str):
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

    # ─────────────── 내부 공용 헬퍼 ───────────────
    def _select_request(self, prefix: str, rid: int) -> Dict[str, Any]:
        with self._cur() as c:
            c.execute(f"SELECT * FROM {prefix}request WHERE id=%s", (rid,))
            meta = c.fetchone()
            if not meta:
                raise KeyError(f"{prefix}request id {rid} not found")

            c.execute(
                f"SELECT key,value FROM {prefix}request_headers "
                f"WHERE {prefix}request_id=%s ORDER BY id",
                (rid,),
            )
            headers = c.fetchall()

            qp_tbl = f"{prefix}query_params"
            c.execute(
                f"SELECT key,value,source FROM {qp_tbl} "
                f"WHERE {prefix}request_id=%s ORDER BY id",
                (rid,),
            )
            params = c.fetchall()

            body_tbl = f"{prefix}request_body"
            c.execute(f"SELECT * FROM {body_tbl} WHERE {prefix}request_id=%s", (rid,))
            body = c.fetchone()

        return {"meta": meta, "headers": headers, "query_params": params, "body": body}

    def _select_response(self, prefix: str, rid: int) -> Dict[str, Any]:
        with self._cur() as c:
            c.execute(
                f"SELECT * FROM {prefix}response "
                f"WHERE {prefix}request_id=%s ORDER BY id",
                (rid,),
            )
            meta = c.fetchone()
            if not meta:
                raise KeyError(f"{prefix}response not found for request_id={rid}")

            resp_id = meta["id"]

            c.execute(
                f"SELECT key,value FROM {prefix}response_headers "
                f"WHERE {prefix}response_id=%s ORDER BY id",
                (resp_id,),
            )
            headers = c.fetchall()
            c.execute(
                f"SELECT * FROM {prefix}response_body " f"WHERE {prefix}response_id=%s",
                (resp_id,),
            )
            body = c.fetchone()
        return {"meta": meta, "headers": headers, "body": body}

    # ─────────────── 공개 API 5개 ───────────────
    def select_filtered_request(self, request_id: int) -> Dict[str, Any]:
        """filtered_request_id -> filtered_request, filtered_headers, filtered_query_params, filtered_requests_body 읽기"""
        return self._select_request("filtered_", request_id)

    def select_filtered_response(self, request_id: int) -> Dict[str, Any]:
        """filtered_request_id -> filtered_response, filtered_response_headers, filtered_response_body 읽기"""
        return self._select_response("filtered_", request_id)

    def select_fuzzed_request(self, fuzzed_request_id: int) -> Dict[str, Any]:
        """fuzzed_request_id -> fuzzed_request, fuzzed_headers, fuzzed_query_params, fuzzed_requests_body 읽기"""
        return self._select_request("fuzzed_", fuzzed_request_id)

    def select_fuzzed_response(self, fuzzed_request_id: int) -> Dict[str, Any]:
        """fuzzed_request_id -> fuzzed_response, fuzzed_response_headers, fuzzed_response_body 읽기"""
        return self._select_response("fuzzed_", fuzzed_request_id)

    def select_recon(self, recon_id: int) -> Dict[str, Any]:
        """recon_id -> recon, recon_software 읽기"""
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
