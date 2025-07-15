"""Flask 기반 스마트 웹 퍼저 대시보드의 웹 서버 모듈"""

import os  # 표준 라이브러리
import atexit  # 앱 종료 시 정리용
from flask import Flask, jsonify, render_template, request  # 서드파티 라이브러리
import psycopg2
import psycopg2.pool
from dotenv import load_dotenv

# Flask 앱 초기화 및 환경 변수 로드
app = Flask(__name__)
load_dotenv()

# DB 설정
DB_CONFIG = {
    "dbname": os.getenv("POSTGRES_DB"),
    "user": os.getenv("POSTGRES_USER"),
    "password": os.getenv("POSTGRES_PASSWORD"),
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
}


class DatabaseManager:
    """데이터베이스 연결 풀을 관리하는 클래스"""

    def __init__(self, db_config):
        self.connection_pool = None
        self.init_pool(db_config)

    def init_pool(self, db_config):
        """Connection Pool 초기화"""
        try:
            self.connection_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1, maxconn=3, **db_config  # 최소 연결 수  # 최대 연결 수
            )
            print("📦 DB Connection Pool 생성 완료")
        except psycopg2.Error as e:
            print(f"❌ DB Connection Pool 생성 실패: {e}")
            self.connection_pool = None

    def execute_query(self, query, params=None):
        """DB 쿼리를 실행하고 결과를 반환"""
        if not self.connection_pool:
            print("❌ Connection Pool이 없습니다")
            return []

        conn = None
        try:
            # Pool에서 연결 가져오기
            conn = self.connection_pool.getconn()
            with conn.cursor() as cur:
                cur.execute(query, params if params else None)
                return cur.fetchall()
        except psycopg2.Error as db_err:
            print("DB 오류:", db_err)
            return []
        finally:
            # Pool에 연결 반환
            if conn:
                self.connection_pool.putconn(conn)

    def cleanup(self):
        """Connection Pool 정리"""
        if self.connection_pool:
            self.connection_pool.closeall()
            self.connection_pool = None
            print("🔒 DB Connection Pool 정리 완료")


# DB 매니저 인스턴스 생성
db_manager = DatabaseManager(DB_CONFIG)


def close_connection_pool():
    """DB 연결 풀 종료 (외부에서도 호출 가능)"""
    db_manager.cleanup()


# 앱 종료 시 정리 (standalone 실행 시에만)
atexit.register(close_connection_pool)


# main.py에서 사용할 수 있도록 cleanup 함수 export
__all__ = ["app", "close_connection_pool"]


@app.route("/")
def index():
    """대시보드 메인 페이지를 렌더링"""
    return render_template("dashboard.html")


@app.route("/api/requests")
def get_requests():
    """최근 원본 요청 목록을 반환하는 API - 쿼리 파라미터 포함"""
    query = """
        WITH request_with_query AS (
            SELECT 
                r.id, 
                r.method, 
                r.domain, 
                r.path,
                r.timestamp,
                CASE 
                    WHEN fr.original_request_id IS NOT NULL THEN true 
                    ELSE false 
                END as has_fuzzing,
                STRING_AGG(
                    CASE 
                        WHEN fqp.key IS NOT NULL AND fqp.value IS NOT NULL 
                        THEN fqp.key || '=' || fqp.value 
                        ELSE NULL 
                    END, 
                    '&' ORDER BY fqp.id
                ) as query_string
            FROM filtered_request r
            LEFT JOIN (
                SELECT DISTINCT original_request_id 
                FROM fuzzed_request
            ) fr ON r.id = fr.original_request_id
            LEFT JOIN filtered_query_params fqp ON r.id = fqp.request_id
            GROUP BY r.id, r.method, r.domain, r.path, r.timestamp, fr.original_request_id
        )
        SELECT id, method, domain, path, query_string, has_fuzzing, timestamp
        FROM request_with_query
        ORDER BY timestamp DESC
        LIMIT 50;
    """
    rows = db_manager.execute_query(query)

    result = []
    for row in rows:
        # 전체 URL 구성 (쿼리 파라미터 포함)
        base_url = f"{row[2]}{row[3]}"  # domain + path
        query_string = row[4]

        if query_string:
            full_url = f"{base_url}?{query_string}"
        else:
            full_url = base_url

        # URL이 너무 길면 줄임 (80자 제한)
        display_url = full_url if len(full_url) <= 80 else full_url[:77] + "..."

        result.append(
            {
                "id": row[0],
                "method": row[1],
                "url": display_url,
                "full_url": full_url,  # 툴팁이나 상세보기용
                "has_fuzzing": row[5],
            }
        )

    return jsonify(result)


@app.route("/api/vulnerabilities/batch", methods=["POST"])
def get_vulnerabilities_batch():
    """여러 퍼징 요청의 취약점을 한 번에 조회 (N+1 쿼리 최적화)"""

    if not request.json:
        return jsonify({"error": "JSON 데이터가 필요합니다"}), 400

    fuzz_ids = request.json.get("fuzz_ids", [])

    if not fuzz_ids:
        return jsonify({"vulnerabilities": {}})

    # JavaScript에서 오는 문자열 ID들을 정수로 변환
    try:
        fuzz_ids = [int(fuzz_id) for fuzz_id in fuzz_ids]
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"유효하지 않은 ID 형식: {e}"}), 400

    # 배열 형태로 한 번에 조회 (각 퍼징 요청당 최신 취약점 하나만)
    query = """
        SELECT fuzzed_request_id, 
                1 as vuln_count,
                JSON_BUILD_ARRAY(
                    JSON_BUILD_OBJECT(
                        'vulnerability_name', vulnerability_name,
                        'domain', domain,
                        'endpoint', endpoint,
                        'method', method,
                        'parameter', parameter,
                        'payload', payload,
                        'extra', extra
                    )
                ) as vulnerabilities
        FROM (
            SELECT DISTINCT ON (fuzzed_request_id) 
                    fuzzed_request_id, vulnerability_name, domain, endpoint, 
                    method, parameter, payload, extra
            FROM vulnerability_scan_results 
            WHERE fuzzed_request_id = ANY(%s)
            ORDER BY fuzzed_request_id, id DESC
        ) latest_vulns;
    """

    rows = db_manager.execute_query(query, (fuzz_ids,))

    # 결과를 딕셔너리 형태로 구성
    vulnerabilities = {}
    for row in rows:
        fuzz_id = row[0]
        vuln_count = row[1]
        vuln_list = row[2] if row[2] else []

        vulnerabilities[str(fuzz_id)] = {"count": vuln_count, "results": vuln_list}

    # 요청된 모든 ID에 대해 결과 보장 (없는 경우 빈 배열)
    for fuzz_id in fuzz_ids:
        if str(fuzz_id) not in vulnerabilities:
            vulnerabilities[str(fuzz_id)] = {"count": 0, "results": []}

    return jsonify({"vulnerabilities": vulnerabilities})


@app.route("/api/request/<int:request_id>/optimized")
def get_request_detail_optimized(request_id):
    """통합 쿼리로 요청 상세 정보를 한 번에 조회 (조인 최적화) - 헤더 정보 포함"""

    # 단일 통합 쿼리로 모든 데이터 조회 - 헤더 정보 포함
    query = """
    WITH request_info AS (
        SELECT 
            r.id as request_id,
            r.method,
            r.http_version as request_http_version,
            r.domain,
            r.path,
            rb.content_type as request_content_type,
            rb.charset as request_charset,
            rb.content_length as request_content_length,
            rb.content_encoding as request_content_encoding,
            rb.body AS request_body,
            res.status_code,
            res.http_version as response_http_version,
            resb.content_type as response_content_type,
            resb.charset as response_charset,
            resb.content_length as response_content_length,
            resb.content_encoding as response_content_encoding,
            resb.body AS response_body
        FROM filtered_request r
        LEFT JOIN filtered_request_body rb ON r.id = rb.request_id
        LEFT JOIN filtered_response res ON r.id = res.request_id
        LEFT JOIN filtered_response_body resb ON res.id = resb.response_id
        WHERE r.id = %s
        ORDER BY res.id DESC
        LIMIT 1
    ),
    latest_vulnerabilities AS (
        SELECT DISTINCT ON (fuzzed_request_id)
            fuzzed_request_id,
            vulnerability_name, domain, endpoint, method, parameter, payload, extra
        FROM vulnerability_scan_results
        ORDER BY fuzzed_request_id, id DESC
    ),
    fuzzing_info AS (
        SELECT 
            fr.id,
            fr.scanner,
            fr.method,
            fr.http_version as fuzz_request_http_version,
            fr.domain as fuzz_request_domain,
            fr.path as fuzz_request_path,
            fr.payload,
            frb.content_type as fuzz_request_content_type,
            frb.charset as fuzz_request_charset,
            frb.content_length as fuzz_request_content_length,
            frb.content_encoding as fuzz_request_content_encoding,
            frb.body AS fuzzed_body,
            fres.status_code,
            fres.http_version as fuzz_response_http_version,
            fresb.content_type as fuzz_response_content_type,
            fresb.charset as fuzz_response_charset,
            fresb.content_length as fuzz_response_content_length,
            fresb.content_encoding as fuzz_response_content_encoding,
            fresb.body AS response_body,
            fr.timestamp,
            CASE 
                WHEN lv.vulnerability_name IS NOT NULL THEN 
                    JSON_BUILD_ARRAY(
                        JSON_BUILD_OBJECT(
                            'vulnerability_name', lv.vulnerability_name,
                            'domain', lv.domain,
                            'endpoint', lv.endpoint,
                            'method', lv.method,
                            'parameter', lv.parameter,
                            'payload', lv.payload,
                            'extra', lv.extra
                        )
                    )
                ELSE '[]'::json
            END as vulnerabilities,
            CASE 
                WHEN lv.vulnerability_name IS NOT NULL THEN 1 
                ELSE 0 
            END as vuln_count
        FROM fuzzed_request fr
        LEFT JOIN fuzzed_request_body frb ON fr.id = frb.fuzzed_request_id
        LEFT JOIN fuzzed_response fres ON fr.id = fres.fuzzed_request_id
        LEFT JOIN fuzzed_response_body fresb ON fres.id = fresb.fuzzed_response_id
        LEFT JOIN latest_vulnerabilities lv ON fr.id = lv.fuzzed_request_id
        WHERE fr.original_request_id = %s
        ORDER BY fr.timestamp DESC
    )
    SELECT 
        ri.request_id,
        ri.method,
        ri.request_http_version,
        ri.domain,
        ri.path,
        ri.request_content_type,
        ri.request_charset,
        ri.request_content_length,
        ri.request_content_encoding,
        ri.request_body,
        ri.status_code,
        ri.response_http_version,
        ri.response_content_type,
        ri.response_charset,
        ri.response_content_length,
        ri.response_content_encoding,
        ri.response_body,
        COALESCE(
            JSON_AGG(
                JSON_BUILD_OBJECT(
                    'id', fi.id,
                    'scanner', fi.scanner,
                    'method', fi.method,
                    'fuzz_request_http_version', fi.fuzz_request_http_version,
                    'fuzz_request_domain', fi.fuzz_request_domain,
                    'fuzz_request_path', fi.fuzz_request_path,
                    'payload', fi.payload,
                    'fuzz_request_content_type', fi.fuzz_request_content_type,
                    'fuzz_request_charset', fi.fuzz_request_charset,
                    'fuzz_request_content_length', fi.fuzz_request_content_length,
                    'fuzz_request_content_encoding', fi.fuzz_request_content_encoding,
                    'fuzzed_body', fi.fuzzed_body,
                    'fuzz_response_status_code', fi.status_code,
                    'fuzz_response_http_version', fi.fuzz_response_http_version,
                    'fuzz_response_content_type', fi.fuzz_response_content_type,
                    'fuzz_response_charset', fi.fuzz_response_charset,
                    'fuzz_response_content_length', fi.fuzz_response_content_length,
                    'fuzz_response_content_encoding', fi.fuzz_response_content_encoding,
                    'response_body', fi.response_body,
                    'vuln_count', fi.vuln_count,
                    'vulnerabilities', fi.vulnerabilities
                ) ORDER BY fi.timestamp DESC
            ) FILTER (WHERE fi.id IS NOT NULL), 
            '[]'::json
        ) as fuzzing_data
    FROM request_info ri
    LEFT JOIN fuzzing_info fi ON TRUE
    GROUP BY ri.request_id, ri.method, ri.request_http_version, ri.domain, ri.path,
             ri.request_content_type, ri.request_charset, ri.request_content_length, ri.request_content_encoding,
             ri.request_body, ri.status_code, ri.response_http_version,
             ri.response_content_type, ri.response_charset, ri.response_content_length, ri.response_content_encoding,
             ri.response_body;
    """

    rows = db_manager.execute_query(query, (request_id, request_id))

    if not rows:
        return jsonify({"error": "요청 ID에 대한 데이터 없음"}), 404

    row = rows[0]

    # 헤더 정보 별도 조회
    request_headers_query = """
        SELECT COALESCE(
            JSON_OBJECT_AGG(key, value ORDER BY id) FILTER (WHERE key IS NOT NULL), 
            '{}'::json
        ) as headers
        FROM filtered_request_headers
        WHERE request_id = %s
    """

    response_headers_query = """
        SELECT COALESCE(
            JSON_OBJECT_AGG(resh.key, resh.value ORDER BY resh.id) FILTER (WHERE resh.key IS NOT NULL), 
            '{}'::json
        ) as headers
        FROM filtered_response res
        LEFT JOIN filtered_response_headers resh ON res.id = resh.response_id
        WHERE res.request_id = %s
    """

    query_params_query = """
        SELECT COALESCE(
            JSON_OBJECT_AGG(key, value ORDER BY id) FILTER (WHERE key IS NOT NULL), 
            '{}'::json
        ) as params
        FROM filtered_query_params
        WHERE request_id = %s
    """

    # 헤더 정보 조회
    request_headers_rows = db_manager.execute_query(
        request_headers_query, (request_id,)
    )
    response_headers_rows = db_manager.execute_query(
        response_headers_query, (request_id,)
    )
    query_params_rows = db_manager.execute_query(query_params_query, (request_id,))

    request_headers = request_headers_rows[0][0] if request_headers_rows else {}
    response_headers = response_headers_rows[0][0] if response_headers_rows else {}
    query_params = query_params_rows[0][0] if query_params_rows else {}

    # 완전한 HTTP 요청 정보 구성
    request_data = {
        "method": row[1],
        "http_version": row[2],
        "domain": row[3],
        "path": row[4],
        "content_type": row[5],
        "charset": row[6],
        "content_length": row[7],
        "content_encoding": row[8],
        "body": row[9] or "",
        "headers": request_headers,
        "query_params": query_params,
    }

    # 완전한 HTTP 응답 정보 구성
    response_data = {
        "status_code": row[10],
        "http_version": row[11],
        "content_type": row[12],
        "charset": row[13],
        "content_length": row[14],
        "content_encoding": row[15],
        "body": row[16] or "",
        "headers": response_headers,
    }

    return jsonify(
        {
            "id": row[0],
            "request": request_data,
            "response": response_data,
            "fuzzing": row[17] if row[17] else [],
        }
    )


@app.route("/api/fuzz-request/<int:fuzz_request_id>/headers")
def get_fuzz_request_headers(fuzz_request_id):
    """퍼징 요청의 헤더 정보를 조회"""

    # 퍼징 요청 헤더 조회
    request_headers_query = """
        SELECT COALESCE(
            JSON_OBJECT_AGG(key, value ORDER BY id) FILTER (WHERE key IS NOT NULL), 
            '{}'::json
        ) as headers
        FROM fuzzed_request_headers
        WHERE fuzzed_request_id = %s
    """

    # 퍼징 요청 쿼리 파라미터 조회
    query_params_query = """
        SELECT COALESCE(
            JSON_OBJECT_AGG(key, value ORDER BY id) FILTER (WHERE key IS NOT NULL), 
            '{}'::json
        ) as params
        FROM fuzzed_query_params
        WHERE fuzzed_request_id = %s
    """

    # 퍼징 응답 헤더 조회
    response_headers_query = """
        SELECT COALESCE(
            JSON_OBJECT_AGG(frh.key, frh.value ORDER BY frh.id) FILTER (WHERE frh.key IS NOT NULL), 
            '{}'::json
        ) as headers
        FROM fuzzed_response fr
        LEFT JOIN fuzzed_response_headers frh ON fr.id = frh.fuzzed_response_id
        WHERE fr.fuzzed_request_id = %s
    """

    # 헤더 정보 조회
    request_headers_rows = db_manager.execute_query(
        request_headers_query, (fuzz_request_id,)
    )
    query_params_rows = db_manager.execute_query(query_params_query, (fuzz_request_id,))
    response_headers_rows = db_manager.execute_query(
        response_headers_query, (fuzz_request_id,)
    )

    request_headers = request_headers_rows[0][0] if request_headers_rows else {}
    query_params = query_params_rows[0][0] if query_params_rows else {}
    response_headers = response_headers_rows[0][0] if response_headers_rows else {}

    return jsonify(
        {
            "request_headers": request_headers,
            "query_params": query_params,
            "response_headers": response_headers,
        }
    )


if __name__ == "__main__":
    try:
        app.run(debug=True)
    except KeyboardInterrupt:
        print("\n🛑 서버 종료 중...")
        close_connection_pool()
