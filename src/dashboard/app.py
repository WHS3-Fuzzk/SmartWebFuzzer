"""Flask 기반 스마트 웹 퍼저 대시보드의 웹 서버 모듈"""

import os  # 표준 라이브러리
import atexit  # 앱 종료 시 정리용
from flask import Flask, jsonify, render_template  # 서드파티 라이브러리
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
    """최근 원본 요청 목록을 반환하는 API"""
    query = """
        SELECT r.id, r.method, r.domain, r.path,
               CASE 
                   WHEN fr.original_request_id IS NOT NULL THEN true 
                   ELSE false 
               END as has_fuzzing
        FROM filtered_request r
        LEFT JOIN (
            SELECT DISTINCT original_request_id 
            FROM fuzzed_request
        ) fr ON r.id = fr.original_request_id
        ORDER BY r.timestamp DESC
        LIMIT 50;
    """
    rows = db_manager.execute_query(query)
    return jsonify(
        [
            {
                "id": row[0],
                "method": row[1],
                "url": f"{row[2]}{row[3]}",
                "has_fuzzing": row[4],
            }
            for row in rows
        ]
    )


@app.route("/api/request/<int:request_id>")
def get_request_detail(request_id):
    """지정된 요청 ID에 대한 본문, 응답, 퍼징 정보를 반환"""
    query = """
        SELECT r.id, rb.body AS request_body, rb2.body AS response_body
        FROM filtered_request r
        LEFT JOIN filtered_request_body rb ON r.id = rb.request_id
        LEFT JOIN filtered_response fr ON r.id = fr.request_id
        LEFT JOIN filtered_response_body rb2 ON fr.id = rb2.response_id
        WHERE r.id = %s
        ORDER BY fr.id DESC
        LIMIT 1;
    """
    rows = db_manager.execute_query(query, (request_id,))
    if not rows:
        return jsonify({"error": "요청 ID에 대한 데이터 없음"}), 404

    request_body = rows[0][1] or "(없음)"
    response_body = rows[0][2] or "(없음)"

    fuzz_query = """
        SELECT fr.id, fr.scanner, fr.method, fr.payload,
               frb.body AS fuzzed_body,
               fresb.body AS response_body
        FROM fuzzed_request fr
        LEFT JOIN fuzzed_request_body frb ON fr.id = frb.fuzzed_request_id
        LEFT JOIN fuzzed_response fres ON fr.id = fres.fuzzed_request_id
        LEFT JOIN fuzzed_response_body fresb ON fres.id = fresb.fuzzed_response_id
        WHERE fr.original_request_id = %s
        ORDER BY fr.timestamp DESC;
    """
    fuzz_rows = db_manager.execute_query(fuzz_query, (request_id,))
    fuzz_data = [
        {
            "id": row[0],
            "scanner": row[1],
            "method": row[2],
            "payload": row[3],
            "fuzzed_body": row[4] or "(없음)",
            "response_body": row[5] or "(없음)",
        }
        for row in fuzz_rows
    ]

    # 취약점 스캔 결과 조회 (원본 요청 기준)
    vuln_query = """
        SELECT vulnerability_name, domain, endpoint, method, 
               parameter, payload, extra
        FROM vulnerability_scan_results
        WHERE original_request_id = %s
        ORDER BY id DESC;
    """
    vuln_rows = db_manager.execute_query(vuln_query, (request_id,))
    vuln_data = [
        {
            "vulnerability_name": row[0],
            "domain": row[1],
            "endpoint": row[2],
            "method": row[3],
            "parameter": row[4],
            "payload": row[5],
            "extra": row[6],
        }
        for row in vuln_rows
    ]

    return jsonify(
        {
            "id": request_id,
            "request_body": request_body,
            "response_body": response_body,
            "fuzzing": fuzz_data,
            "vulnerability_results": vuln_data,
        }
    )


@app.route("/api/fuzzed_request/<int:fuzzed_request_id>/vulnerabilities")
def get_fuzzed_request_vulnerabilities(fuzzed_request_id):
    """특정 퍼징 요청에 대한 취약점 분석 결과를 반환"""
    vuln_query = """
        SELECT vulnerability_name, domain, endpoint, method, 
               parameter, payload, extra
        FROM vulnerability_scan_results
        WHERE fuzzed_request_id = %s
        ORDER BY id DESC;
    """
    vuln_rows = db_manager.execute_query(vuln_query, (fuzzed_request_id,))
    vuln_data = [
        {
            "vulnerability_name": row[0],
            "domain": row[1],
            "endpoint": row[2],
            "method": row[3],
            "parameter": row[4],
            "payload": row[5],
            "extra": row[6],
        }
        for row in vuln_rows
    ]

    return jsonify({"vulnerability_results": vuln_data})


if __name__ == "__main__":
    try:
        app.run(debug=True)
    except KeyboardInterrupt:
        print("\n🛑 서버 종료 중...")
        close_connection_pool()
