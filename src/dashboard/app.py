"""Flask 기반 스마트 퍼징 대시보드의 웹 서버 모듈"""

import os  # 표준 라이브러리
from flask import Flask, jsonify, render_template  # 서드파티 라이브러리
import psycopg2
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


def run_query(query, params=None):
    """DB 쿼리를 실행하고 결과를 반환"""
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                cur.execute(query, params if params else None)
                return cur.fetchall()
    except psycopg2.Error as db_err:
        print("DB 오류:", db_err)
        return []


@app.route("/")
def index():
    """대시보드 메인 페이지를 렌더링"""
    return render_template("dashboard.html")


@app.route("/api/requests")
def get_requests():
    """최근 원본 요청 목록을 반환하는 API"""
    query = """
        SELECT r.id, r.method, r.domain, r.path
        FROM filtered_request r
        ORDER BY r.timestamp DESC
        LIMIT 50;
    """
    rows = run_query(query)
    return jsonify(
        [{"id": row[0], "method": row[1], "url": f"{row[2]}{row[3]}"} for row in rows]
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
    rows = run_query(query, (request_id,))
    if not rows:
        return jsonify({"error": "요청 ID에 대한 데이터 없음"}), 404

    request_body = rows[0][1] or "(없음)"
    response_body = rows[0][2] or "(없음)"

    fuzz_query = """
        SELECT fr.scanner, fr.method, fr.payload,
               frb.body AS fuzzed_body,
               fresb.body AS response_body
        FROM fuzzed_request fr
        LEFT JOIN fuzzed_request_body frb ON fr.id = frb.fuzzed_request_id
        LEFT JOIN fuzzed_response fres ON fr.id = fres.fuzzed_request_id
        LEFT JOIN fuzzed_response_body fresb ON fres.id = fresb.fuzzed_response_id
        WHERE fr.original_request_id = %s
        ORDER BY fr.timestamp DESC;
    """
    fuzz_rows = run_query(fuzz_query, (request_id,))
    fuzz_data = [
        {
            "scanner": row[0],
            "method": row[1],
            "payload": row[2],
            "fuzzed_body": row[3] or "(없음)",
            "response_body": row[4] or "(없음)",
        }
        for row in fuzz_rows
    ]

    return jsonify(
        {
            "id": request_id,
            "request_body": request_body,
            "response_body": response_body,
            "fuzzing": fuzz_data,
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
