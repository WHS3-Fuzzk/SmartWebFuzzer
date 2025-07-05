from flask import Flask, jsonify, render_template
import psycopg2
import os
from dotenv import load_dotenv

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


# DB 쿼리 실행 함수
def run_query(query, params=None):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(query, params)
        result = cur.fetchall()
        cur.close()
        conn.close()
        return result
    except Exception as e:
        print("DB 오류:", e)
        return []


# 메인 페이지 렌더링
@app.route("/")
def index():
    return render_template("dashboard.html")


# 원본 요청 목록 API
@app.route("/api/requests")
def get_requests():
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


# 요청 상세 정보 API
@app.route("/api/request/<int:request_id>")
def get_request_detail(request_id):
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

    row = rows[0]
    request_body = row[1] or "(없음)"
    response_body = row[2] or "(없음)"

    # 퍼징 요청 목록
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


# 앱 실행
if __name__ == "__main__":
    app.run(debug=True)
