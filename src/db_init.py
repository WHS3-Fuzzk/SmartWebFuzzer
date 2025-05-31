"""db 초기화 (초기 DB 생성 및 테이블 생성)"""

import os
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from dotenv import load_dotenv

load_dotenv()  # .env 파일을 환경 변수로 로딩

DB_NAME = os.getenv("POSTGRES_DB")
USER = os.getenv("POSTGRES_USER")
PASSWORD = os.getenv("POSTGRES_PASSWORD")
HOST = os.getenv("POSTGRES_HOST")
PORT = os.getenv("POSTGRES_PORT")


def create_database_if_not_exists():
    """기본 postgres DB에 접속해, 대상 DB가 없으면 새로 생성합니다."""
    conn = psycopg2.connect(
        dbname=DB_NAME, user=USER, password=PASSWORD, host=HOST, port=PORT
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
    exists = cur.fetchone()

    if not exists:
        print(f"📦 데이터베이스 '{DB_NAME}'가 없어서 생성합니다.")
        cur.execute(f"CREATE DATABASE {DB_NAME}")
    else:
        print(f"✅ 데이터베이스 '{DB_NAME}'는 이미 존재합니다.")

    cur.close()
    conn.close()


def create_tables():
    """대상 DB에 접속해 테이블 생성"""
    conn = psycopg2.connect(
        dbname=DB_NAME, user=USER, password=PASSWORD, host=HOST, port=PORT
    )
    cur = conn.cursor()

    table_sql = """
    CREATE TABLE IF NOT EXISTS filtered_request (
        id SERIAL PRIMARY KEY,
        is_http INTEGER,
        http_version VARCHAR,
        domain VARCHAR,
        path VARCHAR,
        method VARCHAR,
        timestamp TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS filtered_response (
        id SERIAL PRIMARY KEY,
        request_id INTEGER NOT NULL REFERENCES filtered_request(id),
        http_version VARCHAR,
        status_code INTEGER,
        timestamp TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS filtered_request_headers (
        id SERIAL PRIMARY KEY,
        request_id INTEGER REFERENCES filtered_request(id),
        key VARCHAR,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS filtered_response_headers (
        id SERIAL PRIMARY KEY,
        response_id INTEGER REFERENCES filtered_response(id),
        key VARCHAR,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS filtered_query_params (
        id SERIAL PRIMARY KEY,
        request_id INTEGER REFERENCES filtered_request(id),
        key VARCHAR,
        value VARCHAR,
        source VARCHAR
    );

    CREATE TABLE IF NOT EXISTS filtered_request_body (
        id SERIAL PRIMARY KEY,
        request_id INTEGER REFERENCES filtered_request(id),
        content_type VARCHAR,
        charset VARCHAR,
        content_length INTEGER,
        content_encoding VARCHAR,
        body TEXT
    );

    CREATE TABLE IF NOT EXISTS filtered_response_body (
        id SERIAL PRIMARY KEY,
        response_id INTEGER REFERENCES filtered_response(id),
        content_type VARCHAR,
        charset VARCHAR,
        content_length INTEGER,
        content_encoding VARCHAR,
        body TEXT
    );

    CREATE TABLE IF NOT EXISTS recon (
        id SERIAL PRIMARY KEY,
        domain VARCHAR,
        path VARCHAR,
        detected_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS recon_software (
        id SERIAL PRIMARY KEY,
        recon_id INTEGER NOT NULL REFERENCES recon(id),
        category VARCHAR,
        name VARCHAR,
        version VARCHAR
    );

    CREATE TABLE IF NOT EXISTS fuzzed_request (
        id SERIAL PRIMARY KEY,
        original_request_id INTEGER NOT NULL REFERENCES filtered_request(id),
        scanner VARCHAR,
        payload TEXT,
        is_http INTEGER,
        http_version VARCHAR,
        domain VARCHAR,
        path VARCHAR,
        method VARCHAR,
        timestamp TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS fuzzed_request_headers (
        id SERIAL PRIMARY KEY,
        fuzzed_request_id INTEGER REFERENCES fuzzed_request(id),
        key VARCHAR,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS fuzzed_query_params (
        id SERIAL PRIMARY KEY,
        fuzzed_request_id INTEGER REFERENCES fuzzed_request(id),
        key VARCHAR,
        value VARCHAR,
        source VARCHAR
    );

    CREATE TABLE IF NOT EXISTS fuzzed_request_body (
        id SERIAL PRIMARY KEY,
        fuzzed_request_id INTEGER REFERENCES fuzzed_request(id),
        content_type VARCHAR,
        charset VARCHAR,
        content_length INTEGER,
        content_encoding VARCHAR,
        body TEXT
    );

    CREATE TABLE IF NOT EXISTS fuzzed_response (
        id SERIAL PRIMARY KEY,
        fuzzed_request_id INTEGER NOT NULL REFERENCES fuzzed_request(id),
        http_version INTEGER,
        status_code INTEGER,
        timestamp TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS fuzzed_response_headers (
        id SERIAL PRIMARY KEY,
        fuzzed_response_id INTEGER REFERENCES fuzzed_response(id),
        key VARCHAR,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS fuzzed_response_body (
        id SERIAL PRIMARY KEY,
        fuzzed_response_id INTEGER REFERENCES fuzzed_response(id),
        content_type VARCHAR,
        charset VARCHAR,
        content_length INTEGER,
        content_encoding VARCHAR,
        body TEXT
    );
    """

    cur.execute(table_sql)
    conn.commit()
    cur.close()
    conn.close()
    print("✅ 모든 테이블 생성 완료")


# 실행
if __name__ == "__main__":
    create_database_if_not_exists()
    create_tables()
