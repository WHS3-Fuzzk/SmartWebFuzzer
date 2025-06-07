"""db 초기화 (초기 DB 생성 및 테이블 생성)"""

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from db_config import DB_NAME, USER, PASSWORD, HOST, PORT


class DBInit:
    """PostgreSQL 데이터베이스 생성 및 테이블 초기화를 담당하는 클래스."""

    def __init__(self):
        """DB 접속에 필요한 환경변수 설정"""
        self.db_name = DB_NAME
        self.user = USER
        self.password = PASSWORD
        self.host = HOST
        self.port = PORT

    def _connect(self, dbname=None):
        """데이터베이스 커넥션을 반환합니다."""
        return psycopg2.connect(
            dbname=dbname or self.db_name,
            user=self.user,
            password=self.password,
            host=self.host,
            port=self.port,
        )

    def create_database_if_not_exists(self):
        """
        postgres DB에 접속하여 대상 DB가 없으면 새로 생성하고,
        존재할 경우 기존 모든 테이블 데이터를 삭제합니다.
        """
        conn = self._connect(dbname="postgres")
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()

        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (self.db_name,))
        exists = cur.fetchone()

        cur.close()
        conn.close()

        if not exists:
            print(f"📦 데이터베이스 '{self.db_name}'가 없어서 생성합니다.")
            self._create_database()
        else:
            print(f"✅ 데이터베이스 '{self.db_name}'는 이미 존재합니다.")
            self.truncate_all_tables()

    def _create_database(self):
        """새로운 데이터베이스를 생성합니다."""
        conn = self._connect(dbname="postgres")
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        cur.execute(f"CREATE DATABASE {self.db_name}")
        cur.close()
        conn.close()

    def truncate_all_tables(self):
        """기존 데이터베이스 내 모든 테이블의 데이터를 비웁니다."""
        conn = self._connect()
        cur = conn.cursor()

        cur.execute(
            """
            DO $$
            DECLARE
                r RECORD;
            BEGIN
                FOR r IN (
                    SELECT tablename FROM pg_tables
                    WHERE schemaname = 'public'
                )
                LOOP
                    EXECUTE 'TRUNCATE TABLE ' || quote_ident(r.tablename) || ' CASCADE';
                END LOOP;
            END $$;
        """
        )

        conn.commit()
        cur.close()
        conn.close()
        print("🧹 모든 테이블 데이터 TRUNCATE 완료")

    def create_tables(self):
        """모든 테이블을 생성합니다."""
        conn = self._connect()
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
    db = DBInit()
    db.create_database_if_not_exists()
    db.create_tables()
