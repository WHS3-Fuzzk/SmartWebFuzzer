"""db 초기화 (초기 DB 생성 및 테이블 생성) 모듈"""

import os
import subprocess
from datetime import datetime

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from dotenv import load_dotenv
from db_config import DB_NAME, USER, PASSWORD, HOST, PORT

load_dotenv()

CONTAINER_NAME = "fuzzk_postgres"


class DBInit:
    """PostgreSQL 데이터베이스 생성 및 테이블 초기화를 담당하는 클래스."""

    def __init__(self):
        """DB 접속에 필요한 환경변수를 초기화합니다."""
        self.db_name = DB_NAME
        self.user = USER
        self.password = PASSWORD
        self.host = HOST
        self.port = PORT

    def _connect(self, dbname=None):
        """지정된 데이터베이스에 연결합니다."""
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
        존재할 경우 기존 모든 테이블을 삭제합니다.
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
            self.drop_all_tables()

    def _create_database(self):
        """대상 데이터베이스를 생성합니다."""
        conn = self._connect(dbname="postgres")
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        cur.execute(f"CREATE DATABASE {self.db_name}")
        cur.close()
        conn.close()

    def drop_all_tables(self):
        """데이터베이스 내 모든 테이블을 삭제합니다."""
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
                    EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
                END LOOP;
            END $$;
            """
        )
        conn.commit()
        cur.close()
        conn.close()
        print("💥 모든 테이블 DROP 완료")

    def create_tables(self):
        """DB 내 모든 테이블을 생성합니다."""
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

        CREATE TABLE IF NOT EXISTS preflight_request (
            id SERIAL PRIMARY KEY,
            domain VARCHAR,
            path VARCHAR,
            origin VARCHAR,
            access_control_request_method VARCHAR,
            timestamp TIMESTAMP,
            headers JSONB,
            preflight_allowed BOOLEAN
        );
        """
        cur.execute(table_sql)
        conn.commit()
        cur.close()
        conn.close()
        print("✅ 모든 테이블 생성 완료")

    def backup_database(self):
        """Docker 컨테이너의 PostgreSQL DB를 SQL 파일로 백업"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "db_backups"
        )
        os.makedirs(backup_dir, exist_ok=True)

        filename = f"{DB_NAME}_{timestamp}.sql"
        backup_path = os.path.join(backup_dir, filename)

        try:
            with open(backup_path, "w", encoding="utf-8") as f:
                subprocess.run(
                    [
                        str("docker"),
                        str("exec"),
                        str("-t"),
                        str(CONTAINER_NAME),
                        str("pg_dump"),
                        str("-U"),
                        str(USER),
                        str(DB_NAME),
                    ],
                    stdout=f,
                    check=True,
                )
            print(f"💾 DB 백업 완료: {backup_path}")
        except subprocess.CalledProcessError as e:
            print("❌ DB 백업 실패:", e)
