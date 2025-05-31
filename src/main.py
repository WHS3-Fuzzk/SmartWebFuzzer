"""main.py"""

import os
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

DB_NAME = os.getenv("DB_NAME")
USER = os.getenv("DB_USER")
PASSWORD = os.getenv("DB_PASSWORD")
HOST = os.getenv("DB_HOST")
PORT = os.getenv("DB_PORT")


def create_database_if_not_exists():
    """기본 postgres DB에 접속해, 대상 DB가 없으면 새로 생성합니다."""
    # 1. PostgreSQL의 기본 DB인 'postgres'에 먼저 연결
    conn = psycopg2.connect(
        dbname="postgres", user=USER, password=PASSWORD, host=HOST, port=PORT
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()

    # 2. DB가 이미 존재하는지 확인
    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
    exists = cur.fetchone()

    if not exists:
        print(f"데이터베이스 '{DB_NAME}'가 없어서 생성합니다.")
        cur.execute(f"CREATE DATABASE {DB_NAME}")
    else:
        print(f"데이터베이스 '{DB_NAME}'는 이미 존재합니다.")

    # 3. 연결 종료
    cur.close()
    conn.close()


# 실행
create_database_if_not_exists()
