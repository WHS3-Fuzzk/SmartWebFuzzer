"""
스마트 웹 퍼징 대시보드 모듈
- 원본 요청 목록을 선택하면 요청/응답/퍼징 결과를 보여줌
"""

import os
import traceback
import pandas as pd
import psycopg2
import gradio as gr
from dotenv import load_dotenv
from psycopg2 import Error as Psycopg2Error

# .env 로드
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv("POSTGRES_DB"),
    "user": os.getenv("POSTGRES_USER"),
    "password": os.getenv("POSTGRES_PASSWORD"),
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
}


def run_query(query_and_params):
    """DB 쿼리 실행 및 DataFrame 반환"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        if isinstance(query_and_params, tuple):
            query, params = query_and_params
            df = pd.read_sql_query(query, conn, params=params)
        else:
            df = pd.read_sql_query(query_and_params, conn)
        conn.close()
        return df
    except (Psycopg2Error, pd.errors.ParserError):
        traceback.print_exc()
        return pd.DataFrame()


def get_response_text(request_id):
    """요청 ID로 응답 내용 반환"""
    response_df = run_query((QUERY_RESPONSE, (request_id,)))
    if not response_df.empty:
        r = response_df.iloc[0]
        return f"응답 코드: {r['status_code']}\n\n{r['response_body'] or '(본문 없음)'}"
    return "응답 없음"


# SQL 쿼리 정의
QUERY_ORIGINAL = """
    SELECT r.id, r.domain, r.path, r.method, rb.body AS request_body
    FROM filtered_request r
    LEFT JOIN filtered_request_body rb ON r.id = rb.request_id
    ORDER BY r.timestamp DESC
    LIMIT 50;
"""

QUERY_RESPONSE = """
    SELECT status_code, rb.body AS response_body
    FROM filtered_response r
    LEFT JOIN filtered_response_body rb ON r.id = rb.response_id
    WHERE r.request_id = %s
    ORDER BY r.id DESC
    LIMIT 1;
"""

QUERY_FUZZING = """
    SELECT fr.scanner, fr.payload, fr.method, frb.body AS fuzzed_body,
           fres.status_code, fresb.body AS response_body
    FROM fuzzed_request fr
    LEFT JOIN fuzzed_request_body frb ON fr.id = frb.fuzzed_request_id
    LEFT JOIN fuzzed_response fres ON fr.id = fres.fuzzed_request_id
    LEFT JOIN fuzzed_response_body fresb ON fres.id = fresb.fuzzed_response_id
    WHERE fr.original_request_id = %s
    ORDER BY fr.timestamp DESC;
"""

# 초기 데이터 로딩
original_df = run_query(QUERY_ORIGINAL)
original_options = [
    f"[{row['method']}] {row['domain']}{row['path']}"
    for _, row in original_df.iterrows()
]
fuzz_cache = {}


def load_request_info(req_text):
    """선택한 요청에 대해 요청/응답/퍼징 정보를 불러옴"""
    index = original_options.index(req_text)
    row = original_df.iloc[index]
    request_id = int(row["id"])
    req_body_text = row["request_body"] or "(본문 없음)"
    res_body_text = get_response_text(request_id)

    fuzz_df = run_query((QUERY_FUZZING, (request_id,)))
    fuzz_list = fuzz_df.to_dict("records")
    fuzz_cache[request_id] = fuzz_list
    fuzz_options = [f"[{f['scanner']}] {f['method']} {f['payload']}" for f in fuzz_list]

    if fuzz_options:
        selected_fuzz = fuzz_list[0]
        fuzz_body_text = selected_fuzz["fuzzed_body"] or "(없음)"
        fuzz_resp_text = selected_fuzz["response_body"] or "(없음)"
        fuzz_dropdown_update = gr.update(choices=fuzz_options, value=fuzz_options[0])
    else:
        fuzz_body_text = "퍼징 요청이 없습니다."
        fuzz_resp_text = "퍼징 응답이 없습니다."
        fuzz_dropdown_update = gr.update(choices=[], value=None)

    analysis_text = "분석 결과 테이블이 아직 존재하지 않습니다."

    return (
        req_body_text,
        res_body_text,
        fuzz_dropdown_update,
        fuzz_body_text,
        fuzz_resp_text,
        analysis_text,
    )


def load_fuzz_detail(fuzz_text, req_text):
    """선택한 퍼징 요청의 상세 정보를 불러옴"""
    index = original_options.index(req_text)
    request_id = int(original_df.iloc[index]["id"])
    fuzz_list = fuzz_cache.get(request_id, [])
    fuzz = next(
        (
            f
            for f in fuzz_list
            if f"[{f['scanner']}] {f['method']} {f['payload']}" == fuzz_text
        ),
        None,
    )
    if fuzz:
        return fuzz["fuzzed_body"] or "(없음)", fuzz["response_body"] or "(없음)"
    return "(없음)", "(없음)"


# Gradio UI 구성
with gr.Blocks() as grammar:
    gr.HTML(
        """
        <style>
        #request-scroll-box {
            max-height: 320px;
            overflow-y: auto;
            padding-right: 6px;
            border: 1px solid #eee;
            border-radius: 8px;
        }
        #request-scroll-box fieldset {
            max-height: 300px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
        }
        </style>
        """
    )

    gr.Markdown("# 🛡️ 스마트 웹 퍼징 대시보드")

    with gr.Row():
        with gr.Column():
            gr.Markdown("### 📦 원본 요청")
            with gr.Column(elem_id="request-scroll-box"):
                original_dropdown = gr.Radio(
                    label="요청 목록", choices=original_options, interactive=True
                )
            request_body_box = gr.Textbox(label="요청 본문", lines=4)
            response_body_box = gr.Textbox(label="요청 응답", lines=6)

        with gr.Column():
            gr.Markdown("### 🔁 퍼징 요청 & 응답")
            fuzz_dropdown_box = gr.Dropdown(
                label="퍼징 요청 목록", choices=[], interactive=True
            )
            fuzz_body_box = gr.Textbox(label="퍼징 요청 본문", lines=4)
            fuzz_response_box = gr.Textbox(label="퍼징 응답 본문", lines=6)

        with gr.Column():
            gr.Markdown("### 📊 분석 결과")
            analysis_result_box = gr.Textbox(label="분석 결과", lines=12)

    original_dropdown.change(  # pylint: disable=no-member
        fn=load_request_info,
        inputs=original_dropdown,
        outputs=[
            request_body_box,
            response_body_box,
            fuzz_dropdown_box,
            fuzz_body_box,
            fuzz_response_box,
            analysis_result_box,
        ],
    )

    fuzz_dropdown_box.change(  # pylint: disable=no-member
        fn=load_fuzz_detail,
        inputs=[fuzz_dropdown_box, original_dropdown],
        outputs=[fuzz_body_box, fuzz_response_box],
    )

grammar.launch()
