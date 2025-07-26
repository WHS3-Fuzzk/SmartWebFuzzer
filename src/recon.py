"""
wad를 통해 엔드포인트의 기술스택 정보를 수집하는 모듈
"""

import os
import subprocess
import json
import re
from datetime import datetime
from db_reader import DBReader
from db_writer import insert_recon


def parse_software_list(tech_list):
    """
    wad에서 반환된 기술 스택 리스트를 파싱해 소프트웨어 목록 생성

    Args:
        tech_list (list): wad JSON에서 추출한 기술 스택 리스트

    Returns:
        list: 소프트웨어 정보 딕셔너리 리스트
    """
    software_list = []
    for tech in tech_list:
        categories = [c.strip() for c in tech.get("type", "").split(",")]
        for category in categories:
            software_list.append(
                {
                    "category": category,
                    "name": tech.get("app", "unknown"),
                    "version": tech.get("ver", ""),
                }
            )
    return software_list


def run_recon(domain: str, path: str) -> int:
    """
    주어진 도메인과 엔드포인트에 대해 wad로 기술스택을 탐지하고 DB에 저장
    Args:
        domain (str): 예시 'example.com'
        path (str): 예시 '/wp-login.php'
    Returns:
        int: 저장된 recon_id
    """

    # 동일 domain, path로 중복 저장 여부 확인
    reader = DBReader()

    path = path.split("?")[0]
    recon_id = reader.get_recon_id_by_domain_path(domain, path)
    if recon_id != -1:
        return recon_id

    url = f"http://{domain}{path}"

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"  # UTF-8 강제 설정

    try:
        result = subprocess.run(
            ["wad", "-u", url],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
            env=env,
        )
    except subprocess.CalledProcessError:
        print("[RECON] ERROR! wad 실행 실패")
        return -1

    match = re.search(r"({.*})", result.stdout, re.DOTALL)
    if not match:
        print("[RECON] ERROR! wad 결과에서 JSON을 찾을 수 없습니다.")
        return -1

    try:
        wad_json = json.loads(match.group(1))
    except json.JSONDecodeError:
        print("[RECON] ERROR! JSON 파싱 실패")
        return -1

    tech_list = next(iter(wad_json.values()), [])
    software_list = parse_software_list(tech_list)

    recon = {
        "domain": domain,
        "path": path,
        "detected_at": datetime.now(),
        "software": software_list,
    }
    recon_id = insert_recon(recon)
    return recon_id
