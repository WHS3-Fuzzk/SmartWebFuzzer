"""
wad를 통해 엔드포인트의 기술스택 정보를 수집하는 모듈
"""

import subprocess
import json
import re
from datetime import datetime
from db_reader import DBReader
from db_writer import insert_recon


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
    recon_id = reader.get_recon_id_by_domain_path(domain, path)
    if recon_id != -1:
        print("이미 저장된 정보가 있습니다.", recon_id)
        return recon_id

    url = f"http://{domain}{path}"

    # wad CLI 실행 (wad가 설치되어 있어야 함)
    result = subprocess.run(
        ["wad", "-u", url], capture_output=True, text=True, check=True
    )
    wad_output = result.stdout

    # wad_output에서 JSON만 추출
    match = re.search(r"({.*})", wad_output, re.DOTALL)
    if not match:
        print("wad 결과에서 JSON을 찾을 수 없습니다.")
        return -1
    print(match)
    wad_json = json.loads(match.group(1))

    # wad 결과 파싱 (예시: wad_json['technologies'])
    tech_list = next(iter(wad_json.values()), [])
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

    # DB 저장
    recon = {
        "domain": domain,
        "path": path,
        "detected_at": datetime.now(),
        "software": software_list,
    }
    recon_id = insert_recon(recon)
    return recon_id
