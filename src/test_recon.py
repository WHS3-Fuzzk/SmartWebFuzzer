"""
recon 모듈 테스트
"""

from db_reader import DBReader
from recon import run_recon


if __name__ == "__main__":
    # 테스트용 도메인과 경로 입력
    DOMAIN = "whitehatschool.kr"
    PATH = "/home/kor/main.do"
    recon_id = run_recon(DOMAIN, PATH)

    if recon_id != -1:

        # DB에서 조회
        reader = DBReader()
        recon_data = reader.select_recon(recon_id)
        print("\nDB에서 조회한 결과:")
        print(recon_data)
