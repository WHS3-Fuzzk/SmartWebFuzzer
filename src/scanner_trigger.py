"""
scanner_trigger.py

- DB에서 아직 처리하지 않은 HTTP 요청(request_id 순)들을 주기적으로 10개씩 가져옴
- 마지막으로 처리한 request_id를 기억해 다음 polling 때 이어서 처리
- 스캐너 함수 실행
- scanned 등 상태값 컬럼 사용 X, 오직 id 순서로만 제어
"""

from concurrent.futures import ThreadPoolExecutor
import time
from typing import List
from db_reader import DBReader
from scanners import _REGISTRY
from scanners.base import BaseScanner


class ScannerTrigger:
    """
    ScannerTrigger는 DB에서 HTTP 요청을 주기적으로 가져와 스캐너를 실행하는 역할을 합니다.
    - poll_interval: DB에서 요청을 가져오는 주기 (초 단위)
    - batch_size: 한 번에 가져오는 요청의 개수
    - last_processed_id: 마지막으로 처리한 요청의 ID
    """

    def __init__(
        self, poll_interval: int = 3, batch_size: int = 10, max_workers: int = 8
    ):
        self.db_reader = DBReader()
        self.poll_interval = poll_interval
        self.batch_size = batch_size
        self.max_workers = max_workers
        self.next_request_id = 1

    # 스캐너 저장소: scanners 모듈에서 활성화된 스캐너를 가져오는 함수
    def load_scanners(self) -> List[BaseScanner]:
        """
        load_scanners 메서드는 scanners 모듈에서 활성화된 스캐너를 가져옵니다.
        - _REGISTRY 딕셔너리를 통해 스캐너 클래스를 가져옵니다.
        """
        for name, cls in _REGISTRY.items():
            print(f"Loaded scanner: {name} -> {cls}")
        return [cls() for cls in _REGISTRY.values()]

    def run(self) -> None:
        """
        run 메서드는 DB에서 요청을 주기적으로 가져와 스캐너를 실행합니다.
        - DB에서 요청 ID를 가져오고, 해당 ID의 요청 데이터를 읽습니다.
        - 요청 데이터가 없으면 다음 ID로 넘어갑니다.
        - 요청 데이터가 있으면 활성화된 스캐너를 실행합니다.
        - 마지막으로 처리한 요청 ID를 업데이트합니다.
        - ThreadPoolExecutor가 while True 바깥에 있어, 스레드 풀은 한 번만 생성되고
          각 루프에서 작업을 submit한 뒤 결과를 기다리지 않고 바로 sleep에 들어갑니다.
        """
        scanners = self.load_scanners()
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while True:
                ids = self.db_reader.fetch_ids(self.next_request_id, self.batch_size)
                if ids:
                    for req_id in ids:
                        data = self.db_reader.select_filtered_request(req_id)
                        if not data:
                            continue
                        print(f"Processing request ID: {req_id},\n")
                        # 스캐너를 개별 쓰레드로 실행
                        for scanner in scanners:
                            print(
                                f"Running: {scanner.vulnerability_name} on request ID: {req_id}"
                            )
                            executor.submit(scanner.run, req_id, data)

                    self.next_request_id = ids[-1] + 1
                else:
                    pass
                time.sleep(self.poll_interval)


if __name__ == "__main__":
    ScannerTrigger().run()
