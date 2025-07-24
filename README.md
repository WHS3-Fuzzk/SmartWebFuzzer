# SmartWebFuzzer

## 요구사항

- **Python**: 3.12.0 권장

## 프로젝트 실행 방법

1. **프로젝트 클론**

   ```sh
   git clone https://github.com/WHS3-Fuzzk/SmartWebFuzzer.git
   cd SmartWebFuzzer
   ```

2. **환경 변수 파일 생성**

   ```sh
   cp .env-template .env
   ```

3. **인프라(데이터베이스 등) 도커로 실행**

   ```sh
   docker-compose up -d
   ```

4. **필요한 패키지 설치**

   ```sh
   pip install -r requirements.txt
   ```

5. **메인 프로그램 실행**

   ```sh
   python main.py
   ```
