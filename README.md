<div align="center">

<!-- logo -->
<img src="https://github.com/whs3-fuzzk.png" width="300"/>

### 스마트 웹 퍼저

### "퍼지직"

<br/> [<img src="https://img.shields.io/badge/프로젝트 기간-2025.05.01~2025.08.02-green?style=flat&logo=&logoColor=white" />]()

</div>

## 프로젝트 소개

Fuzzk Smart Web Fuzzer는 웹 애플리케이션과 웹 서비스의 보안 취약점을 자동으로 탐지하고 분석하는 지능형 웹 퍼저입니다.  
기존 웹 퍼저보다 더 적은 패킷으로 효율적인 취약점 진단을 수행합니다.

### 🔍 주요 특징

- 모듈화 구조: 각 취약점 스캔 모듈이 독립적으로 구성되어 유지보수 및 확장 용이
- 트래픽 최소화: 최소한의 요청으로 효과적인 취약점 진단
- 자동화된 탐지 및 분석: 수동 개입 없이 자동으로 취약점 테스트 수행
- 다양한 취약점 지원: 주요 웹 취약점 진단

### 🛡️ 지원하는 취약점 스캐너 모듈

- Reflected XSS
- Stored XSS
- DOM-based XSS
- SQL Injection
- Command Injection
- SSRF (Server-Side Request Forgery)
- File Upload
- File Download

## ⚙ 기술 스택

<div>
<img src="https://i.ibb.co/v4K1Z2Kr/python.png" width="80">
<img src="https://github.com/yewon-Noh/readme-template/blob/main/skills/Docker.png?raw=true" width="80">
<img src="https://i.ibb.co/Fc6Trxg/postgres.png" width="80">
<img src="https://github.com/yewon-Noh/readme-template/blob/main/skills/Redis.png?raw=true" width="80">
<img src="https://i.ibb.co/6cbtt3Vy/mitmproxy.png" width="80">
</div>

### Tools

<div>
<img src="https://github.com/yewon-Noh/readme-template/blob/main/skills/Github.png?raw=true" width="80">
<img src="https://github.com/yewon-Noh/readme-template/blob/main/skills/Notion.png?raw=true" width="80">
<img src="https://github.com/yewon-Noh/readme-template/blob/main/skills/Discord.png?raw=true" width="80">
</div>

## 📜 MITM 인증서 설치 방법

1. **mitmproxy 실행**

   ```bash
   mitmproxy
   ```

2. **브라우저에서 mitmproxy 인증서 페이지 접속**

   - 주소: [http://mitm.it](http://mitm.it)
   - PC에서 mitmproxy를 통해 접속하면 자동으로 페이지가 열립니다.

3. **운영체제에 맞는 인증서 다운로드**

   - Windows, macOS

4. **신뢰할 수 있는 루트 인증기관으로 인증서 설치**
   - **PC**: OS의 인증서 관리자에서 "신뢰할 수 있는 루트 인증기관" 항목에 추가

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

   # uv
   uv venv --python 3.12.0 .venv
   source .venv/bin/activate
   uv pip install -r requirements.txt
   ```

5. **메인 프로그램 실행**

   **Python 버전**: 3.12.0

   ```sh
   python src/main.py [-h] [-url URL] [-w NUM] [-t NUM] [-rps NUM]

   # uv
   uv run python src/main.py
   ```

   | 옵션       | 전체 이름          | 설명                                         |
   | ---------- | ------------------ | -------------------------------------------- |
   | `-h`       | `--help`           | 도움말 메시지를 출력하고 종료합니다          |
   | `-url URL` | `--url URL`        | 타겟 URL (쉼표로 구분하여 여러 개 지정 가능) |
   | `-w NUM`   | `--workers NUM`    | 퍼징 요청을 보내는 워커 수 (기본값: 4)       |
   | `-t NUM`   | `--threads NUM`    | 스레드 수 (기본값: 8)                        |
   | `-rps NUM` | `--rate-limit NUM` | 초당 요청 수 제한 (RPS, 기본값: 제한 없음)   |

6. **대시보드 확인**

   ```text
   127.0.0.1:5000
   ```

### 화면 구성

|                                        퍼저 메인 #1                                        |
| :----------------------------------------------------------------------------------------: |
| ![Image1](https://github.com/user-attachments/assets/5723f28b-de97-43ea-b30b-6f08257091e6) |

|                                      퍼저 대시보드 #2                                      |
| :----------------------------------------------------------------------------------------: |
| ![Image2](https://github.com/user-attachments/assets/0dfcd073-fe2e-4af5-b1d9-95eaa99280fb) |

<br/>

## 💁‍♂️ 프로젝트 팀원

|                             PM                              |                             팀원                             |                          팀원                           |                            팀원                            |
| :---------------------------------------------------------: | :----------------------------------------------------------: | :-----------------------------------------------------: | :--------------------------------------------------------: |
| <img src="https://github.com/idealinsane.png" width="120"/> | <img src="https://github.com/hyeongseok88.png" width="120"/> | <img src="https://github.com/h4vrut4.png" width="120"/> | <img src="https://github.com/foskingson.png" width="120"/> |
|          [김민수](https://github.com/idealinsane)           |          [김형석](https://github.com/hyeongseok88)           |          [임한섭](https://github.com/h4vrut4)           |          [조민형](https://github.com/foskingson)           |

|                            팀원                            |                           팀원                           |                            팀원                             |                          팀원                          |
| :--------------------------------------------------------: | :------------------------------------------------------: | :---------------------------------------------------------: | :----------------------------------------------------: |
| <img src="https://github.com/dlghtjd123.png" width="120"/> | <img src="https://github.com/myonggyu.png" width="120"/> | <img src="https://github.com/onestar4701.png" width="120"/> | <img src="https://github.com/jin182.png" width="120"/> |
|          [이호성](https://github.com/dlghtjd123)           |          [어명규](https://github.com/myonggyu)           |          [차한솔](https://github.com/onestar4701)           |          [유진우](https://github.com/jin182)           |
