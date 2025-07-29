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
- File Download Vulnerability

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

   **Python 버전**: 3.12.0

   ```sh
   python src/main.py [-h] [-url URL] [-w NUM] [-t NUM] [-v] [-rps NUM]
   ```

6. **대시보드 확인**

   ```text
   127.0.0.1:5000
   ```

### 화면 구성

|                                        퍼저 메인 #1                                        |
| :----------------------------------------------------------------------------------------: |
| ![Image1](https://github.com/user-attachments/assets/3b7259e5-da20-4ed9-b50e-c9af79604b14) |

|                                      퍼저 대시보드 #2                                      |
| :----------------------------------------------------------------------------------------: |
| ![Image2](https://github.com/user-attachments/assets/c4287020-df98-40b5-a3f6-8de29df90330) |

<br/>

## 💁‍♂️ 프로젝트 팀원

|                             PM                              |                             팀원                             |                          팀원                           |                            팀원                            |
| :---------------------------------------------------------: | :----------------------------------------------------------: | :-----------------------------------------------------: | :--------------------------------------------------------: |
| <img src="https://github.com/idealinsane.png" width="120"/> | <img src="https://github.com/hyeongseok88.png" width="120"/> | <img src="https://github.com/h4vrut4.png" width="120"/> | <img src="https://github.com/foskingson.png" width="120"/> |
|          [김민수](https://github.com/idealinsane)           |          [김형석](https://github.com/hyeongseok88)           |          [임한섭](https://github.com/h4vrut4)           |          [조민형](https://github.com/foskingson)           |

|                            팀원                            |                            팀원                            |                            팀원                             |                          팀원                          |
| :--------------------------------------------------------: | :--------------------------------------------------------: | :---------------------------------------------------------: | :----------------------------------------------------: |
| <img src="https://github.com/dlghtjd123.png" width="120"/> | <img src="https://github.com/dlghtjd123.png" width="120"/> | <img src="https://github.com/onestar4701.png" width="120"/> | <img src="https://github.com/jin182.png" width="120"/> |
|          [이호성](https://github.com/dlghtjd123)           |          [어명규](https://github.com/dlghtjd123)           |          [차한솔](https://github.com/onestar4701)           |          [유진우](https://github.com/jin182)           |
