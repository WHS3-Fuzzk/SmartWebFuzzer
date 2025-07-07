const refreshInterval = 10;
let remainingTime = refreshInterval;
let currentRequestId = null;

function updateTimerDisplay() {
    const timerSpan = document.getElementById("refresh-timer");
    if (timerSpan) {
        const minutes = Math.floor(remainingTime / 60);
        const seconds = remainingTime % 60;
        const timeText = minutes > 0 ? `${minutes}분 ${seconds}초` : `${seconds}초`;
        timerSpan.textContent = `⏱️ 자동 새로고침: ${timeText}`;
    }
}

function startTimer() {
    updateTimerDisplay();
    setInterval(() => {
        remainingTime--;
        if (remainingTime <= 0) {
            remainingTime = refreshInterval;
            fetchRequests(); // 전체 요청 새로고침
        }
        updateTimerDisplay();
    }, 1000);
}

async function fetchRequests() {
    try {
        const res = await fetch("/api/requests");
        const data = await res.json();
        const listDiv = document.getElementById("original-request-list");
        const titleDiv = document.getElementById("original-request-title");
        listDiv.innerHTML = "";

        if (data.length === 0) {
            listDiv.innerHTML = "<p style='text-align: center; color: #7f8c8d; padding: 20px;'>📭 요청이 없습니다.<br>웹 트래픽을 기다리는 중...</p>";
            titleDiv.textContent = "📦 원본 요청 목록";
            clearAll();
            return;
        }

        // 섹션 제목에 개수 표시
        const countSpan = document.createElement("span");
        countSpan.style.color = "#7f8c8d";
        countSpan.style.fontSize = "12px";
        countSpan.style.fontWeight = "normal";
        countSpan.textContent = `(${data.length}개)`;
        
        titleDiv.textContent = "📦 원본 요청 목록 ";
        titleDiv.appendChild(countSpan);

        data.forEach((req, index) => {
            const div = document.createElement("div");
            div.classList.add("request-item");
            div.setAttribute("data-request-id", req.id);
            
            // 현재 선택된 요청이면 selected 클래스 추가
            if (req.id === currentRequestId) {
                div.classList.add("selected");
            }

            div.addEventListener("click", () => {
                // 모든 항목에서 selected 클래스 제거
                document.querySelectorAll("#original-request-list .request-item").forEach(item => {
                    item.classList.remove("selected");
                });
                
                // 클릭된 항목에 selected 클래스 추가
                div.classList.add("selected");
                
                currentRequestId = req.id;
                loadRequestDetail(req.id);
            });

            const content = document.createElement("div");
            content.classList.add("request-item-content");
            
            // 메소드별 색상 지정
            const methodColors = {
                'GET': '#3498db',
                'POST': '#e74c3c', 
                'PUT': '#f39c12',
                'DELETE': '#e67e22',
                'PATCH': '#9b59b6'
            };
            const methodColor = methodColors[req.method] || '#95a5a6';
            
            // HTML 안전하게 요소 생성
            const methodSpan = document.createElement("span");
            methodSpan.style.color = methodColor;
            methodSpan.style.fontWeight = "600";
            methodSpan.textContent = `[${req.method}]`;

            const urlSpan = document.createElement("span");
            urlSpan.style.marginLeft = "8px";
            urlSpan.textContent = req.url;

            // content에 안전하게 추가
            content.appendChild(methodSpan);
            content.appendChild(urlSpan);

            // 퍼징 요청이 있는 경우 표시
            if (req.has_fuzzing) {
                const fuzzingIcon = document.createElement("span");
                fuzzingIcon.style.marginLeft = "8px";
                fuzzingIcon.style.fontSize = "14px";
                fuzzingIcon.style.color = "#27ae60";
                fuzzingIcon.textContent = "🔬";
                fuzzingIcon.title = "퍼징 테스트 완료";
                content.appendChild(fuzzingIcon);
            }

            div.appendChild(content);
            listDiv.appendChild(div);
        });

        // 선택된 요청이 목록에 없으면 초기화
        if (currentRequestId && !data.some(r => r.id === currentRequestId)) {
            currentRequestId = null;
            clearAll();
        }

    } catch (err) {
        console.error("요청 목록 오류:", err);
        const listDiv = document.getElementById("original-request-list");
        const titleDiv = document.getElementById("original-request-title");
        listDiv.innerHTML = "<p style='text-align: center; color: #e74c3c; padding: 20px;'>❌ 요청 목록을 불러올 수 없습니다.<br>서버 연결을 확인해주세요.</p>";
        titleDiv.textContent = "📦 원본 요청 목록";
    }
}

async function loadRequestDetail(requestId) {
    try {
        const res = await fetch(`/api/request/${requestId}`);
        const data = await res.json();

        document.getElementById("request-body").value = data.request_body || "(없음)";
        document.getElementById("response-body").value = data.response_body || "(없음)";

        const fuzzListDiv = document.getElementById("fuzz-request-list");
        const fuzzTitleDiv = document.getElementById("fuzz-request-title");
        fuzzListDiv.innerHTML = "";

        if (data.fuzzing.length > 0) {
            // 제목에 개수 표시
            const fuzzCountSpan = document.createElement("span");
            fuzzCountSpan.style.color = "#7f8c8d";
            fuzzCountSpan.style.fontSize = "12px";
            fuzzCountSpan.style.fontWeight = "normal";
            fuzzCountSpan.textContent = `(${data.fuzzing.length}개)`;
            
            fuzzTitleDiv.textContent = "📨 퍼징 요청 선택 ";
            fuzzTitleDiv.appendChild(fuzzCountSpan);

            data.fuzzing.forEach((fuzz, idx) => {
                const div = document.createElement("div");
                div.classList.add("request-item");
                div.setAttribute("data-fuzz-index", idx);
                
                // 첫 번째 항목은 기본 선택
                if (idx === 0) {
                    div.classList.add("selected");
                }

                div.addEventListener("click", async () => {
                    // 모든 퍼징 항목에서 selected 클래스 제거
                    document.querySelectorAll("#fuzz-request-list .request-item").forEach(item => {
                        item.classList.remove("selected");
                    });
                    
                    // 클릭된 항목에 selected 클래스 추가
                    div.classList.add("selected");
                    
                    await updateFuzzDetail(data.fuzzing[idx]);
                });

                const content = document.createElement("div");
                content.classList.add("request-item-content");

                // 스캐너별 색상 지정
                const scannerColors = {
                    'example': '#e74c3c',
                    'ssrf': '#f39c12',
                    'xss': '#9b59b6',
                    'sqli': '#e67e22'
                };
                const scannerColor = scannerColors[fuzz.scanner] || '#95a5a6';

                // 페이로드 길이 제한 (너무 길면 줄임)
                const displayPayload = fuzz.payload.length > 50 
                    ? fuzz.payload.substring(0, 50) + '...' 
                    : fuzz.payload;

                // HTML 안전하게 요소 생성
                const scannerSpan = document.createElement("span");
                scannerSpan.style.color = scannerColor;
                scannerSpan.style.fontWeight = "600";
                scannerSpan.textContent = `[${fuzz.scanner}]`;

                const payloadSpan = document.createElement("span");
                payloadSpan.style.marginLeft = "8px";
                payloadSpan.textContent = displayPayload;

                // content에 안전하게 추가
                content.appendChild(scannerSpan);
                content.appendChild(payloadSpan);

                div.appendChild(content);
                fuzzListDiv.appendChild(div);
            });

            // 첫 번째 퍼징 요청 자동 로드
            await updateFuzzDetail(data.fuzzing[0]);
        } else {
            fuzzTitleDiv.textContent = "📨 퍼징 요청 선택";
            fuzzListDiv.innerHTML = "<p style='text-align: center; color: #7f8c8d; padding: 20px;'>📭 퍼징 요청이 없습니다.</p>";
            document.getElementById("fuzz-body").value = "(퍼징 요청 없음)";
            document.getElementById("fuzz-response").value = "(퍼징 응답 없음)";
            document.getElementById("analysis-result").value = "퍼징 요청이 없습니다.";
        }
    } catch (err) {
        console.error("요청 상세 불러오기 오류:", err);
        clearAll();
    }
}

async function updateFuzzDetail(fuzz) {
    // 로딩 상태 표시
    const analysisResult = document.getElementById("analysis-result");
    analysisResult.classList.add("loading");
    analysisResult.value = "분석 결과를 불러오는 중...";
    
    document.getElementById("fuzz-body").value = fuzz.fuzzed_body || "(없음)";
    document.getElementById("fuzz-response").value = fuzz.response_body || "(없음)";
    
    // 선택된 퍼징 요청의 취약점 분석 결과 조회
    try {
        const res = await fetch(`/api/fuzzed_request/${fuzz.id}/vulnerabilities`);
        const data = await res.json();
        
        // 로딩 상태 제거
        analysisResult.classList.remove("loading");
        
        if (data.vulnerability_results && data.vulnerability_results.length > 0) {
            let resultText = `🔍 퍼징 요청 [${fuzz.scanner}] 분석 결과:\n`;
            resultText += `${'='.repeat(50)}\n\n`;
            
            const vuln = data.vulnerability_results[0]; // 1대1 매칭이므로 첫 번째(유일한) 결과
            
            // 박스 형태로 고정 정보 표시
            resultText += `════════════════════════════════════════════════════════════════\n`;
            resultText += `                           취약점 정보\n`;
            resultText += `════════════════════════════════════════════════════════════════\n`;
            resultText += `취약점      : ${vuln.vulnerability_name}\n`;
            resultText += `도메인      : ${vuln.domain}\n`;
            resultText += `엔드포인트  : ${vuln.endpoint}\n`;
            resultText += `메소드      : ${vuln.method}\n`;
            
            if (vuln.parameter) {
                resultText += `파라미터    : ${vuln.parameter}\n`;
            }
            if (vuln.payload) {
                resultText += `페이로드    : ${vuln.payload}\n`;
            }
            
            resultText += `════════════════════════════════════════════════════════════════\n\n`;
            
            if (vuln.extra) {
                resultText += `추가 정보:\n${JSON.stringify(vuln.extra, null, 2)}\n`;
            }
            
            analysisResult.value = resultText;
        }
    } catch (err) {
        console.error("취약점 분석 결과 조회 오류:", err);
        analysisResult.classList.remove("loading");
        analysisResult.value = "❌ 분석 결과 조회 중 오류가 발생했습니다.\n\n네트워크 연결을 확인하고 다시 시도해주세요.";
        analysisResult.className = '';
    }
}

function clearAll() {
    const titleDiv = document.getElementById("original-request-title");
    if (titleDiv) {
        titleDiv.textContent = "📦 원본 요청 목록";
    }
    
    const fuzzTitleDiv = document.getElementById("fuzz-request-title");
    if (fuzzTitleDiv) {
        fuzzTitleDiv.textContent = "📨 퍼징 요청 선택";
    }
    
    document.getElementById("request-body").value = "";
    document.getElementById("response-body").value = "";
    document.getElementById("fuzz-request-list").innerHTML = "";
    document.getElementById("fuzz-body").value = "";
    document.getElementById("fuzz-response").value = "";
    document.getElementById("analysis-result").value = "";
}

window.addEventListener("DOMContentLoaded", () => {
    fetchRequests();
    startTimer();
});
