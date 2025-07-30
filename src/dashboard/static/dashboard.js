const refreshInterval = 10;
let remainingTime = refreshInterval;
let currentRequestId = null;
let showOnlyFuzzed = false; // 퍼징된 요청만 표시할지 여부
let showOnlyVulnerable = false; // 취약점이 있는 퍼징 요청만 표시할지 여부
let selectedScanner = ""; // 선택된 스캐너 종류

// 취약점 상태 캐시 (성능 최적화 및 중복 호출 방지)
const vulnerabilityCache = new Map();
const CACHE_DURATION = 3000; // 5초 캐시

// 스캐너별 랜덤 색상 매핑
const scannerColorMap = {};
function getRandomColor() {
    const hue = Math.floor(Math.random() * 360);
    return `hsl(${hue}, 90%, 50%)`;
}


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
            
            // 현재 선택된 요청이 있으면 퍼징 요청 목록도 갱신
            if (currentRequestId) {
                refreshFuzzingListIcons();
            }
            
            // 캐시 정리 (5분마다)
            if (remainingTime % 300 === 0) {
                clearVulnerabilityCache();
            }
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

        // 필터링 적용
        const filteredData = showOnlyFuzzed ? data.filter(req => req.has_fuzzing) : data;

        if (filteredData.length === 0 && showOnlyFuzzed) {
            listDiv.innerHTML = "<p style='text-align: center; color: #7f8c8d; padding: 20px;'>🔍 퍼징된 요청이 없습니다.<br>퍼징이 완료될 때까지 기다려주세요.</p>";
            titleDiv.textContent = "📦 원본 요청 목록";
            clearAll();
            return;
        }

        // 섹션 제목에 개수 표시
        const countSpan = document.createElement("span");
        countSpan.style.color = "#7f8c8d";
        countSpan.style.fontSize = "12px";
        countSpan.style.fontWeight = "normal";
        countSpan.style.marginLeft = "6px";
        countSpan.textContent = showOnlyFuzzed 
            ? ` (${filteredData.length}/${data.length}개)`
            : ` (${data.length}개)`;
        
        titleDiv.textContent = "📦 원본 요청 목록 ";
        titleDiv.appendChild(countSpan);

        filteredData.forEach((req, index) => {
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
            methodSpan.className = "bracket-label";
            methodSpan.style.color = methodColor;
            methodSpan.style.width = "50px";
            methodSpan.textContent = req.method;

            const urlSpan = document.createElement("span");
            urlSpan.style.marginLeft = "8px";
            urlSpan.textContent = req.url;
            
            // 전체 URL이 있으면 툴팁으로 표시
            if (req.full_url && req.full_url !== req.url) {
                urlSpan.title = req.full_url;
                urlSpan.style.cursor = "help";
            }

            // content에 안전하게 추가
            content.appendChild(methodSpan);
            content.appendChild(urlSpan);

            // 퍼징 요청이 있는 경우 표시
            if (req.has_fuzzing) {
                const fuzzingIcon = document.createElement("span");
                fuzzingIcon.style.marginLeft = "auto";
                fuzzingIcon.style.fontSize = "14px";
                fuzzingIcon.style.color = "#27ae60";
                fuzzingIcon.textContent = "🚨";
                fuzzingIcon.title = "퍼징 테스트 완료";
                content.appendChild(fuzzingIcon);
            }

            div.appendChild(content);
            listDiv.appendChild(div);
        });

        // 선택된 요청이 필터링된 목록에 없으면 초기화
        if (currentRequestId && !filteredData.some(r => r.id === currentRequestId)) {
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

function updateScannerOptions(fuzzingData) {
    const scannerSelect = document.getElementById("scanner-filter");
    const currentScanner = scannerSelect.value;
    
    // 기존 옵션 제거 (첫 번째 "전체 스캐너" 옵션 제외)
    while (scannerSelect.children.length > 1) {
        scannerSelect.removeChild(scannerSelect.lastChild);
    }
    
    // 스캐너 목록 추출
    const scanners = [...new Set(fuzzingData.map(fuzz => fuzz.scanner))].sort();
    
    scanners.forEach(scanner => {
        const option = document.createElement("option");
        option.value = scanner;
        option.textContent = scanner.toUpperCase();
        scannerSelect.appendChild(option);
    });
    
    // 이전 선택값 복원 (가능한 경우)
    if (scanners.includes(currentScanner)) {
        scannerSelect.value = currentScanner;
    }
}

async function filterFuzzingData(fuzzingData) {
    const filteredData = [];
    
    for (const fuzz of fuzzingData) {
        // 스캐너 필터 적용
        if (selectedScanner && fuzz.scanner !== selectedScanner) {
            continue;
        }
        
        // 취약점 필터 적용 (통합 쿼리에서 이미 vuln_count 제공)
        if (showOnlyVulnerable) {
            if (!fuzz.vuln_count || fuzz.vuln_count === 0) {
                continue;
            }
        }
        
        filteredData.push(fuzz);
    }
    
    return filteredData;
}

async function checkVulnerabilitiesBatch(fuzzIds) {
    const now = Date.now();
    const uncachedIds = [];
    const results = {};
    
    // 캐시에서 먼저 확인
    for (const fuzzId of fuzzIds) {
        const cacheKey = `vuln_${fuzzId}`;
        if (vulnerabilityCache.has(cacheKey)) {
            const cached = vulnerabilityCache.get(cacheKey);
            
            // 취약점이 있는 경우는 영구 캐시 (시간 체크 안함)
            if (cached.hasVulnerability) {
                results[fuzzId] = true;
                continue;
            }
            
            // 취약점이 없는 경우만 캐시 시간 체크
            if (now - cached.timestamp < CACHE_DURATION) {
                results[fuzzId] = false;
                continue;
            }
        }
        uncachedIds.push(fuzzId);
    }
    
    // 캐시되지 않은 ID들을 배치로 조회
    if (uncachedIds.length > 0) {
        try {
            const vulnRes = await fetch('/api/vulnerabilities/batch', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ fuzz_ids: uncachedIds })
            });
            
            if (!vulnRes.ok) {
                throw new Error(`HTTP ${vulnRes.status}: ${vulnRes.statusText}`);
            }
            
            const vulnData = await vulnRes.json();
            
            // 결과를 캐시에 저장하고 반환 데이터에 추가
            for (const fuzzId of uncachedIds) {
                const vulnInfo = vulnData.vulnerabilities[fuzzId];
                const hasVulnerability = vulnInfo && vulnInfo.count > 0;
                
                // 캐시에 저장 (취약점이 있으면 영구, 없으면 5초)
                vulnerabilityCache.set(`vuln_${fuzzId}`, {
                    hasVulnerability,
                    timestamp: hasVulnerability ? 0 : now, // 취약점 있으면 timestamp 0 (영구)
                    permanent: hasVulnerability // 영구 캐시 표시
                });
                
                results[fuzzId] = hasVulnerability;
            }
            
        } catch (err) {
            console.error(`배치 취약점 확인 오류:`, err);
            // 오류 발생 시 uncached ID들은 false로 설정
            for (const fuzzId of uncachedIds) {
                results[fuzzId] = false;
            }
        }
    }
    
    return results;
}

async function checkVulnerabilityStatus(fuzzId) {
    const results = await checkVulnerabilitiesBatch([fuzzId]);
    return results[fuzzId] || false;
}

function createVulnerabilityIcon() {
    const vulnerabilityIcon = document.createElement("span");
    vulnerabilityIcon.style.marginLeft = "auto";
    vulnerabilityIcon.style.fontSize = "14px";
    vulnerabilityIcon.style.color = "#e74c3c";
    vulnerabilityIcon.textContent = "🚨";
    vulnerabilityIcon.title = "취약점 발견";
    vulnerabilityIcon.className = "vulnerability-icon";
    return vulnerabilityIcon;
}

async function updateItemVulnerabilityIcon(fuzzId, hasVulnerability = null) {
    try {
        // 취약점 상태가 제공되지 않은 경우 확인
        if (hasVulnerability === null) {
            hasVulnerability = await checkVulnerabilityStatus(fuzzId);
        }
        
        // DOM 요소 찾기 (최대 3번 재시도)
        let item = null;
        let retries = 3;
        
        while (!item && retries > 0) {
            item = document.querySelector(`#fuzz-request-list .request-item[data-fuzz-id="${fuzzId}"]`);
            if (!item) {
                await new Promise(resolve => setTimeout(resolve, 100)); // 100ms 대기
                retries--;
            }
        }
        
        if (!item) {
            console.warn(`퍼징 요청 ${fuzzId}에 대한 DOM 요소를 찾을 수 없습니다.`);
            return;
        }
        
        const content = item.querySelector('.request-item-content');
        if (!content) {
            console.warn(`퍼징 요청 ${fuzzId}의 content 요소를 찾을 수 없습니다.`);
            return;
        }
        
        // 기존 취약점 아이콘 확인
        const existingIcon = content.querySelector('.vulnerability-icon, span[title="취약점 발견"]');
        const hasExistingIcon = !!existingIcon;
        
        console.log(`🎯 퍼징 요청 ${fuzzId}: hasVulnerability=${hasVulnerability}, hasExistingIcon=${hasExistingIcon}`);
        
        // 상태가 변경된 경우에만 DOM 조작
        if (hasVulnerability && !hasExistingIcon) {
            // 취약점이 있는데 아이콘이 없는 경우 → 아이콘 추가
            const vulnerabilityIcon = createVulnerabilityIcon();
            content.appendChild(vulnerabilityIcon);
            console.log(`✅ 퍼징 요청 ${fuzzId}에 취약점 아이콘 추가`);
        } else if (!hasVulnerability && hasExistingIcon) {
            // 취약점이 없는데 아이콘이 있는 경우 → 아이콘 제거
            existingIcon.remove();
            console.log(`❌ 퍼징 요청 ${fuzzId}의 취약점 아이콘 제거`);
        } else {
            // 상태 변경 없음
            if (hasVulnerability && hasExistingIcon) {
                console.log(`🔒 퍼징 요청 ${fuzzId}: 취약점 아이콘 유지 (이미 존재)`);
            } else {
                console.log(`⚪ 퍼징 요청 ${fuzzId}: 아이콘 없음 유지 (취약점 없음)`);
            }
        }
        
    } catch (err) {
        console.error(`퍼징 요청 ${fuzzId} 아이콘 업데이트 오류:`, err);
    }
}

async function addVulnerabilityIconsToList(fuzzingData) {
    try {
        // DOM이 완전히 렌더링될 때까지 짧은 지연
        await new Promise(resolve => setTimeout(resolve, 50));
        
        // 통합 쿼리에서 vuln_count가 제공되는 경우 직접 사용
        const hasVulnCountData = fuzzingData.length > 0 && fuzzingData[0].hasOwnProperty('vuln_count');
        
        console.log(`🔍 아이콘 추가 시작: ${fuzzingData.length}개 퍼징 요청, hasVulnCountData: ${hasVulnCountData}`);
        
        if (hasVulnCountData) {
            // 이미 취약점 개수 정보가 있는 경우 (통합 쿼리 사용)
            for (const fuzz of fuzzingData) {
                const hasVulnerability = fuzz.vuln_count > 0;
                const vulnArrayLength = fuzz.vulnerabilities ? fuzz.vulnerabilities.length : 0;
                
                console.log(`📊 퍼징 요청 ID ${fuzz.id}: vuln_count=${fuzz.vuln_count}, vulnerabilities_length=${vulnArrayLength}, hasVulnerability=${hasVulnerability}`);
                
                await updateItemVulnerabilityIcon(fuzz.id, hasVulnerability);
            }
            console.log(`퍼징 요청 ${fuzzingData.length}개의 취약점 아이콘 직접 업데이트 완료`);
        } else {
            // 개별 API 호출이 필요한 경우 (기존 API 사용)
            const fuzzIds = fuzzingData.map(fuzz => fuzz.id);
            const vulnerabilityResults = await checkVulnerabilitiesBatch(fuzzIds);
            
            for (const fuzz of fuzzingData) {
                const hasVulnerability = vulnerabilityResults[fuzz.id] || false;
                console.log(`📊 퍼징 요청 ID ${fuzz.id}: 배치 결과=${hasVulnerability}`);
                await updateItemVulnerabilityIcon(fuzz.id, hasVulnerability);
            }
            console.log(`퍼징 요청 ${fuzzingData.length}개의 취약점 아이콘 배치 업데이트 완료`);
        }
        
    } catch (err) {
        console.error("취약점 아이콘 일괄 추가 오류:", err);
    }
}

async function refreshFuzzingListIcons() {
    try {
        // 현재 표시된 퍼징 요청 항목들을 가져옴
        const fuzzItems = document.querySelectorAll("#fuzz-request-list .request-item");
        const fuzzIds = Array.from(fuzzItems).map(item => item.getAttribute("data-fuzz-id")).filter(id => id);
        
        if (fuzzIds.length === 0) {
            console.log("갱신할 퍼징 요청이 없습니다.");
            return;
        }
        
        console.log(`${fuzzIds.length}개 퍼징 요청의 취약점 아이콘을 배치 갱신합니다.`);
        
        // 취약점이 없는 경우만 캐시 무효화 (취약점이 있으면 영구 보존)
        fuzzIds.forEach(fuzzId => {
            const cacheKey = `vuln_${fuzzId}`;
            if (vulnerabilityCache.has(cacheKey)) {
                const cached = vulnerabilityCache.get(cacheKey);
                // 취약점이 있는 경우 캐시를 삭제하지 않음 (영구 보존)
                if (!cached.hasVulnerability) {
                    vulnerabilityCache.delete(cacheKey);
                }
            }
        });
        
        // 배치로 모든 취약점 상태를 한 번에 확인
        const vulnerabilityResults = await checkVulnerabilitiesBatch(fuzzIds);
        
        // 각 항목의 아이콘을 순차적으로 업데이트
        for (const fuzzId of fuzzIds) {
            const hasVulnerability = vulnerabilityResults[fuzzId] || false;
            await updateItemVulnerabilityIcon(fuzzId, hasVulnerability);
        }
        
        console.log("퍼징 요청 취약점 아이콘 배치 갱신 완료");
    } catch (err) {
        console.error("퍼징 목록 아이콘 갱신 오류:", err);
    }
}

async function loadRequestDetail(requestId) {
    try {
        // 통합 쿼리 API 사용 (3개 쿼리 → 1개 쿼리 최적화)
        const res = await fetch(`/api/request/${requestId}/optimized`);
        const data = await res.json();

        // 완전한 HTTP 요청 정보 구성
        let requestText = "";
        if (data.request) {
            const req = data.request;
            
            // 요청 라인 구성
            const queryString = Object.keys(req.query_params || {}).length > 0 
                ? '?' + Object.entries(req.query_params).map(([k, v]) => `${k}=${v}`).join('&')
                : '';
            
            requestText += `${req.method || ''} ${req.path || '/'}${queryString} ${req.http_version || ''}\n`;
            
            // Host 헤더 추가 (일반적으로 필수)
            if (req.domain) {
                requestText += `Host: ${req.domain}\n`;
            }
            
            // 헤더 추가 (중복 방지를 위해 필터링)
            const processedHeaders = new Set();
            Object.entries(req.headers || {}).forEach(([key, value]) => {
                if (key && value) {
                    const normalizedKey = key.toLowerCase();
                    if (!processedHeaders.has(normalizedKey)) {
                        requestText += `${key}: ${value}\n`;
                        processedHeaders.add(normalizedKey);
                    }
                }
            });
            
            // 요청 메타데이터 추가 (헤더에 없는 경우만)
            if (req.content_type && !processedHeaders.has('content-type')) {
                requestText += `Content-Type: ${req.content_type}`;
                if (req.charset) {
                    requestText += `; charset=${req.charset}`;
                }
                requestText += '\n';
            }
            if (req.content_length && !processedHeaders.has('content-length')) {
                requestText += `Content-Length: ${req.content_length}\n`;
            }
            if (req.content_encoding && !processedHeaders.has('content-encoding')) {
                requestText += `Content-Encoding: ${req.content_encoding}\n`;
            }
            
            // 빈 줄 추가 (헤더와 바디 구분)
            requestText += '\n';
            
            // 요청 바디 추가
            if (req.body) {
                requestText += req.body;
            }
        }

        // 완전한 HTTP 응답 정보 구성
        let responseText = "";
        if (data.response) {
            const resp = data.response;
            
            // 응답 라인 구성
            responseText += `${resp.http_version || ''} ${resp.status_code || ''}\n`;
            
            // 헤더 추가 (중복 방지를 위해 필터링)
            const processedHeaders = new Set();
            Object.entries(resp.headers || {}).forEach(([key, value]) => {
                if (key && value) {
                    const normalizedKey = key.toLowerCase();
                    if (!processedHeaders.has(normalizedKey)) {
                        responseText += `${key}: ${value}\n`;
                        processedHeaders.add(normalizedKey);
                    }
                }
            });
            
            // 응답 메타데이터 추가 (헤더에 없는 경우만)
            if (resp.content_type && !processedHeaders.has('content-type')) {
                responseText += `Content-Type: ${resp.content_type}`;
                if (resp.charset) {
                    responseText += `; charset=${resp.charset}`;
                }
                responseText += '\n';
            }
            if (resp.content_length && !processedHeaders.has('content-length')) {
                responseText += `Content-Length: ${resp.content_length}\n`;
            }
            if (resp.content_encoding && !processedHeaders.has('content-encoding')) {
                responseText += `Content-Encoding: ${resp.content_encoding}\n`;
            }
            
            // 빈 줄 추가 (헤더와 바디 구분)
            responseText += '\n';
            
            // 응답 바디 추가
            if (resp.body) {
                responseText += resp.body;
            }
        }

        // 원본 요청/응답 텍스트를 전역 변수에 저장
        window.originalRequestText = requestText;
        window.originalResponseText = responseText;
        
        // 원본 요청/응답 표시
        document.getElementById("request-body-container").textContent = requestText;
        document.getElementById("response-body-container").textContent = responseText;

        const fuzzListDiv = document.getElementById("fuzz-request-list");
        const fuzzTitleDiv = document.getElementById("fuzz-request-title");
        fuzzListDiv.innerHTML = "";

        if (data.fuzzing.length > 0) {
            // 스캐너 옵션 업데이트
            updateScannerOptions(data.fuzzing);
            
            // 필터링 적용
            const filteredData = await filterFuzzingData(data.fuzzing);
            
            // 제목에 개수 표시
            const fuzzCountSpan = document.createElement("span");
            fuzzCountSpan.style.color = "#7f8c8d";
            fuzzCountSpan.style.fontSize = "12px";
            fuzzCountSpan.style.fontWeight = "normal";
            fuzzCountSpan.style.marginLeft = "6px";
            
            if (showOnlyVulnerable || selectedScanner) {
                fuzzCountSpan.textContent = `(${filteredData.length}/${data.fuzzing.length}개)`;
            } else {
                fuzzCountSpan.textContent = `(${data.fuzzing.length}개)`;
            }
            
            fuzzTitleDiv.textContent = "📨 퍼징 요청 목록 ";
            fuzzTitleDiv.appendChild(fuzzCountSpan);

            if (filteredData.length === 0) {
                fuzzListDiv.innerHTML = "<p style='text-align: center; color: #7f8c8d; padding: 20px;'>🔍 필터 조건에 맞는 퍼징 요청이 없습니다.</p>";
                
                // 빈 값으로 초기화 및 화면 갱신
                window.fuzzRequestText = "";
                window.fuzzResponseText = "";
                if (document.getElementById("analysis-result"))
                    document.getElementById("analysis-result").innerHTML = "";
                
                updateFuzzDisplay();
                updateEmptyPlaceholder();
                return;
            }

            // 모든 퍼징 요청 항목을 순차적으로 렌더링
            for (let idx = 0; idx < filteredData.length; idx++) {
                const fuzz = filteredData[idx];
                const div = document.createElement("div");
                div.classList.add("request-item");
                div.setAttribute("data-fuzz-index", idx);
                div.setAttribute("data-fuzz-id", fuzz.id);
                
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
                    
                    // 각 퍼징 요청에 취약점이 포함되어 있음
                    await updateFuzzDetail(filteredData[idx]);
                });

                const content = document.createElement("div");
                content.classList.add("request-item-content");

                // 스캐너별 색상 지정 (랜덤)
                if (!scannerColorMap[fuzz.scanner]) {
                    scannerColorMap[fuzz.scanner] = getRandomColor();
                }
                const scannerColor = scannerColorMap[fuzz.scanner];

                // 페이로드 길이 제한 (너무 길면 줄임)
                const displayPayload = fuzz.payload.length > 50 
                    ? fuzz.payload.substring(0, 50) + '...' 
                    : fuzz.payload;

                // HTML 안전하게 요소 생성
                const scannerSpan = document.createElement("span");
                scannerSpan.className = "bracket-label";
                scannerSpan.style.color = scannerColor;
                scannerSpan.style.width = "120px";
                scannerSpan.textContent = fuzz.scanner;

                const payloadSpan = document.createElement("span");
                payloadSpan.style.marginLeft = "8px";
                payloadSpan.textContent = displayPayload;

                // content에 안전하게 추가
                content.appendChild(scannerSpan);
                content.appendChild(payloadSpan);

                div.appendChild(content);
                fuzzListDiv.appendChild(div);
            }
            
            // 모든 DOM 요소가 추가된 후 취약점 아이콘을 일괄 처리
            await addVulnerabilityIconsToList(filteredData);

            // 첫 번째 퍼징 요청 자동 로드
            await updateFuzzDetail(filteredData[0]);
        } else {
            fuzzTitleDiv.textContent = "📨 퍼징 요청 목록";
            fuzzListDiv.innerHTML = "<p style='text-align: center; color: #7f8c8d; padding: 20px;'>🔍 퍼징 대상이 아닙니다.</p>";
            
            // 빈 값으로 초기화 및 화면 갱신
            window.fuzzRequestText = "";
            window.fuzzResponseText = "";
            if (document.getElementById("analysis-result"))
                document.getElementById("analysis-result").innerHTML = "";
            
            updateFuzzDisplay();
            updateEmptyPlaceholder();
        }
    } catch (err) {
        console.error("요청 상세 불러오기 오류:", err);
        clearAll();
    }
}


async function updateFuzzDetail(fuzz, vulnerabilityData = null) {
    // 로딩 상태 표시
    const analysisResult = document.getElementById("analysis-result");
    analysisResult.classList.add("loading");
    analysisResult.classList.remove("empty-placeholder");
    analysisResult.innerHTML = "취약점이 탐지되지 않았습니다.";
    
    try {
        // 퍼징 요청의 헤더 정보를 가져와서 완전한 HTTP 메시지로 구성
        const headersRes = await fetch(`/api/fuzz-request/${fuzz.id}/headers`);
        const headersData = await headersRes.json();
        
        // 완전한 퍼징 요청 정보 구성
        let fuzzRequestText = "";
        
        // 쿼리 파라미터 구성
        const queryString = Object.keys(headersData.query_params || {}).length > 0 
            ? '?' + Object.entries(headersData.query_params).map(([k, v]) => `${k}=${v}`).join('&')
            : '';
        
        // 요청 라인 구성
        fuzzRequestText += `${fuzz.method || ''} ${fuzz.fuzz_request_path || '/'}${queryString || ''} ${fuzz.fuzz_request_http_version || ''}\n`;
        
        // Host 헤더 추가
        if (fuzz.fuzz_request_domain) {
            fuzzRequestText += `Host: ${fuzz.fuzz_request_domain}\n`;
        }
        
        // 헤더 추가 (중복 방지)
        const processedHeaders = new Set();
        Object.entries(headersData.request_headers || {}).forEach(([key, value]) => {
            if (key && value) {
                const normalizedKey = key.toLowerCase();
                if (!processedHeaders.has(normalizedKey)) {
                    fuzzRequestText += `${key}: ${value}\n`;
                    processedHeaders.add(normalizedKey);
                }
            }
        });
        
        // 요청 메타데이터 추가 (헤더에 없는 경우만)
        if (fuzz.fuzz_request_content_type && !processedHeaders.has('content-type')) {
            fuzzRequestText += `Content-Type: ${fuzz.fuzz_request_content_type}`;
            if (fuzz.fuzz_request_charset) {
                fuzzRequestText += `; charset=${fuzz.fuzz_request_charset}`;
            }
            fuzzRequestText += '\n';
        }
        if (fuzz.fuzz_request_content_length && !processedHeaders.has('content-length')) {
            fuzzRequestText += `Content-Length: ${fuzz.fuzz_request_content_length}\n`;
        }
        if (fuzz.fuzz_request_content_encoding && !processedHeaders.has('content-encoding')) {
            fuzzRequestText += `Content-Encoding: ${fuzz.fuzz_request_content_encoding}\n`;
        }
        
        // 빈 줄 추가 (헤더와 바디 구분)
        fuzzRequestText += '\n';
        
        // 요청 바디 추가
        if (fuzz.fuzzed_body) {
            fuzzRequestText += fuzz.fuzzed_body;
        }
        
        // 완전한 퍼징 응답 정보 구성
        let fuzzResponseText = "";
        
        // 응답 라인 구성
        fuzzResponseText += `${fuzz.fuzz_response_http_version || ''} ${fuzz.fuzz_response_status_code || ''}\n`;
        
        // 헤더 추가 (중복 방지)
        const processedResponseHeaders = new Set();
        Object.entries(headersData.response_headers || {}).forEach(([key, value]) => {
            if (key && value) {
                const normalizedKey = key.toLowerCase();
                if (!processedResponseHeaders.has(normalizedKey)) {
                    fuzzResponseText += `${key}: ${value}\n`;
                    processedResponseHeaders.add(normalizedKey);
                }
            }
        });
        
        // 응답 바디가 있을 때만 헤더 메타데이터 추가
        if (fuzz.response_body) {
            if (fuzz.fuzz_response_content_type && !processedResponseHeaders.has('content-type')) {
                fuzzResponseText += `Content-Type: ${fuzz.fuzz_response_content_type}`;
                if (fuzz.fuzz_response_charset) {
                    fuzzResponseText += `; charset=${fuzz.fuzz_response_charset}`;
                }
                fuzzResponseText += '\n';
            }
            if (fuzz.fuzz_response_content_length && !processedResponseHeaders.has('content-length')) {
                fuzzResponseText += `Content-Length: ${fuzz.fuzz_response_content_length}\n`;
            }
            if (fuzz.fuzz_response_content_encoding && !processedResponseHeaders.has('content-encoding')) {
                fuzzResponseText += `Content-Encoding: ${fuzz.fuzz_response_content_encoding}\n`;
            }
            
            // 빈 줄 추가 (헤더와 바디 구분)
            fuzzResponseText += '\n';
            
            // 응답 바디 추가
            fuzzResponseText += fuzz.response_body;
        }
        
        // 퍼징 요청/응답 텍스트를 전역 변수에 저장
        window.fuzzRequestText = fuzzRequestText;
        window.fuzzResponseText = fuzzResponseText;
        
        // 퍼징 요청/응답 표시 (diff 모드에 따라)
        updateFuzzDisplay();
        
    } catch (err) {
        console.error("퍼징 요청 헤더 정보 조회 오류:", err);
        // 오류 발생 시 기본값 사용
        window.fuzzRequestText = fuzz.fuzzed_body || "";
        window.fuzzResponseText = fuzz.response_body || "";
        updateFuzzDisplay();
    }
    
    updateEmptyPlaceholder();
    
    try {
        let vulnResults = [];
        
        // 통합 쿼리에서 각 퍼징 요청에 취약점이 포함됨 (1:1 관계 보장)
        if (fuzz.vulnerabilities && Array.isArray(fuzz.vulnerabilities)) {
            vulnResults = fuzz.vulnerabilities;
        }
        
        // 로딩 상태 제거
        analysisResult.classList.remove("loading");
        
        if (vulnResults.length > 0) {
            let resultHTML = `<div class="vulnerability-analysis">`;
            
            vulnResults.forEach((vuln, index) => {
                resultHTML += `<div class="vulnerability-card">`;
                resultHTML += `<div class="vulnerability-header">`;
                resultHTML += `<span class="vulnerability-type">${vuln.vulnerability_name.toUpperCase()}</span>`;
                resultHTML += `</div>`;
                
                resultHTML += `<table class="vulnerability-table">`;
                resultHTML += `<tr><td class="field-label">도메인</td><td class="field-value">${vuln.domain}</td></tr>`;
                resultHTML += `<tr><td class="field-label">요청</td><td class="field-value">${vuln.method} ${vuln.endpoint}</td></tr>`;
                
                if (vuln.parameter) {
                    resultHTML += `<tr><td class="field-label">파라미터</td><td class="field-value">${vuln.parameter}</td></tr>`;
                }
                
                if (vuln.payload) {
                    resultHTML += `<tr><td class="field-label">페이로드</td><td class="field-value">${escapeHtml(vuln.payload)}</td></tr>`;
                }
                resultHTML += `</table>`;
                
                if (vuln.extra) {
                    resultHTML += `<div class="extra-info">`;
                    resultHTML += `<h4>추가 정보</h4>`;
                    resultHTML += `<pre class="json-highlight"><code class="language-json">${escapeHtml(JSON.stringify(vuln.extra, null, 2))}</code></pre>`;
                    resultHTML += `</div>`;
                }
                
                resultHTML += `</div>`;
            });
            
            resultHTML += `</div>`;
            
            // HTML로 직접 설정
            analysisResult.innerHTML = resultHTML;
            
            
            // Prism.js 하이라이팅 적용
            setTimeout(() => {
                const codeElements = analysisResult.querySelectorAll('code.language-json');
                codeElements.forEach(code => {
                    Prism.highlightElement(code);
                });
            }, 100);
        } else {
            analysisResult.innerHTML = "";
        }
    } catch (err) {
        console.error("취약점 분석 결과 조회 오류:", err);
        analysisResult.classList.remove("loading");
        analysisResult.innerHTML = "❌ 분석 결과 조회 중 오류가 발생했습니다.\n\n네트워크 연결을 확인하고 다시 시도해주세요.";
        analysisResult.className = '';
    }
    
    updateEmptyPlaceholder();
}

function updateEmptyPlaceholder() {
    // div 요소들 처리
    const divElements = ['fuzz-body-container', 'fuzz-response-container'];
    divElements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            if (element.textContent.trim() === '' || element.textContent.includes('🔍 퍼징 요청을 선택하면')) {
                element.classList.add('empty-placeholder');
            } else {
                element.classList.remove('empty-placeholder');
            }
        }
    });
    
    // div 요소 처리 (analysis-result)
    const analysisElement = document.getElementById('analysis-result');
    if (analysisElement) {
        if (analysisElement.innerHTML.trim() === '') {
            analysisElement.classList.add('empty-placeholder');
        } else {
            analysisElement.classList.remove('empty-placeholder');
        }
    }
}

function toggleFilter() {
    showOnlyFuzzed = !showOnlyFuzzed;
    const filterBtn = document.getElementById("filter-toggle");
    
    if (showOnlyFuzzed) {
        filterBtn.textContent = "🚨 퍼징만";
        filterBtn.classList.add("active");
        filterBtn.title = "전체 요청 보기";
    } else {
        filterBtn.textContent = "🔍 전체";
        filterBtn.classList.remove("active");
        filterBtn.title = "퍼징 요청이 있는 항목만 표시";
    }
    
    // 목록 새로고침
    fetchRequests();
}

async function toggleVulnFilter() {
    showOnlyVulnerable = !showOnlyVulnerable;
    const filterBtn = document.getElementById("vuln-filter-toggle");
    
    if (showOnlyVulnerable) {
        filterBtn.textContent = "🚨 취약점만";
        filterBtn.classList.add("active");
        filterBtn.title = "전체 퍼징 요청 보기";
    } else {
        filterBtn.textContent = "🔍 전체";
        filterBtn.classList.remove("active");
        filterBtn.title = "취약점이 발견된 퍼징 요청만 표시";
    }
    
    // 현재 요청 상세 새로고침
    if (currentRequestId) {
        await loadRequestDetail(currentRequestId);
    }
}

async function onScannerFilterChange() {
    const scannerSelect = document.getElementById("scanner-filter");
    selectedScanner = scannerSelect.value;
    
    // 현재 요청 상세 새로고침
    if (currentRequestId) {
        await loadRequestDetail(currentRequestId);
    }
}


function clearVulnerabilityCache() {
    const now = Date.now();
    const keysToDelete = [];
    
    for (const [key, value] of vulnerabilityCache.entries()) {
        // 영구 캐시는 삭제하지 않음
        if (value.permanent) {
            continue;
        }
        if (now - value.timestamp > CACHE_DURATION) {
            keysToDelete.push(key);
        }
    }
    
    keysToDelete.forEach(key => vulnerabilityCache.delete(key));
    console.log(`만료된 캐시 ${keysToDelete.length}개 정리 완료`);
}

function clearAll() {
    const titleDiv = document.getElementById("original-request-title");
    if (titleDiv) {
        titleDiv.textContent = "📦 원본 요청 목록";
    }
    
    const fuzzTitleDiv = document.getElementById("fuzz-request-title");
    if (fuzzTitleDiv) {
        fuzzTitleDiv.textContent = "📨 퍼징 요청 목록";
    }
    
    document.getElementById("request-body-container").textContent = "";
    document.getElementById("response-body-container").textContent = "";
    document.getElementById("fuzz-request-list").innerHTML = "";
    document.getElementById("fuzz-body-container").textContent = "";
    document.getElementById("fuzz-response-container").textContent = "";
    document.getElementById("analysis-result").innerHTML = "";
    
    // 전역 변수 초기화
    window.originalRequestText = "";
    window.originalResponseText = "";
    window.fuzzRequestText = "";
    window.fuzzResponseText = "";
    

    
    updateEmptyPlaceholder();
}

window.addEventListener("DOMContentLoaded", () => {
    // 원본 요청 필터 버튼 이벤트 설정
    const filterBtn = document.getElementById("filter-toggle");
    if (filterBtn) {
        filterBtn.addEventListener("click", toggleFilter);
    }
    
    // 퍼징 요청 취약점 필터 버튼 이벤트 설정
    const vulnFilterBtn = document.getElementById("vuln-filter-toggle");
    if (vulnFilterBtn) {
        vulnFilterBtn.addEventListener("click", async () => {
            await toggleVulnFilter();
        });
    }
    
    // 스캐너 필터 셀렉트 이벤트 설정
    const scannerFilter = document.getElementById("scanner-filter");
    if (scannerFilter) {
        scannerFilter.addEventListener("change", async () => {
            await onScannerFilterChange();
        });
    }
    
    fetchRequests();
    startTimer();
    updateEmptyPlaceholder();
    
    console.log("대시보드 초기화 완료 - DB 쿼리 최적화 및 취약점 아이콘 최적화 적용");
});

// 페이지 언로드 시 캐시 정리
window.addEventListener("beforeunload", () => {
    vulnerabilityCache.clear();
});

// Diff 관련 함수들
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function computeLCS(originalLines, modifiedLines) {
    
    const m = originalLines.length;
    const n = modifiedLines.length;
    
    // DP 테이블 생성
    const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));
    
    // LCS 길이 계산
    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            if (originalLines[i - 1] === modifiedLines[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
            }
        }
    }
    
    // LCS 역추적하여 diff 생성
    const result = [];
    let i = m, j = n;
    
    while (i > 0 || j > 0) {
        if (i > 0 && j > 0 && originalLines[i - 1] === modifiedLines[j - 1]) {
            // 같은 줄
            result.unshift({ type: 'equal', line: originalLines[i - 1] });
            i--;
            j--;
        } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
            // 추가된 줄
            result.unshift({ type: 'added', line: modifiedLines[j - 1] });
            j--;
        } else if (i > 0) {
            // 삭제된 줄
            result.unshift({ type: 'removed', line: originalLines[i - 1] });
            i--;
        }
    }
    
    return result;
}

function wordLevelDiff(originalLine, modifiedLine) {

    // path/query 구분자와 공백을 단어 분리 기준으로 사용

    const splitRegex = /([\s&=]+)/;
    const originalWords = originalLine.split(splitRegex).filter(Boolean);
    const modifiedWords = modifiedLine.split(splitRegex).filter(Boolean);
    
    const lcs = computeLCS(originalWords, modifiedWords);
    
    let result = '';
    for (const item of lcs) {
        switch (item.type) {
            case 'equal':
                result += escapeHtml(item.line);
                break;
            case 'added':
                result += `<span class="diff-added">${escapeHtml(item.line)}</span>`;
                break;
            case 'removed':
                result += `<span class="diff-removed">${escapeHtml(item.line)}</span>`;
                break;
        }
    }
    return result;
}

function requestLineDiff(originalLine, modifiedLine) {
    // HTTP 요청 라인: METHOD PATH?QUERY HTTP/1.1
    // ex: GET /AJAX/infoartist.php?id=2 HTTP/1.1
    const reqLineRegex = /^(\w+)\s+([^\s\?]+)(\?[^\s]+)?\s+(HTTP\/\d\.\d)$/;
    const origMatch = originalLine.match(reqLineRegex);
    const modMatch = modifiedLine.match(reqLineRegex);
    if (origMatch && modMatch) {
        const [, origMethod, origPath, origQuery = '', origVersion] = origMatch;
        const [, modMethod, modPath, modQuery = '', modVersion] = modMatch;
        // path가 다르면 diff 의미가 없으므로, path가 다르면 기존 방식 사용
        if (origPath !== modPath) {
            return wordLevelDiff(originalLine, modifiedLine);
        }
        // 쿼리 파라미터만 diff 적용
        let queryDiff = '';
        if (origQuery || modQuery) {
            // ?는 제외하고 비교
            queryDiff = '?' + wordLevelDiff(origQuery.slice(1) || '', modQuery.slice(1) || '');
        }
        return `${origMethod} ${origPath}${queryDiff} ${origVersion}`;
    } else {
        // HTTP 요청 라인 형식이 아니면 기존 방식 사용
        return wordLevelDiff(originalLine, modifiedLine);
    }
}

function advancedDiff(originalText, modifiedText) {
    const originalLines = originalText.split('\n');
    const modifiedLines = modifiedText.split('\n');
    
    const diffResult = computeLCS(originalLines, modifiedLines);
    
    let result = '';
    let i = 0;
    
    while (i < diffResult.length) {
        const item = diffResult[i];
        
        if (item.type === 'equal') {
            result += escapeHtml(item.line) + '\n';
            i++;
        } else if (item.type === 'removed' && i + 1 < diffResult.length && diffResult[i + 1].type === 'added') {
            // 연속된 삭제/추가는 수정으로 처리
            const removedLine = item.line;
            const addedLine = diffResult[i + 1].line;
            // 첫 줄(요청 라인)만 특수 처리
            if (i === 0) {
                result += requestLineDiff(removedLine, addedLine) + '\n';
            } else {
                // 줄의 유사도가 높으면 wordLevelDiff 적용
                const similarity = calculateSimilarity(removedLine, addedLine);
                if (similarity > 0.3) {
                    result += wordLevelDiff(removedLine, addedLine) + '\n';
                } else {
                    result += `<span class="diff-removed">${escapeHtml(removedLine)}</span>\n`;
                    result += `<span class="diff-added">${escapeHtml(addedLine)}</span>\n`;
                }
            }
            i += 2;
        } else {
            // 단순 추가 또는 삭제
            switch (item.type) {
                case 'added':
                    result += `<span class="diff-added">${escapeHtml(item.line)}</span>\n`;
                    break;
                case 'removed':
                    result += `<span class="diff-removed">${escapeHtml(item.line)}</span>\n`;
                    break;
            }
            i++;
        }
    }
    
    return result;
}

function calculateSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    
    if (longer.length === 0) {
        return 1.0;
    }
    
    const editDistance = levenshteinDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
}

function levenshteinDistance(str1, str2) {
    const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));
    
    for (let i = 0; i <= str1.length; i++) {
        matrix[0][i] = i;
    }
    
    for (let j = 0; j <= str2.length; j++) {
        matrix[j][0] = j;
    }
    
    for (let j = 1; j <= str2.length; j++) {
        for (let i = 1; i <= str1.length; i++) {
            const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
            matrix[j][i] = Math.min(
                matrix[j][i - 1] + 1,     // deletion
                matrix[j - 1][i] + 1,     // insertion
                matrix[j - 1][i - 1] + indicator // substitution
            );
        }
    }
    
    return matrix[str2.length][str1.length];
}

function updateFuzzDisplay() {
    const requestDiffToggle = document.getElementById("fuzz-request-diff-toggle");
    const responseDiffToggle = document.getElementById("fuzz-response-diff-toggle");
    
    const requestContainer = document.getElementById("fuzz-body-container");
    const responseContainer = document.getElementById("fuzz-response-container");
    
    // 퍼징 요청 표시
    if (window.fuzzRequestText !== undefined && window.fuzzRequestText !== null) {
        if (requestDiffToggle.classList.contains('active') && window.originalRequestText) {
            requestContainer.innerHTML = advancedDiff(window.originalRequestText, window.fuzzRequestText);
        } else {
            // 빈 문자열일 경우도 처리
            requestContainer.textContent = window.fuzzRequestText || "";
        }
    } else {
        requestContainer.textContent = "";
    }
    
    // 퍼징 응답 표시
    if (window.fuzzResponseText !== undefined && window.fuzzResponseText !== null) {
        if (responseDiffToggle.classList.contains('active') && window.originalResponseText) {
            responseContainer.innerHTML = advancedDiff(window.originalResponseText, window.fuzzResponseText);
        } else {
            // 빈 문자열일 경우도 처리
            responseContainer.textContent = window.fuzzResponseText || "";
        }
    } else {
        responseContainer.textContent = "";
    }
}


// JSON syntax highlighting 관련 함수들
function isJSONString(str) {
    if (!str || typeof str !== 'string') {
        return false;
    }
    
    // 빈 문자열이나 너무 짧은 문자열은 제외
    if (str.trim().length < 2) {
        return false;
    }
    
    try {
        JSON.parse(str);
        return true;
    } catch (e) {
        return false;
    }
}

function extractJSONFromText(text) {
    // 더 정확한 JSON 감지를 위한 정규식
    const jsonRegex = /(\{(?:[^{}]|(?:\{[^{}]*\}))*\}|\[(?:[^\[\]]|(?:\[[^\[\]]*\]))*\])/g;
    const matches = [];
    let match;
    
    while ((match = jsonRegex.exec(text)) !== null) {
        const jsonText = match[1];
        if (isJSONString(jsonText)) {
            matches.push({
                text: jsonText,
                start: match.index,
                end: match.index + jsonText.length,
                index: matches.length
            });
        }
    }
    
    return matches;
}

function highlightJSONInText(text) {
    const jsonBlocks = extractJSONFromText(text);
    
    if (jsonBlocks.length === 0) {
        return text;
    }
    
    let result = text;
    let offset = 0;
    
    // JSON 블록들을 역순으로 처리 (인덱스 변경 방지)
    jsonBlocks.reverse().forEach(block => {
        const start = block.start + offset;
        const end = block.end + offset;
        
        try {
            // JSON을 예쁘게 포맷팅
            const formattedJSON = JSON.stringify(JSON.parse(block.text), null, 2);
            
            // Prism.js로 하이라이팅 적용
            const highlightedJSON = Prism.highlight(formattedJSON, Prism.languages.json, 'json');
            
            // JSON 블록으로 교체
            const jsonBlock = `<div class="analysis-json-block"><pre class="json-highlight"><code class="language-json">${highlightedJSON}</code></pre></div>`;
            
            result = result.slice(0, start) + jsonBlock + result.slice(end);
            offset += jsonBlock.length - (end - start);
        } catch (e) {
            console.warn('JSON 하이라이팅 실패:', e);
        }
    });
    
    return result;
}

function updateAnalysisResultWithHighlighting(text) {
    const analysisResult = document.getElementById("analysis-result");
    
    if (!text || text.trim() === '') {
        analysisResult.innerHTML = '';
        analysisResult.classList.add('empty-placeholder');
        return;
    }
    
    // JSON 하이라이팅 적용
    const highlightedText = highlightJSONInText(text);
    
    // 하이라이팅된 내용을 div에 설정
    analysisResult.innerHTML = highlightedText;
    analysisResult.classList.remove('empty-placeholder');
    
    // Prism.js 하이라이팅이 적용된 요소들을 다시 하이라이팅
    setTimeout(() => {
        const codeElements = analysisResult.querySelectorAll('code.language-json');
        codeElements.forEach(code => {
            Prism.highlightElement(code);
        });
    }, 100);
}

// 스크롤 동기화 관련 변수
let isScrollSyncing = false;
let scrollSyncEnabled = true;

// 스크롤 동기화 함수
function syncScroll(source, target) {
    if (isScrollSyncing || !scrollSyncEnabled) return;
    
    isScrollSyncing = true;
    target.scrollTop = source.scrollTop;
    target.scrollLeft = source.scrollLeft;
    
    // 다음 프레임에서 플래그 해제
    requestAnimationFrame(() => {
        isScrollSyncing = false;
    });
}

// 스크롤 동기화 토글 함수
function toggleScrollSync() {
    scrollSyncEnabled = !scrollSyncEnabled;
    const syncButton = document.getElementById('scroll-sync-toggle');
    
    if (scrollSyncEnabled) {
        syncButton.classList.add('active');
        syncButton.title = '스크롤 동기화 비활성화';
    } else {
        syncButton.classList.remove('active');
        syncButton.title = '스크롤 동기화 활성화';
    }
}

// 스크롤 동기화 설정
function setupScrollSync() {
    const originalRequest = document.getElementById('request-body-container');
    const fuzzRequest = document.getElementById('fuzz-body-container');
    const originalResponse = document.getElementById('response-body-container');
    const fuzzResponse = document.getElementById('fuzz-response-container');
    
    // 원본 요청 ↔ 퍼징 요청 스크롤 동기화
    originalRequest.addEventListener('scroll', function() {
        syncScroll(this, fuzzRequest);
    });
    
    fuzzRequest.addEventListener('scroll', function() {
        syncScroll(this, originalRequest);
    });
    
    // 원본 응답 ↔ 퍼징 응답 스크롤 동기화
    originalResponse.addEventListener('scroll', function() {
        syncScroll(this, fuzzResponse);
    });
    
    fuzzResponse.addEventListener('scroll', function() {
        syncScroll(this, originalResponse);
    });
}

// Diff 토글 버튼 이벤트 리스너 추가
document.addEventListener('DOMContentLoaded', function() {
    // 스크롤 동기화 설정
    setupScrollSync();
    
    // 스크롤 동기화 초기 상태 설정
    const syncButton = document.getElementById('scroll-sync-toggle');
    syncButton.classList.add('active');
    syncButton.title = '스크롤 동기화 비활성화';
    
    // 스크롤 동기화 토글 버튼 이벤트
    syncButton.addEventListener('click', toggleScrollSync);
    
    // Diff 토글 버튼 이벤트
    document.getElementById('fuzz-request-diff-toggle').addEventListener('click', function() {
        this.classList.toggle('active');
        updateFuzzDisplay();
    });
    
    document.getElementById('fuzz-response-diff-toggle').addEventListener('click', function() {
        this.classList.toggle('active');
        updateFuzzDisplay();
    });
});
