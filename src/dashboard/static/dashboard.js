const refreshInterval = 10;
let remainingTime = refreshInterval;
let currentRequestId = null;

function updateTimerDisplay() {
    const timerSpan = document.getElementById("refresh-timer");
    if (timerSpan) {
        timerSpan.textContent = `⏱️ 다음 새로고침까지: ${remainingTime}초`;
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
        listDiv.innerHTML = "";

        if (data.length === 0) {
            listDiv.innerHTML = "<p>요청 없음</p>";
            clearAll();
            return;
        }

        data.forEach(req => {
            const radio = document.createElement("input");
            radio.type = "radio";
            radio.name = "request";
            radio.value = req.id;
            if (req.id === currentRequestId) radio.checked = true;

            radio.addEventListener("change", () => {
                currentRequestId = req.id;
                loadRequestDetail(req.id);
            });

            const label = document.createElement("label");
            label.appendChild(radio);
            label.append(` [${req.method}] ${req.url}`);

            const div = document.createElement("div");
            div.classList.add("request-item");
            div.appendChild(label);

            listDiv.appendChild(div);
        });

        // 선택된 요청이 목록에 없으면 초기화
        if (currentRequestId && !data.some(r => r.id === currentRequestId)) {
            currentRequestId = null;
            clearAll();
        }

    } catch (err) {
        console.error("요청 목록 오류:", err);
    }
}

async function loadRequestDetail(requestId) {
    try {
        const res = await fetch(`/api/request/${requestId}`);
        const data = await res.json();

        document.getElementById("request-body").value = data.request_body || "(없음)";
        document.getElementById("response-body").value = data.response_body || "(없음)";

        const fuzzSelect = document.getElementById("fuzz-select");
        fuzzSelect.innerHTML = "";
        data.fuzzing.forEach((fuzz, idx) => {
            const option = document.createElement("option");
            option.value = idx;
            option.textContent = `[${fuzz.scanner}] ${fuzz.method} ${fuzz.payload}`;
            fuzzSelect.appendChild(option);
        });

        if (data.fuzzing.length > 0) {
            updateFuzzDetail(data.fuzzing[0]);
            fuzzSelect.onchange = (e) => {
                updateFuzzDetail(data.fuzzing[e.target.value]);
            };
        } else {
            document.getElementById("fuzz-body").value = "(퍼징 요청 없음)";
            document.getElementById("fuzz-response").value = "(퍼징 응답 없음)";
            document.getElementById("analysis-result").value = "분석 결과 없음";
        }
    } catch (err) {
        console.error("요청 상세 불러오기 오류:", err);
        clearAll();
    }
}

function updateFuzzDetail(fuzz) {
    document.getElementById("fuzz-body").value = fuzz.fuzzed_body || "(없음)";
    document.getElementById("fuzz-response").value = fuzz.response_body || "(없음)";
    document.getElementById("analysis-result").value = "분석 결과 없음 (샘플)";
}

function clearAll() {
    document.getElementById("request-body").value = "";
    document.getElementById("response-body").value = "";
    document.getElementById("fuzz-select").innerHTML = "";
    document.getElementById("fuzz-body").value = "";
    document.getElementById("fuzz-response").value = "";
    document.getElementById("analysis-result").value = "";
}

window.addEventListener("DOMContentLoaded", () => {
    fetchRequests();
    startTimer();
});
