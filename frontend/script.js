const logInput = document.getElementById("logInput");
const sampleBtn = document.getElementById("sampleBtn");
const analyzeBtn = document.getElementById("analyzeBtn");

const totalRequests = document.getElementById("totalRequests");
const successfulRequests = document.getElementById("successfulRequests");
const clientErrors = document.getElementById("clientErrors");
const serverErrors = document.getElementById("serverErrors");
const securityFindings = document.getElementById("securityFindings");

const statusCodes = document.getElementById("statusCodes");
const suspiciousPaths = document.getElementById("suspiciousPaths");
const unauthorizedRequests = document.getElementById("unauthorizedRequests");
const message = document.getElementById("message");


/* SAMPLE SERVER LOGS */

const sampleLogs = `192.168.1.10 - - [05/Oct/2026:10:15:01 +0000] "GET / HTTP/1.1" 200 1245
192.168.1.11 - - [05/Oct/2026:10:15:02 +0000] "GET /login HTTP/1.1" 200 2450
192.168.1.12 - - [05/Oct/2026:10:15:03 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.12 - - [05/Oct/2026:10:15:04 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.12 - - [05/Oct/2026:10:15:05 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.13 - - [05/Oct/2026:10:15:06 +0000] "GET /admin HTTP/1.1" 403 320
192.168.1.14 - - [05/Oct/2026:10:15:07 +0000] "GET /etc/passwd HTTP/1.1" 404 210
192.168.1.15 - - [05/Oct/2026:10:15:08 +0000] "GET /api/users HTTP/1.1" 200 1890
192.168.1.16 - - [05/Oct/2026:10:15:09 +0000] "GET /backup/config.php HTTP/1.1" 404 300
192.168.1.17 - - [05/Oct/2026:10:15:10 +0000] "GET /dashboard HTTP/1.1" 500 100
192.168.1.18 - - [05/Oct/2026:10:15:11 +0000] "GET / HTTP/1.1" 200 1245`;


/* LOAD SAMPLE LOGS */

sampleBtn.addEventListener("click", () => {

    logInput.value = sampleLogs;

    message.textContent = "Sample logs loaded.";
    message.className = "message success-message";

});


/* ANALYZE LOGS */

analyzeBtn.addEventListener("click", async () => {

    const logs = logInput.value.trim();

    if (!logs) {

        message.textContent = "Please enter or load server logs.";
        message.className = "message error-message";

        return;
    }

    message.textContent = "Analyzing logs...";
    message.className = "message";

    try {

        const response = await fetch("/api/analyze", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                logs: logs
            })

        });

        if (!response.ok) {
            throw new Error("Server returned an error.");
        }

        const data = await response.json();

        updateDashboard(data);

        message.textContent =
            "Log analysis completed successfully.";

        message.className =
            "message success-message";

    } catch (error) {

        console.error(error);

        message.textContent =
            "Unable to connect to the Flask backend.";

        message.className =
            "message error-message";
    }

});


/* UPDATE DASHBOARD */

function updateDashboard(data) {

    totalRequests.textContent =
        data.total_requests || 0;

    successfulRequests.textContent =
        data.successful_requests || 0;

    clientErrors.textContent =
        data.client_errors || 0;

    serverErrors.textContent =
        data.server_errors || 0;

    securityFindings.textContent =
        data.security_findings || 0;


    /* HTTP STATUS CODES */

    statusCodes.innerHTML = "";

    const codes = data.status_codes || {};

    if (Object.keys(codes).length === 0) {

        statusCodes.innerHTML =
            '<p class="empty-state">No status codes found.</p>';

    } else {

        Object.entries(codes).forEach(([code, count]) => {

            const item =
                document.createElement("div");

            item.className =
                "status-item";

            item.innerHTML = `
                <span class="status-code">
                    HTTP ${escapeHtml(code)}
                </span>

                <span class="status-count">
                    ${escapeHtml(String(count))}
                </span>
            `;

            statusCodes.appendChild(item);

        });
    }


    /* SUSPICIOUS PATHS */

    suspiciousPaths.innerHTML = "";

    const paths =
        data.suspicious_paths || [];

    if (paths.length === 0) {

        suspiciousPaths.innerHTML =
            '<p class="empty-state">No suspicious paths detected.</p>';

    } else {

        paths.forEach((finding) => {

            const item =
                document.createElement("div");

            item.className =
                "finding-item";

            item.innerHTML = `
                <div class="finding-path">
                    ${escapeHtml(finding.path)}
                </div>

                <div class="finding-details">
                    IP: ${escapeHtml(finding.ip)}
                    &nbsp; | &nbsp;
                    Reason: ${escapeHtml(finding.reason)}
                </div>
            `;

            suspiciousPaths.appendChild(item);

        });
    }


    /* REPEATED 401 REQUESTS */

    unauthorizedRequests.innerHTML = "";

    const unauthorized =
        data.repeated_unauthorized || [];

    if (unauthorized.length === 0) {

        unauthorizedRequests.innerHTML =
            '<p class="empty-state">No repeated unauthorized requests detected.</p>';

    } else {

        unauthorized.forEach((finding) => {

            const item =
                document.createElement("div");

            item.className =
                "finding-item";

            item.innerHTML = `
                <div class="finding-path">
                    ${escapeHtml(finding.ip)}
                </div>

                <div class="finding-details">
                    ${escapeHtml(String(finding.count))}
                    unauthorized requests
                </div>
            `;

            unauthorizedRequests.appendChild(item);

        });
    }
}


/* HTML ESCAPING */

function escapeHtml(value) {

    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}