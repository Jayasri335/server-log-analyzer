from flask import Flask, request, jsonify
from collections import Counter, defaultdict
import re
from urllib.parse import unquote

app = Flask(__name__)


# --------------------------------------------------
# LOG PARSING
# --------------------------------------------------

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)'
    r'\s+\S+\s+\S+'
    r'\s+\[[^\]]+\]'
    r'\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+[^"]*)?"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<size>\S+)'
)


# --------------------------------------------------
# SUSPICIOUS PATH DETECTION
# --------------------------------------------------

SUSPICIOUS_PATTERNS = [
    ("/admin", "Admin panel access"),
    ("/wp-admin", "WordPress admin access"),
    ("/wp-login", "WordPress login access"),
    ("/etc/passwd", "Attempt to access system password file"),
    ("/etc/shadow", "Attempt to access system shadow file"),
    (".env", "Environment configuration file access"),
    ("../", "Directory traversal attempt"),
    ("..%2f", "Encoded directory traversal attempt"),
    ("config.php", "Configuration file access"),
    ("/config", "Configuration path access"),
    ("/backup", "Backup file/directory access"),
    ("/phpmyadmin", "Database administration panel access"),
]


def check_suspicious_path(path):
    decoded_path = unquote(path).lower()

    for pattern, reason in SUSPICIOUS_PATTERNS:
        if pattern.lower() in decoded_path:
            return reason

    return None


# --------------------------------------------------
# ANALYZE LOGS
# --------------------------------------------------

def analyze_logs(log_text):

    total_requests = 0
    successful_requests = 0
    client_errors = 0
    server_errors = 0

    status_codes = Counter()
    unauthorized_by_ip = defaultdict(int)
    suspicious_paths = []

    lines = log_text.splitlines()

    for line in lines:

        line = line.strip()

        if not line:
            continue

        match = LOG_PATTERN.match(line)

        if not match:
            continue

        ip = match.group("ip")
        path = match.group("path")
        status = int(match.group("status"))

        total_requests += 1

        status_codes[status] += 1

        # -----------------------------
        # HTTP STATUS CATEGORIES
        # -----------------------------

        if 200 <= status < 300:
            successful_requests += 1

        elif 400 <= status < 500:
            client_errors += 1

        elif 500 <= status < 600:
            server_errors += 1


        # -----------------------------
        # REPEATED 401 REQUESTS
        # -----------------------------

        if status == 401:
            unauthorized_by_ip[ip] += 1


        # -----------------------------
        # SUSPICIOUS PATHS
        # -----------------------------

        reason = check_suspicious_path(path)

        if reason:

            suspicious_paths.append({
                "ip": ip,
                "path": path,
                "reason": reason
            })


    # --------------------------------------------------
    # FIND IPS WITH 3 OR MORE 401 REQUESTS
    # --------------------------------------------------

    repeated_unauthorized = []

    for ip, count in unauthorized_by_ip.items():

        if count >= 3:

            repeated_unauthorized.append({
                "ip": ip,
                "count": count
            })


    # --------------------------------------------------
    # SECURITY FINDINGS
    # --------------------------------------------------

    security_findings = (
        len(suspicious_paths)
        + len(repeated_unauthorized)
    )


    return {
        "total_requests": total_requests,
        "successful_requests": successful_requests,
        "client_errors": client_errors,
        "server_errors": server_errors,
        "security_findings": security_findings,

        "status_codes": {
            str(code): count
            for code, count in sorted(status_codes.items())
        },

        "suspicious_paths": suspicious_paths,

        "repeated_unauthorized": repeated_unauthorized
    }


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "healthy",
        "service": "server-log-analyzer-backend"
    })


# --------------------------------------------------
# API - ANALYZE LOGS
# --------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def analyze():

    data = request.get_json(silent=True)

    if not data or "logs" not in data:

        return jsonify({
            "error": "No logs were provided."
        }), 400


    logs = data["logs"]

    if not isinstance(logs, str):

        return jsonify({
            "error": "Logs must be provided as text."
        }), 400


    result = analyze_logs(logs)

    return jsonify(result)


# --------------------------------------------------
# START FLASK SERVER
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )