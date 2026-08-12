import json
import time
from flask import Flask, request, jsonify
from logger import log_event

app = Flask(__name__)

with open("rules.json", "r") as f:
    RULES = json.load(f)

REQUEST_COUNTS = {}
RATE_LIMIT = 10
TIME_WINDOW = 60

def is_rate_limited(ip):
    current_time = time.time()
    if ip not in REQUEST_COUNTS:
        REQUEST_COUNTS[ip] = []
    
    REQUEST_COUNTS[ip] = [t for t in REQUEST_COUNTS[ip] if current_time - t < TIME_WINDOW]
    REQUEST_COUNTS[ip].append(current_time)
    
    return len(REQUEST_COUNTS[ip]) > RATE_LIMIT

def inspect_request(data):
    data_str = str(data).upper()
    for attack_type, patterns in RULES.items():
        for pattern in patterns:
            if pattern.upper() in data_str:
                return attack_type, pattern
    return None, None

@app.before_request
def waf_middleware():
    client_ip = request.remote_addr
    
    if is_rate_limited(client_ip):
        log_event(client_ip, "Rate Limit Exceeded", "Excessive Requests", "BLOCKED")
        return jsonify({"status": "429 Too Many Requests", "message": "Rate limit exceeded"}), 429

    combined_input = {**request.args.to_dict(), **request.form.to_dict()}
    attack_type, matched_pattern = inspect_request(combined_input)
    
    if attack_type:
        log_event(client_ip, attack_type, matched_pattern, "BLOCKED")
        return jsonify({
            "status": "403 Forbidden",
            "message": f"Security Alert: Malicious activity detected ({attack_type})"
        }), 403

@app.route('/')
def home():
    return jsonify({"status": "200 OK", "message": "Welcome to SentinelShield Protected Web Portal"})

@app.route('/dashboard')
def dashboard():
    try:
        with open("security_logs.json", "r") as f:
            logs = json.load(f)
    except FileNotFoundError:
        logs = []
    return jsonify({"total_alerts": len(logs), "logs": logs})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
