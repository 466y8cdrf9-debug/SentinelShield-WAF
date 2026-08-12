import json
from datetime import datetime

LOG_FILE = "security_logs.json"

def log_event(ip, attack_type, payload, action):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "client_ip": ip,
        "attack_type": attack_type,
        "payload": payload,
        "action": action
    }
    
    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
        
    logs.append(log_entry)
    
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)
