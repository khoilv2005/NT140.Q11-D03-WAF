import sqlite3
import requests
import re
import time
from flask import Flask, request, Response, render_template, jsonify
from urllib.parse import urlparse

# --- Cấu hình ---
DATABASE_FILE = "waf.db"
BACKEND_ADDRESS = "http://127.0.0.1:80"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080

app = Flask(__name__)

# --- Cache & Các hàm DB ---
WAF_RULES = []
IP_BLACKLIST = set()

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def load_rules_from_db():
    global WAF_RULES
    conn = get_db_connection()
    WAF_RULES = [dict(row) for row in conn.execute("SELECT * FROM rules WHERE enabled = 1").fetchall()]
    conn.close()
    print(f"[INFO] Loaded {len(WAF_RULES)} active rules.")

def load_blacklist_from_db():
    global IP_BLACKLIST
    conn = get_db_connection()
    IP_BLACKLIST = {row['ip_address'] for row in conn.execute("SELECT ip_address FROM ip_blacklist").fetchall()}
    conn.close()
    print(f"[INFO] Loaded {len(IP_BLACKLIST)} blacklisted IPs.")

def log_event_to_db(client_ip, method, path, status, action, rule_id=None):
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO activity_log (client_ip, request_method, request_path, status_code, action_taken, triggered_rule_id) VALUES (?, ?, ?, ?, ?, ?)",
            (client_ip, method, path, status, action, rule_id)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] DB Log Failed: {e}")

# ==========================================================
# === HÀM KIỂM TRA ĐÃ THÊM LOG CHI TIẾT ===
# ==========================================================
def inspect_request_flask(req):
    client_ip = req.remote_addr
    print("\n--- NEW REQUEST ---")
    print(f"[DEBUG] Inspecting request from IP: {client_ip}")
    print(f"[DEBUG] Path: {req.path}")
    print(f"[DEBUG] Query String: {req.query_string.decode('utf-8', 'ignore')}")

    if client_ip in IP_BLACKLIST:
        print(f"[DEBUG] MATCH FOUND! Reason: IP is in blacklist.")
        return "IP_BLACKLIST"

    print(f"[DEBUG] Checking against {len(WAF_RULES)} rules in cache...")
    for rule in WAF_RULES:
        print(f"\n[DEBUG]   -> Checking Rule ID: {rule['id']}")
        target_data = None
        
        if rule['target'] == 'URL_PATH':
            target_data = req.path
            print(f"[DEBUG]      Target: URL_PATH, Data: '{target_data}'")
        elif rule['target'] == 'URL_QUERY':
            target_data = req.query_string.decode('utf-8', 'ignore')
            print(f"[DEBUG]      Target: URL_QUERY, Data: '{target_data}'")
        elif 'HEADERS:' in rule['target']:
            header_name = rule['target'].split(':', 1)[1]
            target_data = req.headers.get(header_name, '')
            print(f"[DEBUG]      Target: {rule['target']}, Data: '{target_data}'")
        elif rule['target'] == 'BODY':
            target_data = req.get_data(as_text=True)
            print(f"[DEBUG]      Target: BODY, Data: '{target_data}'")

        if not target_data:
            print("[DEBUG]      No data for this target. Skipping.")
            continue

        print(f"[DEBUG]      Operator: '{rule['operator']}', Value: '{rule['value']}'")
        match = False
        if rule['operator'] == 'CONTAINS' and rule['value'] in target_data: match = True
        elif rule['operator'] == 'REGEX' and re.search(rule['value'], target_data, re.IGNORECASE): match = True
        
        if match:
            print(f"[DEBUG]      MATCH FOUND! Blocking request.")
            return f"RULE_ID: {rule['id']}"
    
    print("[DEBUG] No rules matched. Allowing request.")
    print("--- END REQUEST ---")
    return None

# --- Route chính ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def reverse_proxy(path):
    block_reason = inspect_request_flask(request)
    if block_reason:
        rule_id = int(re.search(r'\d+', block_reason).group()) if 'RULE_ID' in block_reason else None
        log_event_to_db(request.remote_addr, request.method, request.full_path, 403, 'BLOCKED', rule_id)
        return render_template('error_page.html'), 403

    try:
        headers = {key: value for (key, value) in request.headers if key.lower() != 'host'}
        headers['Host'] = urlparse(BACKEND_ADDRESS).netloc
        backend_url = f'{BACKEND_ADDRESS}/{path}'
        if request.query_string:
            backend_url += '?' + request.query_string.decode('utf-8')
        
        resp = requests.request(
            method=request.method, url=backend_url, headers=headers,
            data=request.get_data(), cookies=request.cookies, allow_redirects=False, timeout=10)

        log_event_to_db(request.remote_addr, request.method, request.full_path, resp.status_code, 'ALLOWED')
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        return Response(resp.content, resp.status_code, resp_headers)
        
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not connect to backend: {e}")
        log_event_to_db(request.remote_addr, request.method, request.full_path, 502, 'ERROR')
        return "<h1>502 Bad Gateway</h1>", 502

@app.route('/reset-rules', methods=['POST'])
def reset_rules():
    # Lớp bảo vệ: Chỉ chấp nhận request từ chính server đó (localhost)
    if request.remote_addr not in ['127.0.0.1','192.168.232.1' ,'::1']:
        print(f"[SECURITY] Unauthorized attempt to reset rules from IP: {request.remote_addr}")
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    try:
        print("\n[INFO] Received command to reload rules...")
        load_rules_from_db()
        load_blacklist_from_db()
        print("[INFO] Rules and blacklist reloaded successfully.")
        return jsonify({"status": "success", "message": "Rules reloaded."})
    except Exception as e:
        print(f"[ERROR] Failed to reload rules: {e}")
        return jsonify({"status": "error", "message": "Failed to reload rules."}), 500

# --- Main ---
if __name__ == "__main__":
    load_rules_from_db()
    load_blacklist_from_db()
    print(f"\n[INFO] WAF (Flask Edition with DB Logging) is running on http://{LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)