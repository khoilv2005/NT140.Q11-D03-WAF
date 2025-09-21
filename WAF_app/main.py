import sys
import os
import requests
import re
from flask import Flask, request, Response, render_template, jsonify
from urllib.parse import urlparse

# Thêm thư mục gốc của dự án vào Python Path để có thể import từ 'shared'
# Dòng này giúp code tìm thấy thư mục 'shared'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import các thành phần ORM từ file dùng chung
try:
    from shared.database import SessionLocal, Rule, IPBlacklist, ActivityLog
except ImportError:
    print("FATAL ERROR: Could not import from 'shared/database.py'.")
    print("Please ensure the file exists and the project structure is correct.")
    sys.exit(1)

# --- Cấu hình ---
BACKEND_ADDRESS = "http://127.0.0.1:80"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080

app = Flask(__name__)

# --- Cache ---
WAF_RULES = []
IP_BLACKLIST = set()

# --- Các hàm DB (sử dụng SQLAlchemy ORM) ---
def model_to_dict(model_instance):
    """Hàm tiện ích để chuyển đổi một object SQLAlchemy thành dictionary."""
    d = {}
    for column in model_instance.__table__.columns:
        d[column.name] = getattr(model_instance, column.name)
    return d

def load_rules_from_db():
    """Tải rule từ DB vào cache bằng ORM."""
    global WAF_RULES
    session = SessionLocal()
    try:
        rules_obj = session.query(Rule).filter_by(enabled=True).all()
        WAF_RULES = [model_to_dict(r) for r in rules_obj]
        print(f"[INFO][WAF] Loaded {len(WAF_RULES)} active rules using ORM.")
    finally:
        session.close()

def load_blacklist_from_db():
    """Tải blacklist từ DB vào cache bằng ORM."""
    global IP_BLACKLIST
    session = SessionLocal()
    try:
        ips_list = session.query(IPBlacklist.ip_address).all()
        IP_BLACKLIST = {ip[0] for ip in ips_list}
        print(f"[INFO][WAF] Loaded {len(IP_BLACKLIST)} blacklisted IPs using ORM.")
    finally:
        session.close()

def log_event_to_db(client_ip, method, path, status, action, rule_id=None):
    """Ghi log vào DB bằng cách tạo một object ActivityLog."""
    session = SessionLocal()
    try:
        new_log = ActivityLog(
            client_ip=client_ip, request_method=method, request_path=path,
            status_code=status, action_taken=action, triggered_rule_id=rule_id
        )
        session.add(new_log)
        session.commit()
    except Exception as e:
        print(f"[ERROR][WAF] DB Log Failed: {e}")
        session.rollback()
    finally:
        session.close()

# --- Logic WAF (không đổi) ---
def inspect_request_flask(req):
    if req.remote_addr in IP_BLACKLIST:
        return "IP_BLACKLIST"
    # ... (Toàn bộ logic kiểm tra rule giữ nguyên y hệt như cũ) ...
    for rule in WAF_RULES:
        target_data = None
        if rule['target'] == 'URL_PATH': target_data = req.path
        elif rule['target'] == 'URL_QUERY': target_data = req.query_string.decode('utf-8', 'ignore')
        elif 'HEADERS:' in rule['target']: target_data = req.headers.get(rule['target'].split(':', 1)[1], '')
        elif rule['target'] == 'BODY': target_data = req.get_data(as_text=True)
        if not target_data: continue
        match = False
        if rule['operator'] == 'CONTAINS' and rule['value'] in target_data: match = True
        elif rule['operator'] == 'REGEX' and re.search(rule['value'], target_data, re.IGNORECASE): match = True
        if match: return f"RULE_ID: {rule['id']}"
    return None

# --- Routes ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def reverse_proxy(path):
    block_reason = inspect_request_flask(request)
    if block_reason:
        print(f"[BLOCK][WAF] Denied request from IP {request.remote_addr}. Reason: {block_reason}")
        rule_id = int(re.search(r'\d+', block_reason).group()) if 'RULE_ID' in block_reason else None
        log_event_to_db(request.remote_addr, request.method, request.full_path, 403, 'BLOCKED', rule_id)
        # Giả sử bạn có file templates/error_403.html
        return render_template('error_403.html'), 403
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
        print(f"[ERROR][WAF] Could not connect to backend: {e}")
        log_event_to_db(request.remote_addr, request.method, request.full_path, 502, 'ERROR')
        return "<h1>502 Bad Gateway</h1>", 502

@app.route('/reset-rules', methods=['POST'])
def reset_rules():
    if request.remote_addr not in ['127.0.0.1', '::1']:
        print(f"[SECURITY][WAF] Unauthorized attempt to reset rules from IP: {request.remote_addr}")
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    try:
        print("\n[INFO][WAF] Received command to reload rules...")
        load_rules_from_db()
        load_blacklist_from_db()
        print("[INFO][WAF] Rules and blacklist reloaded successfully.")
        return jsonify({"status": "success", "message": "Rules reloaded."})
    except Exception as e:
        print(f"[ERROR][WAF] Failed to reload rules: {e}")
        return jsonify({"status": "error", "message": "Failed to reload rules."}), 500

# --- Main ---
if __name__ == "__main__":
    load_rules_from_db()
    load_blacklist_from_db()
    print(f"\n[INFO] WAF Service (ORM Edition) is running on http://{LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)