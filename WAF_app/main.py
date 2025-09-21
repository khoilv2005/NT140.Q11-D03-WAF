import sys
import os
import requests
import re
from flask import Flask, request, Response, render_template, jsonify
from urllib.parse import urlparse

# Thêm thư mục gốc của dự án vào Python Path để có thể import từ 'shared'
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
BLOCK_THRESHOLD = 3 # Ngưỡng vi phạm để cấm IP

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

def load_cache_from_db():
    """Tải tất cả rule và IP blacklist từ DB vào cache trong bộ nhớ."""
    global WAF_RULES, IP_BLACKLIST
    session = SessionLocal()
    try:
        # Tải rules
        rules_obj = session.query(Rule).filter_by(enabled=True).all()
        WAF_RULES = [model_to_dict(r) for r in rules_obj]
        print(f"[INFO][WAF] Loaded {len(WAF_RULES)} active rules using ORM.")

        # Tải IP blacklist
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

def add_ip_to_blacklist(ip, rule_id):
    """Thêm một IP vào DB và gọi hàm tải lại cache."""
    session = SessionLocal()
    try:
        existing_ip = session.query(IPBlacklist).filter_by(ip_address=ip).first()
        if not existing_ip:
            new_blacklist_entry = IPBlacklist(
                ip_address=ip,
                triggered_rule_id=rule_id,
                notes=f"Auto-blocked after reaching {BLOCK_THRESHOLD} violations."
            )
            session.add(new_blacklist_entry)
            session.commit()
            print(f"[AUTO-BLOCK] IP {ip} has been added to the blacklist.")
            # Gọi trực tiếp hàm load cache để cập nhật ngay lập tức
            print("[INFO] Auto-ban triggered cache reload.")
            load_cache_from_db()
    except Exception as e:
        print(f"[ERROR] Could not add IP {ip} to blacklist: {e}")
        session.rollback()
    finally:
        session.close()

def check_and_auto_block(ip, rule_id):
    """Kiểm tra lịch sử vi phạm của IP và tự động chặn nếu cần."""
    session = SessionLocal()
    try:
        block_count = session.query(ActivityLog).filter_by(client_ip=ip, action_taken='BLOCKED').count()
        print(f"[INFO] IP {ip} has {block_count} previous blocks. Threshold is {BLOCK_THRESHOLD}.")
        if block_count >= BLOCK_THRESHOLD:
            add_ip_to_blacklist(ip, rule_id)
    except Exception as e:
        print(f"[ERROR] Could not check auto-block status for IP {ip}: {e}")
    finally:
        session.close()

# --- Logic WAF ---
def inspect_request_flask(req):
    if req.remote_addr in IP_BLACKLIST:
        return "IP_BLACKLIST"
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
        check_and_auto_block(request.remote_addr, rule_id)
        
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

@app.route('/reset-db-management', methods=['POST'])
def reset_db_management():
    if request.remote_addr not in ['127.0.0.1', '192.168.232.1', '::1']:
        print(f"[SECURITY] Unauthorized attempt to reset cache from IP: {request.remote_addr}")
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    try:
        print("\n[INFO] Received API command to reload cache from Admin Panel...")
        load_cache_from_db()
        print("[INFO] Cache reloaded successfully via API.")
        return jsonify({"status": "success", "message": "Cache reloaded."})
    except Exception as e:
        print(f"[ERROR] Failed to reload cache via API: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Main ---
if __name__ == "__main__":
    load_cache_from_db()
    print(f"\n[INFO] WAF Service (ORM Edition with Auto-Ban) is running on http://{LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)