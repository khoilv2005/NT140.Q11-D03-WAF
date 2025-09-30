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
    from shared.database import SessionLocal, Rule, IPBlacklist, ActivityLog, logger
except ImportError:
    print("FATAL ERROR: Could not import from 'shared/database.py'.")
    print("Please ensure the file exists and the project structure is correct.")
    sys.exit(1)

# Import decoder để lọc dữ liệu
try:
    from decoder import deep_decode_data
except ImportError:
    print("FATAL ERROR: Could not import from 'decoder.py'.")
    print("Please ensure the decoder.py file exists in the WAF_app directory.")
    sys.exit(1)

# Load configuration from environment variables
from dotenv import load_dotenv
load_dotenv()

# --- Cấu hình ---
BACKEND_ADDRESS = os.getenv("WAF_BACKEND_ADDRESS", "http://127.0.0.1:80")
LISTEN_HOST = os.getenv("WAF_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("WAF_LISTEN_PORT", "8080"))
BLOCK_THRESHOLD = int(os.getenv("WAF_BLOCK_THRESHOLD", "3"))  # Ngưỡng vi phạm để cấm IP

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
        WAF_RULES = [r.to_dict() for r in rules_obj]
        logger.info(f"Loaded {len(WAF_RULES)} active rules using ORM.")

        # Tải IP blacklist
        ips_list = session.query(IPBlacklist.ip_address).all()
        IP_BLACKLIST = {ip[0] for ip in ips_list}
        logger.info(f"Loaded {len(IP_BLACKLIST)} blacklisted IPs using ORM.")
    except Exception as e:
        logger.error(f"Failed to load cache from database: {e}")
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
        logger.error(f"DB Log Failed: {e}")
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
            logger.info(f"IP {ip} has been added to the blacklist.")
            # Gọi trực tiếp hàm load cache để cập nhật ngay lập tức
            logger.info("Auto-ban triggered cache reload.")
            load_cache_from_db()
    except Exception as e:
        logger.error(f"Could not add IP {ip} to blacklist: {e}")
        session.rollback()
    finally:
        session.close()

def check_and_auto_block(ip, rule_id):
    """Kiểm tra lịch sử vi phạm của IP và tự động chặn nếu cần."""
    session = SessionLocal()
    try:
        block_count = session.query(ActivityLog).filter_by(client_ip=ip, action_taken='BLOCKED').count()
        logger.info(f"IP {ip} has {block_count} previous blocks. Threshold is {BLOCK_THRESHOLD}.")
        if block_count >= BLOCK_THRESHOLD:
            add_ip_to_blacklist(ip, rule_id)
    except Exception as e:
        logger.error(f"Could not check auto-block status for IP {ip}: {e}")
    finally:
        session.close()

# --- Logic WAF ---
def inspect_request_flask(req):
    if req.remote_addr in IP_BLACKLIST:
        return "IP_BLACKLIST"

    # Lấy request body một lần để tái sử dụng
    request_body_bytes = req.get_data(cache=True)

    for rule in WAF_RULES:
        # 1. THU THẬP DỮ LIỆU: Luôn đưa dữ liệu cần kiểm tra vào một danh sách
        targets_to_check = []
        rule_target = rule.get('target')

        if rule_target == 'URL_PATH':
            targets_to_check.append(req.path)
        elif rule_target == 'URL_QUERY':
            targets_to_check.append(req.query_string.decode('utf-8', 'ignore'))
        elif rule_target and 'HEADERS:' in rule_target:
            header_name = rule_target.split(':', 1)[1]
            targets_to_check.append(req.headers.get(header_name, ''))
        elif rule_target == 'BODY':
            targets_to_check.append(request_body_bytes.decode('utf-8', 'ignore'))
        elif rule_target in ('ARGS', 'ARGS_NAMES'):
            all_args = req.args.to_dict()
            all_args.update(req.form.to_dict())
            if rule_target == 'ARGS':
                targets_to_check.extend(all_args.values())
            else: # ARGS_NAMES
                targets_to_check.extend(all_args.keys())
        elif rule_target == 'FILENAME':
            if req.files:
                targets_to_check.extend([file.filename for file in req.files.values() if file.filename])

        # 2. XỬ LÝ DỮ LIỆU: Chỉ cần MỘT vòng lặp duy nhất
        for item in targets_to_check:
            if not item:
                continue

            # Áp dụng deep decode để lọc dữ liệu
            decoded_data, decode_log = deep_decode_data(str(item))
            
            # (Tùy chọn) In log giải mã nếu cần
            if len(decode_log) > 2:
                logger.info(f"[DECODE] Rule {rule['id']}: '{item}' -> '{decoded_data}'")

            # Kiểm tra rule với dữ liệu đã được decode
            match = False
            if rule['operator'] == 'CONTAINS' and rule['value'] in decoded_data:
                match = True
            elif rule['operator'] == 'REGEX' and re.search(rule['value'], decoded_data, re.IGNORECASE):
                match = True
            
            if match:
                logger.warning(f"[MATCH] Rule {rule['id']} on decoded data: '{decoded_data}'")
                return f"RULE_ID: {rule['id']}"
            
    return None

# --- Routes ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def reverse_proxy(path):
    block_reason = inspect_request_flask(request)
    if block_reason:
        logger.warning(f"Denied request from IP {request.remote_addr}. Reason: {block_reason}")
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
        logger.error(f"Could not connect to backend: {e}")
        log_event_to_db(request.remote_addr, request.method, request.full_path, 502, 'ERROR')
        return render_template('error_502.html'), 502

@app.route('/reset-db-management', methods=['POST'])
def reset_db_management():
    allowed_ips = os.getenv("ADMIN_ALLOWED_IPS", "127.0.0.1,192.168.232.1,::1").split(',')
    if request.remote_addr not in allowed_ips:
        logger.warning(f"Unauthorized attempt to reset cache from IP: {request.remote_addr}")
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    try:
        logger.info("Received API command to reload cache from Admin Panel...")
        load_cache_from_db()
        logger.info("Cache reloaded successfully via API.")
        return jsonify({"status": "success", "message": "Cache reloaded."})
    except Exception as e:
        logger.error(f"Failed to reload cache via API: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Main ---
if __name__ == "__main__":
    load_cache_from_db()
    logger.info(f"WAF Service is running on http://{LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)