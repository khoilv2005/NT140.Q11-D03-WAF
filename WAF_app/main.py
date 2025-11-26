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
    from shared.database import SessionLocal, Rule, IPBlacklist, ActivityLog, logger, init_database
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
BLOCK_THRESHOLD = int(os.getenv("WAF_BLOCK_THRESHOLD", "100000"))  # Ngưỡng vi phạm để cấm IP

app = Flask(__name__)

# --- Cache ---
WAF_RULES = []
IP_BLACKLIST = set()

# --- Các hàm DB (sử dụng SQLAlchemy ORM) ---
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
        # Đếm số lần bị BLOCKED trước đó của IP này
        block_count = session.query(ActivityLog).filter_by(client_ip=ip, action_taken='BLOCKED').count()
        logger.info(f"IP {ip} has {block_count} previous blocks. Threshold is {BLOCK_THRESHOLD}.")
        # Chú ý: so sánh với >= vì lần vi phạm hiện tại chưa được ghi vào log
        if block_count >= BLOCK_THRESHOLD - 1:
            add_ip_to_blacklist(ip, rule_id)
    except Exception as e:
        logger.error(f"Could not check auto-block status for IP {ip}: {e}")
    finally:
        session.close()

# --- Logic WAF (ĐÃ SỬA LỖI) ---
def inspect_request_flask(req):
    if req.remote_addr in IP_BLACKLIST:
        return "IP_BLACKLIST"

    # Lấy các phần của request một lần để tái sử dụng
    request_body_str = req.get_data(as_text=True, cache=True)
    query_string_str = req.query_string.decode('utf-8', 'ignore')
    all_form_args = req.form.to_dict()
    all_query_args = req.args.to_dict()

    for rule in WAF_RULES:
        targets_to_check = set() # Dùng set để tránh kiểm tra trùng lặp
        rule_targets = rule.get('target', '').split('|')

        # 1. TÁCH CHUỖI TARGET VÀ THU THẬP DỮ LIỆU
        for target_part in rule_targets:
            if target_part in ('URL_PATH', 'REQUEST_URI'):
                targets_to_check.add(req.path)
            elif target_part == 'URL_QUERY':
                targets_to_check.add(query_string_str)
            elif 'HEADERS:' in target_part:
                header_name = target_part.split(':', 1)[1]
                targets_to_check.add(req.headers.get(header_name, ''))
            elif target_part == 'BODY':
                targets_to_check.add(request_body_str)
            elif target_part == 'ARGS':
                targets_to_check.update(all_query_args.values())
                targets_to_check.update(all_form_args.values())
            elif target_part == 'ARGS_NAMES':
                targets_to_check.update(all_query_args.keys())
                targets_to_check.update(all_form_args.keys())
            elif target_part == 'FILENAME':
                if req.files:
                    targets_to_check.update([file.filename for file in req.files.values() if file.filename])

        # 2. XỬ LÝ VÀ KIỂM TRA DỮ LIỆU
        for item in targets_to_check:
            if not item:
                continue

            decoded_data, decode_log = deep_decode_data(str(item))
            
            if len(decode_log) > 2:
                logger.info(f"[DECODE] Rule {rule['id']}: '{item}' -> '{decoded_data}'")

            match = False
            # Chấp nhận cả REGEX và REGEX_MATCH để tương thích
            operator = rule.get('operator')
            value = rule.get('value')
            
            if operator == 'CONTAINS' and value in decoded_data:
                match = True
            elif operator in ('REGEX', 'REGEX_MATCH') and re.search(value, decoded_data, re.IGNORECASE):
                match = True
            
            if match:
                logger.warning(f"[MATCH] Rule {rule['id']} ('{rule['description']}') triggered on decoded data: '{decoded_data}'")
                return f"RULE_ID: {rule['id']}"
            
    return None

# --- Routes ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def reverse_proxy(path):
    block_reason = inspect_request_flask(request)
    if block_reason:
        logger.warning(f"Denied request from IP {request.remote_addr}. Reason: {block_reason}")
        
        rule_id = None
        if 'RULE_ID' in block_reason:
            try:
                rule_id = int(re.search(r'\d+', block_reason).group())
            except (AttributeError, ValueError):
                pass
        
        # Ghi log trước khi kiểm tra auto-block
        log_event_to_db(request.remote_addr, request.method, request.full_path, 403, 'BLOCKED', rule_id)
        if rule_id:
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
    # Initialize database first
    if not init_database():
        logger.error("Failed to initialize database. Exiting...")
        sys.exit(1)

    load_cache_from_db()
    logger.info(f"WAF Service is running on http://{LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)