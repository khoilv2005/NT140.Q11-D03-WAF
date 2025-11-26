import sys
import os
import requests
import re
import json
import ipaddress
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

# --- STRUCTURED DATA PARSING FUNCTIONS ---
def parse_structured_data(data):
    """Parse JSON/XML data to extract all values for inspection."""
    parsed_values = []

    # Try JSON parsing
    try:
        json_obj = json.loads(data)
        parsed_values.extend(_extract_values_from_dict(json_obj))
    except (json.JSONDecodeError, ValueError):
        pass

    # Try XML parsing (simple regex-based)
    xml_tags = re.findall(r'<([^!/?][^>]*)>([^<]*)</\1>', data)
    for tag, content in xml_tags:
        parsed_values.append(content.strip())

    return parsed_values

def _extract_values_from_dict(obj):
    """Recursively extract all values from a nested dict/list structure."""
    values = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            # Add both keys and values for comprehensive checking
            values.append(str(key))
            if isinstance(value, (dict, list)):
                values.extend(_extract_values_from_dict(value))
            else:
                values.append(str(value))
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                values.extend(_extract_values_from_dict(item))
            else:
                values.append(str(item))
    else:
        values.append(str(obj))

    return values

def evaluate_operator(operator, value, target):
    """Evaluate different types of operators for rule matching."""
    try:
        if operator == 'CONTAINS':
            return value in target
        elif operator in ('REGEX', 'REGEX_MATCH'):
            return bool(re.search(value, target, re.IGNORECASE))
        elif operator == '@eq':  # Equal
            return str(target) == str(value)
        elif operator == '@gt':  # Greater than
            return float(target) > float(value)
        elif operator == '@lt':  # Less than
            return float(target) < float(value)
        elif operator == '@ipMatch':  # IP/CIDR matching
            try:
                target_ip = ipaddress.ip_address(str(target))
                value_ips = value.split(',')
                for val_ip in value_ips:
                    val_ip = val_ip.strip()
                    if '/' in val_ip:  # CIDR notation
                        if target_ip in ipaddress.ip_network(val_ip, strict=False):
                            return True
                    else:  # Single IP
                        if target_ip == ipaddress.ip_address(val_ip):
                            return True
                return False
            except (ValueError, ipaddress.AddressValueError):
                return False
        else:
            logger.warning(f"Unknown operator: {operator}")
            return False
    except (ValueError, TypeError) as e:
        logger.debug(f"Operator evaluation error for {operator}: {e}")
        return False

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
        targets_to_check = set()  # Dùng set để tránh kiểm tra trùng lặp
        rule_targets = rule.get('target', '').split('|')

        # 1. TÁCH CHUỖI TARGET VÀ THU THẬP DỮ LIỆU
        for target_part in rule_targets:
            if target_part in ('URL_PATH', 'REQUEST_URI'):
                targets_to_check.add(req.path)
            elif target_part == 'URL_QUERY':
                targets_to_check.add(query_string_str)
            elif target_part == 'HEADERS':
                # Kiểm tra toàn bộ giá trị header (dùng cho các rule tổng quát trên header)
                targets_to_check.update(req.headers.values())
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
            # --- NEW TARGETS ---
            elif target_part == 'COOKIES':
                # Kiểm tra giá trị của tất cả cookie
                targets_to_check.update(req.cookies.values())
            elif target_part == 'COOKIES_NAMES':
                # Kiểm tra tên cookie
                targets_to_check.update(req.cookies.keys())
            elif target_part == 'REQUEST_METHOD':
                targets_to_check.add(req.method.upper())
            elif target_part == 'REQUEST_PROTOCOL':
                targets_to_check.add(req.environ.get('SERVER_PROTOCOL', 'HTTP/1.1'))
            elif target_part == 'FILES_CONTENT':
                # Kiểm tra nội dung file upload (cẩn thận với file lớn)
                if req.files:
                    for file in req.files.values():
                        if file.filename:
                            try:
                                # Giới hạn đọc 1MB để tránh DoS
                                file_content = file.read(1024 * 1024)
                                file.seek(0)  # Reset file pointer
                                targets_to_check.add(file_content.decode('utf-8', errors='ignore'))
                            except Exception as e:
                                logger.warning(f"Could not read file content for inspection: {e}")
            # --- END NEW TARGETS ---

        # 2. XỬ LÝ VÀ KIỂM TRA DỮ LIỆU
        for item in targets_to_check:
            if not item:
                continue

            decoded_data, decode_log = deep_decode_data(str(item))

            if len(decode_log) > 2:
                logger.info(f"[DECODE] Rule {rule['id']}: '{item}' -> '{decoded_data}'")

            # Prepare targets for inspection (original + parsed structured data)
            inspection_targets = [decoded_data]

            # Add structured data parsing for JSON/XML content
            if len(decoded_data) > 0:  # Only parse if there's content
                parsed_values = parse_structured_data(decoded_data)
                inspection_targets.extend(parsed_values)

            # Evaluate against all targets
            operator = rule.get('operator')
            value = rule.get('value')
            # Sử dụng trường action của rule: BLOCK / LOG / ALLOW (mặc định BLOCK)
            action = str(rule.get('action', 'BLOCK')).upper()

            for target in inspection_targets:
                if evaluate_operator(operator, value, target):
                    if action == 'BLOCK':
                        logger.warning(
                            f"[MATCH][BLOCK] Rule {rule['id']} ('{rule['description']}') "
                            f"triggered on: '{target}' (operator: {operator})"
                        )
                        return f"RULE_ID: {rule['id']}"
                    elif action in ('LOG', 'ALLOW'):
                        # Chỉ ghi log, KHÔNG chặn request
                        logger.info(
                            f"[MATCH][{action}] Rule {rule['id']} ('{rule['description']}') "
                            f"matched on: '{target}' (operator: {operator}) - no blocking applied."
                        )
                        # Tiếp tục kiểm tra các rule khác để vẫn cho phép rule BLOCK khác hoạt động
                        break

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
    client_ip = request.remote_addr

    # Check if client IP is allowed
    is_allowed = False
    for allowed_ip in allowed_ips:
        allowed_ip = allowed_ip.strip()
        if allowed_ip == client_ip:
            is_allowed = True
            break
        # Support subnet matching (e.g., 172.18.0.0/16)
        elif '/' in allowed_ip and client_ip.startswith(allowed_ip.split('/')[0].rsplit('.', 1)[0]):
            is_allowed = True
            break

    if not is_allowed:
        logger.warning(f"Unauthorized attempt to reset cache from IP: {client_ip}")
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