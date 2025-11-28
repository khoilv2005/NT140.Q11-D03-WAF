import sys
import os
import requests
import re
import json
import ipaddress
from functools import lru_cache
from contextlib import contextmanager
from threading import Lock
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
BLOCK_THRESHOLD = int(os.getenv("WAF_BLOCK_THRESHOLD", "100000"))

app = Flask(__name__)

# --- Cache với thread-safe lock ---
_cache_lock = Lock()
WAF_RULES = []
IP_BLACKLIST = set()
_COMPILED_REGEX_CACHE = {}  # Cache cho compiled regex patterns


# =============================================================================
# TỐI ƯU 1: Context Manager cho Database Session
# =============================================================================
@contextmanager
def get_db_session():
    """Thread-safe database session context manager."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# =============================================================================
# TỐI ƯU 2: Cache Compiled Regex Patterns
# =============================================================================
@lru_cache(maxsize=512)
def get_compiled_regex(pattern: str):
    """Cache compiled regex patterns để tránh compile lại mỗi request."""
    return re.compile(pattern, re.IGNORECASE)


# =============================================================================
# TỐI ƯU 3: Cải thiện load_cache_from_db với thread-safe
# =============================================================================
def load_cache_from_db():
    """Tải tất cả rule và IP blacklist từ DB vào cache trong bộ nhớ."""
    global WAF_RULES, IP_BLACKLIST
    
    with _cache_lock:
        with get_db_session() as session:
            try:
                # Tải rules
                rules_obj = session.query(Rule).filter_by(enabled=True).all()
                new_rules = [r.to_dict() for r in rules_obj]
                
                # Pre-compile regex patterns cho các rules
                for rule in new_rules:
                    if rule.get('operator') in ('REGEX', 'REGEX_MATCH'):
                        pattern = rule.get('value', '')
                        if pattern:
                            try:
                                get_compiled_regex(pattern)  # Cache compiled pattern
                            except re.error as e:
                                logger.error(f"Invalid regex in rule {rule['id']}: {e}")
                
                WAF_RULES = new_rules
                logger.info(f"Loaded {len(WAF_RULES)} active rules using ORM.")

                # Tải IP blacklist
                ips_list = session.query(IPBlacklist.ip_address).all()
                IP_BLACKLIST = frozenset(ip[0] for ip in ips_list)  # frozenset cho lookup nhanh hơn
                logger.info(f"Loaded {len(IP_BLACKLIST)} blacklisted IPs using ORM.")
                
            except Exception as e:
                logger.error(f"Failed to load cache from database: {e}")


def log_event_to_db(client_ip, method, path, status, action, rule_id=None):
    """Ghi log vào DB bằng cách tạo một object ActivityLog."""
    try:
        with get_db_session() as session:
            new_log = ActivityLog(
                client_ip=client_ip, request_method=method, request_path=path,
                status_code=status, action_taken=action, triggered_rule_id=rule_id
            )
            session.add(new_log)
    except Exception as e:
        logger.error(f"DB Log Failed: {e}")


def add_ip_to_blacklist(ip, rule_id):
    """Thêm một IP vào DB và cập nhật cache."""
    global IP_BLACKLIST
    
    try:
        with get_db_session() as session:
            existing_ip = session.query(IPBlacklist).filter_by(ip_address=ip).first()
            if not existing_ip:
                new_blacklist_entry = IPBlacklist(
                    ip_address=ip,
                    triggered_rule_id=rule_id,
                    notes=f"Auto-blocked after reaching {BLOCK_THRESHOLD} violations."
                )
                session.add(new_blacklist_entry)
                logger.info(f"IP {ip} has been added to the blacklist.")
                
                # Cập nhật cache trực tiếp thay vì reload toàn bộ
                with _cache_lock:
                    IP_BLACKLIST = IP_BLACKLIST | {ip}
                    
    except Exception as e:
        logger.error(f"Could not add IP {ip} to blacklist: {e}")


# =============================================================================
# TỐI ƯU 4: Cải thiện Structured Data Parsing
# =============================================================================
def parse_structured_data(data: str) -> list:
    """Parse JSON/XML data to extract all values for inspection.
    
    Tối ưu: Kiểm tra nhanh trước khi parse để tránh overhead không cần thiết.
    """
    if not data or len(data) < 2:
        return []
    
    parsed_values = []
    data_stripped = data.strip()
    
    # Quick check cho JSON (bắt đầu bằng { hoặc [)
    if data_stripped.startswith(('{', '[')):
        try:
            json_obj = json.loads(data)
            parsed_values.extend(_extract_values_from_dict(json_obj))
        except (json.JSONDecodeError, ValueError):
            pass
    
    # Quick check cho XML (chứa < và >)
    if '<' in data and '>' in data:
        xml_tags = re.findall(r'<([^!/?][^>]*)>([^<]*)</\1>', data)
        for _, content in xml_tags:
            content_stripped = content.strip()
            if content_stripped:
                parsed_values.append(content_stripped)
    
    return parsed_values


def _extract_values_from_dict(obj, _depth=0) -> list:
    """Recursively extract all values from a nested dict/list structure.
    
    Tối ưu: Thêm depth limit để tránh stack overflow với nested data.
    """
    if _depth > 20:  # Giới hạn độ sâu đệ quy
        return []
    
    values = []
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            values.append(str(key))
            if isinstance(value, (dict, list)):
                values.extend(_extract_values_from_dict(value, _depth + 1))
            elif value is not None:
                values.append(str(value))
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                values.extend(_extract_values_from_dict(item, _depth + 1))
            elif item is not None:
                values.append(str(item))
    elif obj is not None:
        values.append(str(obj))
    
    return values


# =============================================================================
# TỐI ƯU 5: Cải thiện evaluate_operator
# =============================================================================
def evaluate_operator(operator: str, value: str, target: str) -> bool:
    """Evaluate different types of operators for rule matching.
    
    Tối ưu: Sử dụng dict dispatch thay vì if-elif chain.
    """
    try:
        if operator == 'CONTAINS':
            return value in target
        
        if operator in ('REGEX', 'REGEX_MATCH'):
            compiled = get_compiled_regex(value)
            return bool(compiled.search(target))
        
        if operator == '@eq':
            return str(target) == str(value)
        
        if operator == '@gt':
            return float(target) > float(value)
        
        if operator == '@lt':
            return float(target) < float(value)
        
        if operator == '@ipMatch':
            return _check_ip_match(target, value)
        
        logger.warning(f"Unknown operator: {operator}")
        return False
        
    except (ValueError, TypeError, re.error) as e:
        logger.debug(f"Operator evaluation error for {operator}: {e}")
        return False


def _check_ip_match(target: str, value: str) -> bool:
    """Helper function cho IP/CIDR matching."""
    try:
        target_ip = ipaddress.ip_address(str(target))
        for val_ip in value.split(','):
            val_ip = val_ip.strip()
            if not val_ip:
                continue
            if '/' in val_ip:
                if target_ip in ipaddress.ip_network(val_ip, strict=False):
                    return True
            elif target_ip == ipaddress.ip_address(val_ip):
                return True
        return False
    except (ValueError, ipaddress.AddressValueError):
        return False


def check_and_auto_block(ip: str, rule_id: int):
    """Kiểm tra lịch sử vi phạm của IP và tự động chặn nếu cần."""
    try:
        with get_db_session() as session:
            block_count = session.query(ActivityLog).filter_by(
                client_ip=ip, action_taken='BLOCKED'
            ).count()
            
            logger.info(f"IP {ip} has {block_count} previous blocks. Threshold is {BLOCK_THRESHOLD}.")
            
            if block_count >= BLOCK_THRESHOLD - 1:
                add_ip_to_blacklist(ip, rule_id)
    except Exception as e:
        logger.error(f"Could not check auto-block status for IP {ip}: {e}")




# =============================================================================
# TỐI ƯU 6: Cải thiện inspect_request_flask
# =============================================================================
def inspect_request_flask(req):
    """Kiểm tra request với các rule WAF."""
    client_ip = req.remote_addr
    
    # Quick check IP blacklist (O(1) lookup với frozenset)
    if client_ip in IP_BLACKLIST:
        return "IP_BLACKLIST"

    # Lấy các phần của request một lần để tái sử dụng
    request_body_str = req.get_data(as_text=True, cache=True)
    query_string_str = req.query_string.decode('utf-8', 'ignore')
    all_form_args = req.form.to_dict()
    all_query_args = req.args.to_dict()
    
    # Cache các giá trị headers để tránh gọi nhiều lần
    headers_values = None
    cookies_values = None
    cookies_keys = None
    
    for rule in WAF_RULES:
        targets_to_check = set()
        rule_targets = rule.get('target', '').split('|')

        for target_part in rule_targets:
            if target_part in ('URL_PATH', 'REQUEST_URI'):
                targets_to_check.add(req.path)
                if req.path.startswith('/') and len(req.path) > 1:
                    targets_to_check.add(req.path[1:])
                    
            elif target_part == 'URL_QUERY':
                targets_to_check.add(query_string_str)
                
            elif target_part == 'HEADERS':
                if headers_values is None:
                    headers_values = set(req.headers.values())
                targets_to_check.update(headers_values)
                
            elif target_part.startswith('HEADERS:'):
                header_name = target_part.split(':', 1)[1]
                header_val = req.headers.get(header_name, '')
                if header_val:
                    targets_to_check.add(header_val)
                    
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
                    targets_to_check.update(f.filename for f in req.files.values() if f.filename)
                    
            elif target_part == 'COOKIES':
                if cookies_values is None:
                    cookies_values = set(req.cookies.values())
                targets_to_check.update(cookies_values)
                
            elif target_part == 'COOKIES_NAMES':
                if cookies_keys is None:
                    cookies_keys = set(req.cookies.keys())
                targets_to_check.update(cookies_keys)
                
            elif target_part == 'REQUEST_METHOD':
                targets_to_check.add(req.method.upper())
                
            elif target_part == 'REQUEST_PROTOCOL':
                targets_to_check.add(req.environ.get('SERVER_PROTOCOL', 'HTTP/1.1'))
                
            elif target_part == 'FILES_CONTENT':
                if req.files:
                    for file in req.files.values():
                        if file.filename:
                            try:
                                file_content = file.read(1024 * 1024)  # Giới hạn 1MB
                                file.seek(0)
                                targets_to_check.add(file_content.decode('utf-8', errors='ignore'))
                            except Exception as e:
                                logger.warning(f"Could not read file content for inspection: {e}")

        # Bỏ các giá trị rỗng
        targets_to_check.discard('')
        targets_to_check.discard(None)
        
        if not targets_to_check:
            continue

        operator = rule.get('operator')
        value = rule.get('value')
        action = str(rule.get('action', 'BLOCK')).upper()

        for item in targets_to_check:
            decoded_data, decode_log = deep_decode_data(str(item))

            if len(decode_log) > 2:
                logger.info(f"[DECODE] Rule {rule['id']}: '{item}' -> '{decoded_data}'")

            # Prepare targets for inspection
            inspection_targets = [decoded_data]
            
            # Chỉ parse structured data nếu có nội dung
            if decoded_data:
                parsed_values = parse_structured_data(decoded_data)
                if parsed_values:
                    inspection_targets.extend(parsed_values)

            for target in inspection_targets:
                if evaluate_operator(operator, value, target):
                    if action == 'BLOCK':
                        logger.warning(
                            f"[MATCH][BLOCK] Rule {rule['id']} ('{rule['description']}') "
                            f"triggered on: '{target}' (operator: {operator})"
                        )
                        return f"RULE_ID: {rule['id']}"
                    elif action in ('LOG', 'ALLOW'):
                        logger.info(
                            f"[MATCH][{action}] Rule {rule['id']} ('{rule['description']}') "
                            f"matched on: '{target}' (operator: {operator}) - no blocking applied."
                        )
                        break

    return None


# =============================================================================
# TỐI ƯU 7: Cải thiện IP validation trong reset_db_management
# =============================================================================
def is_ip_allowed(client_ip: str, allowed_ips_str: str) -> bool:
    """Kiểm tra IP có được phép hay không với hỗ trợ CIDR đúng cách."""
    try:
        client_ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    
    for allowed_ip in allowed_ips_str.split(','):
        allowed_ip = allowed_ip.strip()
        if not allowed_ip:
            continue
        try:
            if '/' in allowed_ip:
                # CIDR notation
                if client_ip_obj in ipaddress.ip_network(allowed_ip, strict=False):
                    return True
            else:
                # Single IP
                if client_ip_obj == ipaddress.ip_address(allowed_ip):
                    return True
        except ValueError:
            continue
    
    return False


# --- Routes ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def reverse_proxy(path):
    block_reason = inspect_request_flask(request)
    if block_reason:
        logger.warning(f"Denied request from IP {request.remote_addr}. Reason: {block_reason}")
        
        rule_id = None
        if 'RULE_ID' in block_reason:
            match = re.search(r'\d+', block_reason)
            if match:
                try:
                    rule_id = int(match.group())
                except ValueError:
                    pass
        
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
            method=request.method,
            url=backend_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10
        )
            
        log_event_to_db(request.remote_addr, request.method, request.full_path, resp.status_code, 'ALLOWED')
        
        excluded_headers = frozenset(['content-encoding', 'content-length', 'transfer-encoding', 'connection'])
        resp_headers = [(name, value) for (name, value) in resp.raw.headers.items() 
                        if name.lower() not in excluded_headers]
        
        return Response(resp.content, resp.status_code, resp_headers)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Could not connect to backend: {e}")
        log_event_to_db(request.remote_addr, request.method, request.full_path, 502, 'ERROR')
        return render_template('error_502.html'), 502


@app.route('/reset-db-management', methods=['POST'])
def reset_db_management():
    allowed_ips = os.getenv("ADMIN_ALLOWED_IPS", "127.0.0.1,192.168.232.1,::1")
    client_ip = request.remote_addr

    if not is_ip_allowed(client_ip, allowed_ips):
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
    if not init_database():
        logger.error("Failed to initialize database. Exiting...")
        sys.exit(1)

    load_cache_from_db()
    logger.info(f"WAF Service is running on http://{LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)