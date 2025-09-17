# webguard.py
import json
import re
import requests
import logging
import threading
import time
from flask import Flask, request, Response, redirect
from urllib.parse import quote_plus

# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# URL của ứng dụng web cần được bảo vệ (backend)
BACKEND_URL = 'http://127.0.0.1'
# Thời gian cập nhật blacklist (tính bằng giây)
BLACKLIST_UPDATE_INTERVAL = 60

# Dùng một đối tượng Lock để đảm bảo an toàn cho việc cập nhật blacklist
blacklist_lock = threading.Lock()
BLACKLIST_IPS = set()

def load_blacklist_periodically():
    """Tải blacklist từ file vào bộ nhớ định kỳ."""
    while True:
        try:
            with open('blacklist.json', 'r') as f:
                config = json.load(f)
                new_blacklist_ips = set(config.get('blacklist_ips', []))
            
            # Cập nhật blacklist một cách an toàn
            with blacklist_lock:
                global BLACKLIST_IPS
                BLACKLIST_IPS = new_blacklist_ips
            
            logging.info("Blacklist IP đã được cập nhật thành công.")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.warning(f"Không thể tải blacklist.json: {e}")
        
        time.sleep(BLACKLIST_UPDATE_INTERVAL)

# Khởi động luồng cập nhật blacklist
blacklist_thread = threading.Thread(target=load_blacklist_periodically, daemon=True)
blacklist_thread.start()

# Bộ quy tắc (rule) đơn giản để phát hiện tấn công
SQLI_PATTERNS = [
    re.compile(r'\b(union|select|insert|delete|update)\b', re.IGNORECASE),
    re.compile(r'or\s+1\s*=\s*1', re.IGNORECASE),
    re.compile(r'--|#|\'|\"|\(|\)', re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r'<script.*?>', re.IGNORECASE),
    re.compile(r'on\w+=', re.IGNORECASE),
    re.compile(r'javascript:', re.IGNORECASE),
]

def check_for_attacks(data):
    """Kiểm tra dữ liệu request để tìm các mẫu tấn công."""
    if not isinstance(data, str):
        data = str(data)
    
    for pattern in SQLI_PATTERNS:
        if pattern.search(data):
            return "SQL-INJECTION"

    for pattern in XSS_PATTERNS:
        if pattern.search(data):
            return "XSS"

    return None

# Chức năng reverse proxy
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def reverse_proxy(path):
    client_ip = request.remote_addr

    # 1. Quản lý IP Blacklist
    with blacklist_lock:
        if client_ip in BLACKLIST_IPS:
            logging.info(f"[{client_ip}] BỊ CHẶN: IP nằm trong blacklist")
            return show_error_page()

    # 2. Lọc dựa trên Signature/Regex
    full_url = request.url
    request_data = request.get_data().decode('utf-8', 'ignore') if request.get_data() else ''
    
    attack_found = check_for_attacks(full_url)
    if not attack_found:
        attack_found = check_for_attacks(request_data)
    
    if attack_found:
        logging.info(f"[{client_ip}] BỊ CHẶN: {attack_found}")
        return show_error_page()
    
    # 3. Ghi log yêu cầu hợp lệ
    logging.info(f"[{client_ip}] CHUYỂN TIẾP: {full_url}")

    # 4. Chuyển tiếp yêu cầu đến backend và trả về response
    try:
        headers = {key: value for key, value in request.headers}
        
        resp = requests.request(
            method=request.method,
            url=f'{BACKEND_URL}/{path}',
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False)

        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [
            (name, value) for (name, value) in resp.raw.headers.items()
            if name.lower() not in excluded_headers
        ]

        return Response(resp.content, resp.status_code, resp_headers)

    except requests.exceptions.RequestException as e:
        logging.error(f"[{client_ip}] LỖI: Không thể kết nối đến server backend - {e}")
        return f"Lỗi kết nối đến server backend: {e}", 502

# Route để hiển thị trang lỗi
@app.route('/error')
def show_error_page():
    try:
        with open('error_page.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "Không tìm thấy trang lỗi.", 404

if __name__ == '__main__':
    app.run(port=8080, host='0.0.0.0')