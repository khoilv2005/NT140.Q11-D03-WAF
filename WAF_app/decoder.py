import base64
import urllib.parse
import html
import re
from typing import Tuple, List

# --- CÁC HÀM GIẢI MÃ ĐƠN LẺ ---

def decode_html_entities(data: str) -> str:
    """
    Giải mã các HTML Entities (ví dụ: &lt;, &#x2F;, &#105;).
    Sử dụng thư viện 'html' tích hợp của Python.
    """
    return html.unescape(data)

def try_decode_base64(data: str) -> str:
    """
    Cố gắng giải mã chuỗi Base64.
    Kiểm tra độ dài và các ký tự hợp lệ để giảm thiểu lỗi.
    """
    # 1. Kiểm tra sơ bộ: Base64 phải có độ dài là bội số của 4
    if len(data) % 4 != 0:
        return data

    # 2. Kiểm tra ký tự (chỉ chứa A-Z, a-z, 0-9, +, /, =)
    if not re.fullmatch(r'^[A-Za-z0-9+/=\s]*$', data):
        return data
    
    try:
        # Loại bỏ khoảng trắng (nếu có) trước khi decode
        cleaned_data = data.strip()
        
        # Base64 decode, sau đó cố gắng decode sang chuỗi UTF-8
        decoded_bytes = base64.b64decode(cleaned_data, validate=True)
        return decoded_bytes.decode('utf-8', errors='replace')
    except (base64.binascii.Error, UnicodeDecodeError):
        # Nếu không phải Base64 hợp lệ hoặc không phải UTF-8, trả về chuỗi gốc
        return data

def try_decode_uri_and_js_escape(data: str) -> str:
    r"""
    Giải mã URL-encoding (ví dụ: %20) và JavaScript Escape (\uXXXX).
    """
    current_data = data
    
    # 1. Giải mã URL-encoding (%xx)
    uri_decoded = urllib.parse.unquote(current_data)
    
    # 2. Giải mã JavaScript Escape Sequences (\uXXXX, \n, \t, v.v.)
    # Sử dụng 'unicode_escape' để xử lý các chuỗi thoát của JS/JSON
    if re.search(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}', uri_decoded) or uri_decoded != current_data:
        try:
            # Mã hóa về bytes, sau đó giải mã bằng 'unicode_escape'
            js_decoded = uri_decoded.encode('utf-8').decode('unicode_escape')
            return js_decoded
        except UnicodeDecodeError:
            pass # Giữ nguyên nếu lỗi
            
    return uri_decoded

# --- HÀM LỌC CHÍNH ---

def deep_decode_data(input_data: str, max_iterations: int = 10) -> Tuple[str, List[str]]:
    """
    Lặp lại việc giải mã dữ liệu qua các lớp khác nhau (HTML, URL/JS, Base64) 
    cho đến khi dữ liệu ổn định hoặc đạt giới hạn lặp.

    Trả về: (chuỗi_đã_lọc, danh_sách_log)
    """
    current_data = input_data.strip()
    log = [f"[Bắt đầu] Dữ liệu gốc ({len(current_data)} ký tự)."]

    for i in range(1, max_iterations + 1):
        previous_data = current_data
        
        # THỨ TỰ LỌC QUAN TRỌNG: 
        # Thường URL/JS Escape (lớp ngoài) -> HTML Entities -> Base64 (lớp trong)
        
        # 1. URL/JS Escape
        current_data = try_decode_uri_and_js_escape(current_data)
        if current_data != previous_data:
            log.append(f"[Lặp {i}][URI/JS Escape] Đã giải mã.")
            continue
            
        # 2. HTML Entities
        current_data = decode_html_entities(current_data)
        if current_data != previous_data:
            log.append(f"[Lặp {i}][HTML Entities] Đã giải mã.")
            continue
        
        # 3. Base64
        current_data = try_decode_base64(current_data)
        if current_data != previous_data:
            log.append(f"[Lặp {i}][Base64] Đã giải mã.")
            continue
            
        # Nếu không có thay đổi nào trong vòng lặp này, thì dừng
        log.append(f"[Kết thúc] Dữ liệu đã ổn định sau {i - 1} lần giải mã.")
        break
    else:
        log.append(f"[Cảnh báo] Đạt giới hạn {max_iterations} lần lặp. Có thể vẫn còn mã hóa.")
        
    return current_data, log

# --- VÍ DỤ SỬ DỤNG ---

if __name__ == "__main__":
    
    print("="*50)
    print("KIỂM THỬ CHỨC NĂNG LỌC DỮ LIỆU TỰ ĐỘNG (DEEP DECODE)")
    print("="*50)

    # Ví dụ 1: Mã hóa nhiều lớp (HTML Entity -> URL Escape -> Base64)
    # Chuỗi gốc: <h1>Clean Data</h1>
    # Base64: PGgxPkNsZWFuIERhdGE8L2gxPg==
    # URL: PGgxPkNsZWFuIERhdGE8L2gxPg%3D%3D
    # Entities: PGgxPkNsZWFuIERhdGE8L2gxPg&#x25;3D%3D
    example_1 = "q=%3Cscript%3E"
    
    print(f"\n[Ví dụ 1] Chuỗi đầu vào: {example_1}")
    result_1, log_1 = deep_decode_data(example_1)
    
    print("\n--- Lịch Sử Giải Mã ---")
    for line in log_1:
        print(line)
        
    print(f"\n>>> KẾT QUẢ CUỐI CÙNG: {result_1}")
    print("-"*50)


    # Ví dụ 2: Mã hóa Base64 lồng nhau
    # Chuỗi gốc: secret
    # Lớp 1 (Base64): c2VjcmV0
    # Lớp 2 (Base64): YzJWakNSRnRJ
    example_2 = "YzJWakNSRnRJ"
    
    print(f"\n[Ví dụ 2] Chuỗi đầu vào: {example_2}")
    result_2, log_2 = deep_decode_data(example_2)
    
    print("\n--- Lịch Sử Giải Mã ---")
    for line in log_2:
        print(line)
        
    print(f"\n>>> KẾT QUẢ CUỐI CÙNG: {result_2}")
    print("-"*50)
    
    # Ví dụ 3: Chuỗi XSS cổ điển (HTML Entity -> JS Escape)
    example_3 = "alert&#40;1&#41;" 
    
    print(f"\n[Ví dụ 3] Chuỗi đầu vào: {example_3}")
    result_3, log_3 = deep_decode_data(example_3)
    
    print("\n--- Lịch Sử Giải Mã ---")
    for line in log_3:
        print(line)
        
    print(f"\n>>> KẾT QUẢ CUỐI CÙNG: {result_3}")
    print("-"*50)
