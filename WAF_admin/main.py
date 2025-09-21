import sys
import os
import requests
from flask import Flask, request, render_template, redirect, url_for

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
WAF_RESET_URL = "http://127.0.0.1:8080/reset-db-management"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 5000

app = Flask(__name__)

# --- Các hàm tiện ích ---
def notify_waf_to_reset():
    """Gửi một request đến WAF để yêu cầu nó tải lại rule."""
    try:
        response = requests.post(WAF_RESET_URL, timeout=5)
        if response.status_code == 200:
            print("[INFO][Admin] Notified WAF to reload rules successfully.")
        else:
            print(f"[WARNING][Admin] Failed to notify WAF. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR][Admin] Could not connect to WAF to send reset command: {e}")

# --- Các Route ---

# Route cho Dashboard Chính
@app.route('/')
def admin_dashboard():
    # Giới hạn chỉ cho localhost và IP được phép truy cập
    allowed_ips = ['127.0.0.1', '192.168.232.1', '::1']
    if request.remote_addr not in allowed_ips:
        return render_template('error_403.html'), 403

    session = SessionLocal()
    try:
        total_requests = session.query(ActivityLog).count()
        blocked_requests = session.query(ActivityLog).filter_by(action_taken='BLOCKED').count()
        active_rules = session.query(Rule).filter_by(enabled=True).count()
        blacklisted_ips = session.query(IPBlacklist).count()

        stats = {
            'total_requests': total_requests,
            'blocked_requests': blocked_requests,
            'allowed_requests': total_requests - blocked_requests,
            'active_rules': active_rules,
            'blacklisted_ips': blacklisted_ips
        }
        logs = session.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(100).all()
        
        return render_template('admin_dashboard.html', stats=stats, logs=logs)
    finally:
        session.close()

# Route để XEM danh sách rule
@app.route('/manage-rules')
def manage_rules():
    allowed_ips = ['127.0.0.1', '192.168.232.1', '::1']
    if request.remote_addr not in allowed_ips:
        return render_template('error_403.html'), 403
    
    session = SessionLocal()
    try:
        rules = session.query(Rule).order_by(Rule.id).all()
        return render_template('manage_rules.html', rules=rules)
    finally:
        session.close()

# Route để THÊM rule mới
@app.route('/add-rule', methods=['POST'])
def add_rule():
    allowed_ips = ['127.0.0.1', '192.168.232.1', '::1']
    if request.remote_addr not in allowed_ips:
        return render_template('error_403.html'), 403
        
    session = SessionLocal()
    try:
        new_rule = Rule(
            id=int(request.form['id']),
            description=request.form['description'],
            target=request.form['target'],
            operator=request.form['operator'],
            value=request.form['value'],
            enabled='enabled' in request.form,
            severity='MEDIUM', # Gán giá trị mặc định
            action='BLOCK'     # Gán giá trị mặc định
        )
        session.add(new_rule)
        session.commit()
        # Gửi tín hiệu cho WAF sau khi commit thành công
        notify_waf_to_reset()
    except Exception as e:
        print(f"[ERROR] Could not add rule: {e}")
        session.rollback()
    finally:
        session.close()
    
    return redirect(url_for('manage_rules'))

# Route để XÓA một rule
@app.route('/delete-rule/<int:rule_id>', methods=['POST'])
def delete_rule(rule_id):
    allowed_ips = ['127.0.0.1', '192.168.232.1', '::1']
    if request.remote_addr not in allowed_ips:
        return render_template('error_403.html'), 403
        
    session = SessionLocal()
    try:
        rule_to_delete = session.query(Rule).get(rule_id)
        if rule_to_delete:
            session.delete(rule_to_delete)
            session.commit()
            # Gửi tín hiệu cho WAF sau khi commit thành công
            notify_waf_to_reset()
        else:
            print(f"[WARNING] Rule with ID {rule_id} not found for deletion.")
    except Exception as e:
        print(f"[ERROR] Could not delete rule {rule_id}: {e}")
        session.rollback()
    finally:
        session.close()

    return redirect(url_for('manage_rules'))

# --- Main ---
if __name__ == "__main__":
    print(f"\n[INFO] Admin Panel (ORM Edition) is running on http://{LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)