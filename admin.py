import sqlite3
import requests
from flask import Flask, request, render_template, redirect, url_for, jsonify

# --- Cấu hình ---
DATABASE_FILE = "waf.db"
WAF_RESET_URL = "http://127.0.0.1:8080/reset-rules" # Địa chỉ endpoint reset của WAF
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 5000

app = Flask(__name__)

# --- Các hàm tiện ích ---
def get_db_connection():
    """Tạo kết nối đến DB."""
    conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

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
    # Giới hạn chỉ cho localhost truy cập
    if request.remote_addr not in ['127.0.0.1', '192.168.232.1', '::1']:
        return render_template('error_403.html'), 403

    conn = get_db_connection()
    try:
        total_requests = conn.execute('SELECT COUNT(*) FROM activity_log').fetchone()[0]
        blocked_requests = conn.execute("SELECT COUNT(*) FROM activity_log WHERE action_taken = 'BLOCKED'").fetchone()[0]
        active_rules = conn.execute('SELECT COUNT(*) FROM rules WHERE enabled = 1').fetchone()[0]
        blacklisted_ips = conn.execute('SELECT COUNT(*) FROM ip_blacklist').fetchone()[0]
    except (sqlite3.OperationalError, IndexError, TypeError):
        total_requests, blocked_requests, active_rules, blacklisted_ips = 0, 0, 0, 0

    stats = {
        'total_requests': total_requests,
        'blocked_requests': blocked_requests,
        'allowed_requests': total_requests - blocked_requests,
        'active_rules': active_rules,
        'blacklisted_ips': blacklisted_ips
    }
    logs = conn.execute('SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 100').fetchall()
    conn.close()
    
    return render_template('admin_dashboard.html', stats=stats, logs=logs)

# Route để XEM danh sách rule
@app.route('/manage-rules')
def manage_rules():
    if request.remote_addr not in ['127.0.0.1', '192.168.232.1', '::1']:
        return render_template('error_403.html'), 403
    
    conn = get_db_connection()
    rules = conn.execute('SELECT * FROM rules ORDER BY id ASC').fetchall()
    conn.close()
    return render_template('manage_rules.html', rules=rules)

# Route để THÊM rule mới
@app.route('/add-rule', methods=['POST'])
def add_rule():
    if request.remote_addr not in ['127.0.0.1', '192.168.232.1', '::1']:
        return render_template('error_403.html'), 403
        
    try:
        rule_id = request.form['id']
        description = request.form['description']
        target = request.form['target']
        operator = request.form['operator']
        value = request.form['value']
        enabled = 1 if 'enabled' in request.form else 0

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO rules (id, enabled, description, severity, target, operator, value, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (rule_id, enabled, description, 'MEDIUM', target, operator, value, 'BLOCK')
        )
        conn.commit()
        conn.close()
        # Gửi tín hiệu cho WAF sau khi commit
        notify_waf_to_reset()
    except Exception as e:
        print(f"[ERROR] Could not add rule: {e}")
    
    return redirect(url_for('manage_rules'))

# Route để XÓA một rule
@app.route('/delete-rule/<int:rule_id>', methods=['POST'])
def delete_rule(rule_id):
    if request.remote_addr not in ['127.0.0.1', '192.168.232.1', '::1']:
        return render_template('error_403.html'), 403
        
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
        conn.commit()
        conn.close()
        # Gửi tín hiệu cho WAF sau khi commit
        notify_waf_to_reset()
    except Exception as e:
        print(f"[ERROR] Could not delete rule {rule_id}: {e}")

    return redirect(url_for('manage_rules'))

# --- Main ---
if __name__ == "__main__":
    print(f"\n[INFO] Admin Panel is running on http://{LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)