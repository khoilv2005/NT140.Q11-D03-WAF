import sys
import os
import requests
from flask import Flask, request, render_template, redirect, url_for, flash, json

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
app.secret_key = "super_secret_key_123" 
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


@app.route('/import-rules', methods=['POST'])
def import_rules():
    if request.remote_addr not in ['127.0.0.1', '192.168.232.1', '::1']:
        return render_template('error_403.html'), 403

    # 1. Kiểm tra file upload
    if 'rule_file' not in request.files:
        flash('No file part in the request.', 'error')
        return redirect(url_for('manage_rules'))
    
    file = request.files['rule_file']
    if file.filename == '':
        flash('No file selected for uploading.', 'error')
        return redirect(url_for('manage_rules'))

    if file and file.filename.endswith('.json'):
        session = SessionLocal()
        try:
            # 2. Đọc và phân tích file JSON
            content = file.read().decode('utf-8')
            rules_from_json = json.loads(content)
            
            if not isinstance(rules_from_json, list):
                raise ValueError("JSON content must be a list of rules.")

            added_count = 0
            skipped_count = 0

            # 3. Thêm rule vào DB
            for rule_data in rules_from_json:
                # Kiểm tra xem rule ID đã tồn tại chưa
                existing_rule = session.query(Rule).get(rule_data.get('id'))
                if existing_rule:
                    skipped_count += 1
                    continue # Bỏ qua nếu đã có
                
                new_rule = Rule(
                    id=rule_data.get('id'),
                    enabled=rule_data.get('enabled', True),
                    description=rule_data.get('description'),
                    severity=rule_data.get('severity', 'MEDIUM'),
                    target=rule_data.get('target'),
                    operator=rule_data.get('operator'),
                    value=rule_data.get('value'),
                    action=rule_data.get('action', 'BLOCK')
                )
                session.add(new_rule)
                added_count += 1
            
            session.commit()
            flash(f'Successfully imported {added_count} new rules. Skipped {skipped_count} existing rules.', 'success')
            
            # 4. Gửi tín hiệu cho WAF
            if added_count > 0:
                notify_waf_to_reset()

        except json.JSONDecodeError:
            flash('Invalid JSON format in the uploaded file.', 'error')
            session.rollback()
        except Exception as e:
            flash(f'An error occurred: {e}', 'error')
            session.rollback()
        finally:
            session.close()
    else:
        flash('Invalid file type. Please upload a .json file.', 'error')

    return redirect(url_for('manage_rules'))
# --- Main ---
if __name__ == "__main__":
    print(f"\n[INFO] Admin Panel (ORM Edition) is running on http://{LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)