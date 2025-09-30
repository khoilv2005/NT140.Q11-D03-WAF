import sys
import os
import requests
import json
from flask import Flask, request, render_template, redirect, url_for, flash

# Thêm thư mục gốc của dự án vào Python Path để có thể import từ 'shared'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import các thành phần ORM từ file dùng chung
try:
    from shared.database import SessionLocal, Rule, IPBlacklist, ActivityLog, logger
except ImportError:
    print("FATAL ERROR: Could not import from 'shared/database.py'.")
    print("Please ensure the file exists and the project structure is correct.")
    sys.exit(1)

# Load configuration from environment variables
from dotenv import load_dotenv
load_dotenv()

# --- Cấu hình ---
WAF_RESET_URL = os.getenv("WAF_RESET_URL", "http://127.0.0.1:8080/reset-db-management")
LISTEN_HOST = os.getenv("ADMIN_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("ADMIN_LISTEN_PORT", "5000"))
ADMIN_ALLOWED_IPS = os.getenv("ADMIN_ALLOWED_IPS", "127.0.0.1,192.168.232.1,::1").split(',')

app = Flask(__name__)
app.secret_key = os.getenv("ADMIN_SECRET_KEY", "super_secret_key_123") 
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
    if request.remote_addr not in ADMIN_ALLOWED_IPS:
        return render_template('error_403.html'), 403

    session = SessionLocal()
    try:
        total_requests = session.query(ActivityLog).count()
        blocked_requests = session.query(ActivityLog).filter_by(action_taken='BLOCKED').count()
        active_rules = session.query(Rule).filter_by(enabled=True).count()
        blacklisted_ips = session.query(IPBlacklist).count()

        # Thống kê theo category
        from sqlalchemy import func
        category_stats = session.query(
            Rule.category, 
            func.count(Rule.id).label('rule_count')
        ).filter_by(enabled=True).group_by(Rule.category).all()

        stats = {
            'total_requests': total_requests,
            'blocked_requests': blocked_requests,
            'allowed_requests': total_requests - blocked_requests,
            'active_rules': active_rules,
            'blacklisted_ips': blacklisted_ips,
            'category_stats': [{'category': cat, 'count': count} for cat, count in category_stats]
        }
        logs = session.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(100).all()
        
        return render_template('admin_dashboard.html', stats=stats, logs=logs)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('Database connection error. Please try again.', 'error')
        return render_template('admin_dashboard.html', stats={}, logs=[])
    finally:
        session.close()

# Route để XEM danh sách rule
@app.route('/manage-rules')
def manage_rules():
    if request.remote_addr not in ADMIN_ALLOWED_IPS:
        return render_template('error_403.html'), 403
    
    session = SessionLocal()
    try:
        rules = session.query(Rule).order_by(Rule.id).all()
        return render_template('manage_rules.html', rules=rules)
    except Exception as e:
        logger.error(f"Manage rules error: {e}")
        flash('Database connection error. Please try again.', 'error')
        return render_template('manage_rules.html', rules=[])
    finally:
        session.close()

# Route để THÊM rule mới
@app.route('/add-rule', methods=['POST'])
def add_rule():
    if request.remote_addr not in ADMIN_ALLOWED_IPS:
        return render_template('error_403.html'), 403
        
    session = SessionLocal()
    try:
        new_rule = Rule(
            id=int(request.form['id']),
            description=request.form['description'],
            category=request.form['category'],  # Thêm trường category mới
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
        flash('Rule added successfully!', 'success')
    except Exception as e:
        logger.error(f"Could not add rule: {e}")
        flash('Failed to add rule. Please try again.', 'error')
        session.rollback()
    finally:
        session.close()
    
    return redirect(url_for('manage_rules'))

# Route để XÓA một rule
@app.route('/delete-rule/<int:rule_id>', methods=['POST'])
def delete_rule(rule_id):
    if request.remote_addr not in ADMIN_ALLOWED_IPS:
        return render_template('error_403.html'), 403
        
    session = SessionLocal()
    try:
        rule_to_delete = session.query(Rule).get(rule_id)
        if rule_to_delete:
            session.delete(rule_to_delete)
            session.commit()
            flash('Rule deleted successfully!', 'success')
            # Gửi tín hiệu cho WAF sau khi commit thành công
            notify_waf_to_reset()
        else:
            logger.warning(f"Rule with ID {rule_id} not found for deletion.")
            flash('Rule not found.', 'warning')
    except Exception as e:
        logger.error(f"Could not delete rule {rule_id}: {e}")
        flash('Failed to delete rule. Please try again.', 'error')
        session.rollback()
    finally:
        session.close()

    return redirect(url_for('manage_rules'))


@app.route('/import-rules', methods=['POST'])
def import_rules():
    if request.remote_addr not in ADMIN_ALLOWED_IPS:
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
            
            # Kiểm tra nội dung file không rỗng
            if not content.strip():
                flash('The uploaded file is empty.', 'error')
                return redirect(url_for('manage_rules'))
            
            rules_from_json = json.loads(content)
            
            if not isinstance(rules_from_json, list):
                raise ValueError("JSON content must be a list of rules.")

            added_count = 0
            skipped_count = 0

            # 3. Thêm rule vào DB
            for rule_data in rules_from_json:
                # Validate required fields
                required_fields = ['id', 'description', 'target', 'operator', 'value']
                missing_fields = [field for field in required_fields if not rule_data.get(field)]
                if missing_fields:
                    flash(f'Rule with ID {rule_data.get("id", "unknown")} is missing required fields: {", ".join(missing_fields)}', 'error')
                    continue
                
                # Kiểm tra xem rule ID đã tồn tại chưa
                existing_rule = session.query(Rule).get(rule_data.get('id'))
                if existing_rule:
                    skipped_count += 1
                    continue # Bỏ qua nếu đã có
                
                new_rule = Rule(
                    id=rule_data.get('id'),
                    enabled=rule_data.get('enabled', True),
                    description=rule_data.get('description'),
                    category=rule_data.get('category', 'Custom'),  # Thêm trường category với default
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

        except json.JSONDecodeError as e:
            flash('Invalid JSON format in the uploaded file.', 'error')
            logger.error(f"JSON decode error: {e}")
            session.rollback()
        except Exception as e:
            flash(f'An error occurred: {e}', 'error')
            logger.error(f"Import rules error: {e}")
            session.rollback()
        finally:
            session.close()
    else:
        flash('Invalid file type. Please upload a .json file.', 'error')

    return redirect(url_for('manage_rules'))
# --- Main ---
if __name__ == "__main__":
    logger.info(f"Admin Panel is running on http://{LISTEN_HOST}:{LISTEN_PORT}")
    logger.info(f"Allowed IPs: {', '.join(ADMIN_ALLOWED_IPS)}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)