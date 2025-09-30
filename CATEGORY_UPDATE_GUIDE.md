# WAF Category Update Guide

## 🔄 Database Migration Required

Sau khi cập nhật code để thêm trường `category` vào bảng `rules`, bạn cần chạy migration để cập nhật database.

## 📋 Các thay đổi đã thực hiện:

### 1. **Model Changes** (`shared/models.py`)
- Thêm cột `category = Column(String(50), nullable=False, index=True)` vào model `Rule`
- Cập nhật method `to_dict()` để bao gồm category

### 2. **Admin Interface** (`WAF_admin/templates/manage_rules.html`)
- Thêm cột "Category" vào bảng hiển thị rules
- Thêm dropdown chọn category trong form thêm rule mới
- Thêm CSS để hiển thị category badges với màu sắc khác nhau

### 3. **Admin Logic** (`WAF_admin/main.py`)
- Cập nhật function `add_rule()` để xử lý trường category
- Cập nhật function `import_rules()` để support category trong JSON
- Thêm thống kê rules theo category trong dashboard

### 4. **Dashboard** (`WAF_admin/templates/admin_dashboard.html`)
- Hiển thị thống kê số lượng rules theo từng category
- Category badges với màu sắc phân biệt

## 🚀 Hướng dẫn Migration:

### Option 1: Chạy Migration Script (Recommended)
```bash
cd /path/to/WAF_project
python migrate_database.py
```

### Option 2: Manual Migration
```bash
# Nếu sử dụng MySQL
mysql -u waf -p wafdb
ALTER TABLE rules ADD COLUMN category VARCHAR(50) NOT NULL DEFAULT 'Custom';
CREATE INDEX idx_rules_category ON rules(category);

# Nếu sử dụng SQLite
sqlite3 waf_database.db
ALTER TABLE rules ADD COLUMN category TEXT NOT NULL DEFAULT 'Custom';
CREATE INDEX idx_rules_category ON rules(category);
```

### Option 3: Recreate Database (Mất dữ liệu cũ!)
```bash
# Xóa database hiện tại và tạo lại
# CẢNH BÁO: Sẽ mất tất cả dữ liệu!
```

## 📝 Categories Available:

- **SQL Injection** - Chống SQL injection attacks  
- **XSS** - Chống Cross-Site Scripting
- **Bot Protection** - Chặn bot và crawler xấu
- **Path Traversal** - Chống path traversal attacks
- **Command Injection** - Chống command injection
- **File Upload** - Bảo vệ file upload
- **Rate Limiting** - Giới hạn tần suất request
- **Custom** - Rules tùy chỉnh khác

## 🎨 Category Color Coding:

- 🔴 **SQL Injection**: Đỏ (#dc3545)
- 🟠 **XSS**: Cam (#fd7e14) 
- 🟢 **Bot Protection**: Xanh lá (#20c997)
- 🟣 **Path Traversal**: Tím (#6f42c1)
- 🟡 **Command Injection**: Hồng (#e83e8c)
- 🔵 **File Upload**: Xanh dương (#17a2b8)
- 🟢 **Rate Limiting**: Xanh lá đậm (#28a745)
- ⚫ **Custom**: Xám (#6c757d)

## 🔍 Kiểm tra sau Migration:

1. **Khởi động WAF Admin:**
   ```bash
   cd WAF_admin
   python main.py
   ```

2. **Truy cập:** http://localhost:5000

3. **Kiểm tra:**
   - Dashboard hiển thị thống kê theo category
   - Bảng rules có cột Category
   - Form thêm rule có dropdown Category
   - Các rule cũ hiển thị category "Custom"

## ⚠️ Lưu ý:

- Backup database trước khi chạy migration
- Các rule hiện có sẽ được gán category mặc định "Custom"
- Sau migration, bạn có thể edit từng rule để gán category phù hợp
- Category field là required khi thêm rule mới

## 🐛 Troubleshooting:

### Lỗi "column category cannot be null"
```bash
# Chạy lại migration script
python migrate_database.py
```

### Rules hiển thị lỗi trên giao diện
- Đảm bảo đã restart cả WAF_admin và WAF_app sau migration
- Clear browser cache

### Import JSON rules lỗi
- Đảm bảo file JSON có format đúng với trường "category":
```json
[
  {
    "id": 101,
    "enabled": true,
    "description": "Block SQL injection",
    "category": "SQL Injection",
    "severity": "HIGH",
    "target": "URL_QUERY",
    "operator": "CONTAINS",
    "value": "union select",
    "action": "BLOCK"
  }
]
```

### Sample rules file
- Sử dụng file `sample_rules.json` để test import feature