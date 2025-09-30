# WAF Project - Database Setup Guide

## Tổng quan

Dự án đã được đơn giản hóa với kiến trúc sạch:

- `shared/database.py`: Kết nối database đơn giản với SQLAlchemy
- `shared/models.py`: Định nghĩa các model SQLAlchemy
- `.env`: Cấu hình DATABASE_URL
- File `createdb.py` đã được xóa vì bảng được tự động tạo khi import

## Cấu trúc thư mục

```
NT140.Q11-D03-WAF/
├── .env                    # Biến môi trường
├── requirements.txt        # Dependencies
├── shared/
│   ├── database.py        # Database connection & utilities
│   └── models.py          # SQLAlchemy models
├── WAF_admin/
│   └── main.py           # Admin panel
└── WAF_app/
    └── main.py           # WAF service
```

## Cài đặt

1. **Cài đặt dependencies:**
```bash
pip install -r requirements.txt
```

2. **Cấu hình database trong file `.env`:**
```env
# Cho MySQL
DATABASE_URL=mysql+mysqlconnector://waf:wafadmin@127.0.0.1:3306/wafdb

# Hoặc cho SQLite  
DATABASE_URL=sqlite:///waf_database.db
```

3. **Khởi động MySQL (nếu sử dụng):**
```bash
sudo docker run --name waf-mysql \
  -e MYSQL_ROOT_PASSWORD=my-secret-pw \
  -e MYSQL_DATABASE=wafdb \
  -e MYSQL_USER=waf \
  -e MYSQL_PASSWORD=wafadmin \
  -v waf-mysql-data:/var/lib/mysql \
  -p 3306:3306 -d mysql:latest
```

## Chạy ứng dụng

1. **Khởi động WAF Service:**
```bash
cd WAF_app
python main.py
```

2. **Khởi động Admin Panel:**
```bash
cd WAF_admin
python main.py
```

## Tính năng

### Database Connection
- **Đơn giản**: Sử dụng SQLAlchemy cơ bản với DATABASE_URL
- **Tự động tạo bảng**: Bảng được tạo khi import database module
- **Flexible database**: Hỗ trợ cả MySQL và SQLite

### Environment Variables
- Chỉ cần cấu hình `DATABASE_URL` trong `.env`
- Đơn giản và dễ hiểu

### Models
- Tách riêng thành file `models.py`
- Thêm phương thức `to_dict()` cho mỗi model
- Clean và documented

## Cấu hình biến môi trường

Các biến quan trọng trong `.env`:

```env
# Database - Chỉ cần DATABASE_URL
DATABASE_URL=mysql+mysqlconnector://waf:wafadmin@127.0.0.1:3306/wafdb

# WAF Configuration
WAF_LISTEN_PORT=8080
WAF_BACKEND_ADDRESS=http://127.0.0.1:80
WAF_BLOCK_THRESHOLD=3

# Admin Panel
ADMIN_LISTEN_PORT=5000
ADMIN_SECRET_KEY=your-secret-key
ADMIN_ALLOWED_IPS=127.0.0.1,192.168.232.1,::1
```

## Migration từ phiên bản cũ

1. **Database sẽ được tự động khởi tạo** khi chạy ứng dụng lần đầu
2. **Không cần chạy `createdb.py`** nữa
3. **Cấu hình trong `.env`** thay vì hardcode trong code
4. **Import statements** đã được cập nhật để sử dụng models từ file riêng

## Troubleshooting

### Lỗi kết nối database
- Kiểm tra cấu hình trong `.env`
- Đảm bảo MySQL đang chạy (nếu sử dụng MySQL)
- Kiểm tra firewall và network connectivity

### Lỗi import
- Đảm bảo đã cài đặt tất cả dependencies trong `requirements.txt`
- Kiểm tra Python path và cấu trúc thư mục

### Lỗi permission
- Kiểm tra quyền truy cập database
- Đảm bảo user có quyền tạo bảng (nếu chạy lần đầu)

## API Usage

### Database Session
```python
# Sử dụng SessionLocal
session = SessionLocal()
try:
    # database operations
    session.commit()
except:
    session.rollback()
finally:
    session.close()
```

### Models
```python
# Import models và SessionLocal
from shared.database import SessionLocal, Rule, IPBlacklist, ActivityLog
```

### Tạo bảng
```python
# Bảng được tự động tạo khi import database module
from shared.database import SessionLocal  # Bảng đã được tạo
```