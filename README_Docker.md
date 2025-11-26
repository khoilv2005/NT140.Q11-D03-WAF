# WAF Docker Setup

## Tổng quan

Docker setup này bao gồm:
- **MySQL Database**: Cơ sở dữ liệu lưu trữ rules, logs, và blacklist
- **WAF App**: Ứng dụng WAF chính (port 8080)
- **Admin Panel**: Giao diện quản lý WAF (port 5000)
- **Backend**: Web server backend để test (port 99)

## Cài đặt và Chạy

### 1. Khởi động toàn bộ hệ thống
```bash
docker-compose up -d
```

### 2. Kiểm tra trạng thái
```bash
docker-compose ps
docker-compose logs -f
```

### 3. Truy cập các dịch vụ
- **Admin Panel**: http://localhost:5000
- **WAF**: http://localhost:8080 (sẽ proxy đến backend)
- **Backend trực tiếp**: http://localhost:99
- **MySQL**: localhost:3306

### 4. Dừng hệ thống
```bash
docker-compose down
```

### 5. Xóa toàn bộ dữ liệu
```bash
docker-compose down -v
```

## Cấu hình

### Environment Variables
Các biến môi trường có thể được thay đổi trong `docker-compose.yml`:

**WAF App:**
- `DATABASE_URL`: Chuỗi kết nối database
- `WAF_LISTEN_HOST`: Host lắng nghe (mặc định: 0.0.0.0)
- `WAF_LISTEN_PORT`: Port WAF (mặc định: 8080)
- `WAF_BACKEND_ADDRESS`: Địa chỉ backend (mặc định: http://backend:99)
- `WAF_BLOCK_THRESHOLD`: Ngưỡng block IP (mặc định: 3)

**Admin Panel:**
- `ADMIN_LISTEN_HOST`: Host lắng nghe (mặc định: 0.0.0.0)
- `ADMIN_LISTEN_PORT`: Port admin (mặc định: 5000)
- `ADMIN_SECRET_KEY`: Secret key cho session
- `ADMIN_ALLOWED_IPS`: IP được phép truy cập admin

**MySQL:**
- `MYSQL_ROOT_PASSWORD`: Mật khẩu root
- `MYSQL_DATABASE`: Tên database
- `MYSQL_USER`: User WAF
- `MYSQL_PASSWORD`: Mật khẩu user WAF

## Test WAF

### Test với các request hợp lệ
```bash
curl http://localhost:8080/
```

### Test với SQL Injection
```bash
curl "http://localhost:8080/?id=1' OR '1'='1"
```

### Test với XSS
```bash
curl "http://localhost:8080/?search=<script>alert('xss')</script>"
```

### Test với Path Traversal
```bash
curl "http://localhost:8080/?file=../../../etc/passwd"
```

## Logs
- Application logs: `./logs/` (volume mapped)
- Container logs: `docker-compose logs waf_app`
- Database logs: `docker-compose logs mysql`

## Development

### Build lại containers
```bash
docker-compose build --no-cache
```

### Chạy chỉ một service
```bash
docker-compose up -d mysql
docker-compose up -d waf_app
```

### Debug
```bash
docker-compose exec waf_app python main.py
docker-compose exec admin_panel python main.py
```

## Tối ưu
- Sử dụng `.dockerignore` để giảm kích thước build
- Cache dependencies với multi-stage builds
- Health checks để đảm bảo service sẵn sàng
- Volumes cho persistent data