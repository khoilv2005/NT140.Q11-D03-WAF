# WAF (Web Application Firewall) System

## 📋 Mô tả

Hệ thống WAF được xây dựng với Flask, hỗ trợ reverse proxy với khả năng:
- Kiểm tra và chặn các request độc hại theo rules
- Quản lý IP blacklist tự động
- Giao diện admin để quản lý rules và logs
- Hỗ trợ nhiều target types: URL, Headers, Body, Args, Filenames
- Deep decoding cho các payload được encode
- Phân loại rules theo categories

## 🏗️ Kiến trúc hệ thống

```
Internet → Nginx (Port 80/443) → WAF App (Port 8080) → Backend Application
                                      ↓
                              Admin Panel (Port 5000)
                                      ↓
                               MySQL Database (Port 3306)
```

## 📂 Cấu trúc thư mục

```
NT140.Q11-D03-WAF/
├── Readme.md
├── requirements.txt
├── .env                          # Cấu hình environment
├── shared/
│   ├── database.py               # Kết nối database & session management
│   └── models.py                 # SQLAlchemy models (Rule, IPBlacklist, ActivityLog)
├── WAF_admin/
│   ├── main.py                   # Admin panel Flask app
│   └── templates/
│       ├── admin_dashboard.html  # Dashboard với statistics
│       ├── manage_rules.html     # Quản lý WAF rules
│       └── error_403.html        # Error page
├── WAF_app/
│   ├── main.py                   # WAF reverse proxy
│   ├── decoder.py                # Deep decode functions
│   └── templates/
│       └── error_403.html        # Blocked request page
├── sample_rules.json             # Example rules
└── TARGET_TYPES_GUIDE.md         # Documentation
```

## 🚀 Cài đặt và chạy

### 1. Cài đặt dependencies

```bash
pip install -r requirements.txt
```

### 2. Cấu hình database

#### Option A: MySQL (Recommended for Production)
```bash
# Chạy MySQL container
sudo docker run --name waf-mysql \
  -e MYSQL_ROOT_PASSWORD=my-secret-pw \
  -e MYSQL_DATABASE=wafdb \
  -e MYSQL_USER=waf \
  -e MYSQL_PASSWORD=wafadmin \
  -v waf-mysql-data:/var/lib/mysql \
  -p 3306:3306 -d mysql:latest

# Kiểm tra kết nối
sudo docker exec -it waf-mysql mysql -u waf -p wafdb
```

#### Option B: SQLite (Development)
```bash
# Database sẽ được tạo tự động khi chạy app
```

### 3. Cấu hình environment

Chỉnh sửa file `.env`:
```bash
# Database Configuration
DATABASE_URL=mysql+mysqlconnector://waf:wafadmin@127.0.0.1:3306/wafdb
# Hoặc SQLite: DATABASE_URL=sqlite:///waf_database.db

# WAF Configuration
WAF_LISTEN_HOST=127.0.0.1
WAF_LISTEN_PORT=8080
WAF_BACKEND_ADDRESS=http://127.0.0.1:3000  # Your backend app
WAF_BLOCK_THRESHOLD=3

# Admin Panel Configuration
ADMIN_LISTEN_HOST=127.0.0.1
ADMIN_LISTEN_PORT=5000
ADMIN_SECRET_KEY=your_super_secret_key_here
ADMIN_ALLOWED_IPS=127.0.0.1,192.168.1.0/24
```

### 4. Chạy các services

#### Terminal 1: WAF Application
```bash
cd WAF_app
python3 main.py
```

#### Terminal 2: Admin Panel
```bash
cd WAF_admin
python3 main.py
```

### 5. Truy cập

- **WAF Service**: http://localhost:8080
- **Admin Panel**: http://localhost:5000
- **Backend được bảo vệ**: Tất cả traffic đi qua WAF

## 🔧 Cấu hình WAF Rules

### Target Types hỗ trợ:

| Target Type | Mô tả | Ví dụ |
|-------------|-------|-------|
| `URL_PATH` | Đường dẫn URL | `/admin`, `/wp-admin` |
| `URL_QUERY` | Query string | `?id=1&name=test` |
| `HEADERS:X-Header` | HTTP Headers | `User-Agent`, `X-Forwarded-For` |
| `BODY` | Request body | POST/PUT data |
| `ARGS` | Parameter values | Form data, URL params |
| `ARGS_NAMES` | Parameter names | Field names |
| `FILENAME` | Upload filenames | File upload names |

### Operators:

- `CONTAINS`: Chứa chuỗi con
- `REGEX`: Biểu thức chính quy

### Categories:

- `SQL Injection`
- `XSS`
- `Path Traversal`
- `Command Injection`
- `File Upload`
- `CSRF`
- `Rate Limiting`
- `General Security`

## 📊 Tính năng chính

### WAF Application (`WAF_app/main.py`)
- ✅ Reverse proxy với inspection
- ✅ Deep decode (URL + HTML + Base64)
- ✅ Hỗ trợ 7 target types
- ✅ Auto IP blocking sau n vi phạm
- ✅ Real-time rule matching
- ✅ Activity logging

### Admin Panel (`WAF_admin/main.py`)
- ✅ Dashboard với statistics
- ✅ Rule management (CRUD)
- ✅ Category-based organization
- ✅ Activity logs viewer
- ✅ IP blacklist management
- ✅ Cache reload functionality

### Database Models
- ✅ `Rule`: WAF rules với categories
- ✅ `IPBlacklist`: Blocked IPs
- ✅ `ActivityLog`: Request logs

## 🔒 Bảo mật Production

### 1. Nginx Reverse Proxy
```nginx
# /etc/nginx/sites-available/waf
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8080;  # WAF
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 2. Firewall Rules
```bash
# Chỉ cho phép Nginx truy cập WAF
iptables -A INPUT -p tcp --dport 8080 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP

# Chặn direct access to backend
iptables -A INPUT -p tcp --dport 3000 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -j DROP
```

### 3. Environment Security
- Thay đổi `ADMIN_SECRET_KEY`
- Giới hạn `ADMIN_ALLOWED_IPS`
- Sử dụng HTTPS trong production
- Backup database định kỳ

## 📝 API Endpoints

### WAF App
- `/*` - All traffic (reverse proxy)
- `/reset-db-management` - Reload cache (POST, IP restricted)

### Admin Panel
- `/` - Dashboard
- `/rules` - Manage rules
- `/rules/add` - Add new rule
- `/rules/edit/<id>` - Edit rule
- `/rules/delete/<id>` - Delete rule
- `/logs` - View activity logs
- `/blacklist` - Manage IP blacklist

## 🐛 Troubleshooting

### Database Connection Issues
```bash
# Check MySQL container
sudo docker ps | grep waf-mysql
sudo docker logs waf-mysql

# Test connection
mysql -u waf -p -h 127.0.0.1 wafdb
```

### WAF Not Blocking
1. Check rules are enabled in admin panel
2. Verify cache reload: `POST /reset-db-management`
3. Check logs in terminal output
4. Test with simple rule first

### Performance Issues
1. Enable MySQL query cache
2. Add database indexes
3. Optimize regex patterns
4. Consider Redis for session storage

## 📈 Monitoring

### Logs Location
- WAF App: Terminal output + database
- Admin Panel: Terminal output
- Nginx: `/var/log/nginx/`

### Key Metrics
- Blocked requests per hour
- Top triggered rules
- Response time impact
- False positive rate

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Test thoroughly
4. Submit pull request

## 📄 License

Educational purpose - NT140.Q11 Course Project