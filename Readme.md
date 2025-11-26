# WAF (Web Application Firewall) System

Một hệ thống Web Application Firewall hoàn chỉnh được xây dựng với Flask và SQLAlchemy, cung cấp bảo vệ thời gian thực chống lại các cuộc tấn công web phổ biến.

## 🏗️ Kiến trúc

Hệ thống WAF bao gồm 4 thành phần chính:

### 1. **WAF App** (Port 8080)
- Flask application hoạt động như reverse proxy
- Inspect và filter HTTP requests dựa trên rules
- Auto-ban IPs khi vượt ngưỡng violations
- Logging tất cả activities

### 2. **Admin Panel** (Port 5000)
- Web interface để quản lý WAF
- Dashboard với thống kê real-time
- Quản lý security rules
- Quản lý IP blacklist
- Import/Export rules

### 3. **MySQL Database**
- Lưu trữ security rules
- Log activities và violations
- Blacklist management

### 4. **Backend Service** (Port 8888)
- Web application được bảo vệ (bWAPP)
- Backend thực tế mà WAF bảo vệ

## 🚀 Quick Start

### Yêu cầu
- Docker và Docker Compose
- Git

### Installation

1. **Clone repository:**
```bash
git clone <repository-url>
cd NT140.Q11-D03-WAF
```

2. **Cấu hình môi trường:**
```bash
# Copy file môi trường và chỉnh sửa
cp .env.example .env
nano .env  # Chỉnh các giá trị cần thiết
```

3. **Khởi động hệ thống:**
```bash
docker-compose up -d --build
```

4. **Import WAF rules:**
   - Mở browser: http://localhost:5000
   - Vào trang "Manage Rules"
   - Import rules từ file JSON có sẵn

## 📊 Services và Ports

| Service | Port | Description |
|---------|------|-------------|
| WAF App | 8080 | WAF proxy server |
| Admin Panel | 5000 | Web management interface |
| MySQL | 3306 | Database server |
| Backend | 8888 | Protected web application |

## 🔧 Cấu hình

### Environment Variables

Sao chép `.env.example` sang `.env` và tùy chỉnh:

```bash
# MySQL Configuration
MYSQL_ROOT_PASSWORD=rootpassword
MYSQL_DATABASE=wafdb
MYSQL_USER=waf
MYSQL_PASSWORD=wafadmin

# WAF Configuration
WAF_BACKEND_ADDRESS=http://host.docker.internal:8888
WAF_BLOCK_THRESHOLD=100000  # Số violations trước khi auto-ban
WAF_LISTEN_HOST=0.0.0.0
WAF_LISTEN_PORT=8080

# Admin Panel Configuration
ADMIN_SECRET_KEY=your_secret_key_here
ADMIN_ALLOWED_IPS=127.0.0.1,192.168.1.1,172.18.0.1,::1
ADMIN_LISTEN_PORT=5000
```

## 🛡️ Security Features

### 1. **Rule Engine**
- Support multiple operators: CONTAINS, REGEX
- Multiple targets: URL_PATH, URL_QUERY, BODY, ARGS, HEADERS
- Categories: SQL Injection, XSS, Bot Protection, Path Traversal, etc.

### 2. **Auto-ban System**
- Auto-blacklist IPs khi vượt ngưỡng violations
- Configurable block threshold (default: 100000 for testing)
- Manual IP management through admin panel
- **Smart IP Removal**: Xóa IP khỏi blacklist sẽ reset violation count

### 3. **Real-time Monitoring**
- Live dashboard với AJAX updates (5-second intervals)
- Request filtering và pagination (100 logs per page)
- Category-based statistics
- Clickable stat cards for filtering
- Smart log highlighting without flashing

### 4. **Request Processing**
- URL decoding và deep inspection
- Multi-layer request analysis
- Custom response codes for blocked requests

## 📁 Project Structure

```
NT140.Q11-D03-WAF/
├── WAF_app/                    # WAF Application
│   ├── main.py                 # Main WAF logic
│   ├── decoder.py              # Request decoder
│   └── Dockerfile              # Docker config
├── WAF_admin/                  # Admin Panel
│   ├── main.py                 # Admin application
│   └── templates/              # Admin HTML templates
│       ├── admin_dashboard.html
│       ├── manage_rules.html
│       └── blacklist.html
├── shared/                     # Shared modules
│   └── database.py             # Database models and functions
├── backend_content/            # Protected web content
├── docker-compose.yml          # Docker orchestration
├── .env.example                # Environment template
├── Dockerfile_WAF              # Docker build file
└── README.md                   # This file
```

## 🔌 API Endpoints

### Admin Panel API
- `GET /` - Admin dashboard
- `GET /api/logs/latest?page=1&per_page=100` - Real-time logs (AJAX)
- `GET /manage-rules` - Rule management
- `POST /add-rule` - Add new rule
- `POST /delete-rule/<id>` - Delete rule
- `GET /blacklist` - View blacklist management
- `POST /remove-from-blacklist/<ip>` - Remove IP from blacklist

### WAF API
- `ALL REQUESTS` - WAF processes all HTTP requests
- `POST /reset-db-management` - Reload rules cache

## 🛠️ Management

### Access Admin Panel
1. Mở browser: http://localhost:5000
2. IP được phép: 127.0.0.1, 192.168.1.1, 172.18.0.1, ::1

### Testing WAF
```bash
# Test legitimate request
curl http://localhost:8080/

# Test SQL injection (should be blocked)
curl "http://localhost:8080/login.php?id=1' OR '1'='1"

# Test with special payload
curl "http://localhost:8080/login.php?test%27%20OR%20%271%27%3D%271"
```

### Rule Management
- **Add Rules**: Manual form input hoặc JSON import
- **Categories**: SQL Injection, XSS, Bot Protection, Path Traversal, Command Injection, File Upload, Rate Limiting, Custom, NoSQL Injection
- **Targets**: URL_PATH, URL_QUERY, BODY, ARGS, ARGS_NAMES, FILENAME, HEADERS
- **Operators**: CONTAINS, REGEX, REGEX_MATCH

### Blacklist Management
- **Auto-ban**: IPs tự động thêm vào blacklist khi vượt ngưỡng violations
- **Manual ban**: Add IPs thủ công qua admin panel
- **Smart removal**: Xóa IP sẽ reset violation count và xóa logs BLOCKED
- **Real-time updates**: Blacklist status updates immediately

## 🚨 Security Considerations

### Production Deployment
1. **Change Default Secrets:**
   - ADMIN_SECRET_KEY
   - MySQL passwords
   - Database credentials

2. **Network Security:**
   - Configure proper firewall rules
   - Use HTTPS in production
   - Restrict admin panel access
   - Don't expose WAF app directly to internet

3. **Monitoring:**
   - Monitor WAF logs regularly
   - Set up alerting for high violation rates
   - Backup configuration và rules

### Performance
- Database optimization for high traffic
- Rule caching optimization
- Log rotation setup
- Consider Redis for distributed caching

## 🐛 Troubleshooting

### Common Issues

1. **Services không start:**
   ```bash
   docker-compose logs [service_name]
   ```

2. **Database connection errors:**
   - Check MySQL container status
   - Verify DATABASE_URL configuration
   - Ensure proper network connectivity

3. **Rules không load:**
   - Check database connection
   - Verify rule format in JSON
   - Reload cache: POST /reset-db-management

4. **IP không được unblocked:**
   - Restart WAF service
   - Check violation logs
   - Verify IP removal from database

### Debug Mode
Enable debug logging:
```bash
# Edit .env
LOG_LEVEL=DEBUG

# Restart services
docker-compose restart
```

## 📈 Monitoring và Logging

### Log Locations
- **WAF App**: `./logs/` directory
- **Admin Panel**: Container logs
- **MySQL**: Database logs

### Metrics Available in Dashboard
- Total requests
- Blocked vs allowed requests
- Active rules count
- Blacklisted IPs count
- Violations by IP
- Rule trigger statistics
- Category-based breakdown

### Real-time Features
- **AJAX Log Updates**: 5-second intervals
- **Filter by Status**: Click stat cards to filter ALLOWED/BLOCKED
- **Pagination**: Navigate through large log sets
- **Smart Highlighting**: New logs highlighted without constant flashing

## 🔄 Maintenance

### Regular Tasks
1. **Review and update rules**
2. **Monitor blocked IPs**
3. **Analyze attack patterns**
4. **Backup configuration**
5. **Update WAF signatures**
6. **Clean old logs** to prevent database bloat

### Backup và Restore
```bash
# Backup database
docker exec waf_mysql mysqldump -u root -p wafdb > backup.sql

# Restore database
docker exec -i waf_mysql mysql -u root -p wafdb < backup.sql
```

### Environment Configuration
All configuration is managed through environment variables in `.env`:
- No hardcoded values in code
- Production-ready configuration management
- Easy deployment across environments
- Security-focused defaults

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit pull request

## 📄 License

This project is for educational purposes. Use responsibly and in compliance with applicable laws and regulations.

---

**Quick Test Commands:**
```bash
# Check if services are running
docker-compose ps

# Check WAF logs
docker logs waf_app

# Access admin dashboard
open http://localhost:5000

# Test WAF protection
curl "http://localhost:8080/login.php?select%20*%20from%20users"
```