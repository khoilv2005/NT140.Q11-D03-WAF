# WAF Target Types Documentation

## 📋 Available Target Types

### 1. **URL_PATH** 
- **Mô tả**: Đường dẫn URL (phần sau domain)
- **Ví dụ**: `/admin/login.php`, `/api/users`
- **Use case**: Chặn truy cập các path nhạy cảm

### 2. **URL_QUERY**
- **Mô tả**: Query string parameters trong URL  
- **Ví dụ**: `?id=1&name=test` → `id=1&name=test`
- **Use case**: Phát hiện SQL injection, XSS trong GET parameters

### 3. **BODY**
- **Mô tả**: Nội dung body của POST/PUT requests
- **Ví dụ**: Form data, JSON payload, raw body
- **Use case**: Kiểm tra dữ liệu được submit qua forms

### 4. **ARGS** ⭐ *NEW*
- **Mô tả**: Tất cả giá trị parameters từ GET và POST
- **Ví dụ**: `?user=admin&pass=123` + POST `email=test@test.com` → Kiểm tra: `["admin", "123", "test@test.com"]`
- **Use case**: Phát hiện payload malicious trong bất kỳ parameter nào

### 5. **ARGS_NAMES** ⭐ *NEW*
- **Mô tả**: Tên của tất cả parameters từ GET và POST
- **Ví dụ**: `?user=admin&pass=123` + POST `email=test` → Kiểm tra: `["user", "pass", "email"]`  
- **Use case**: Chặn parameter names nguy hiểm như `cmd`, `exec`, `eval`

### 6. **FILENAME** ⭐ *NEW*
- **Mô tả**: Tên file trong file uploads
- **Ví dụ**: Upload file `shell.php` → Kiểm tra: `shell.php`
- **Use case**: Chặn upload các file extension nguy hiểm

### 7. **HEADERS:***
- **Mô tả**: Giá trị của HTTP headers cụ thể
- **Các options phổ biến**:
  - `HEADERS:User-Agent` - Browser/client info
  - `HEADERS:Referer` - Previous page URL
  - `HEADERS:Cookie` - Session cookies
  - `HEADERS:Content-Type` - MIME type của request

## 🎯 Examples & Use Cases

### **SQL Injection Protection**
```json
{
  "target": "ARGS",
  "operator": "CONTAINS", 
  "value": "union select"
}
```
↳ Chặn SQL injection trong bất kỳ parameter nào

### **Malicious Parameter Names**
```json
{
  "target": "ARGS_NAMES",
  "operator": "REGEX",
  "value": "(cmd|exec|eval|system)"
}
```
↳ Chặn parameters có tên nguy hiểm

### **File Upload Security**
```json
{
  "target": "FILENAME", 
  "operator": "REGEX",
  "value": "\\.(php|jsp|asp|exe|sh)$"
}
```
↳ Chặn upload file có extension nguy hiểm

### **Bot Detection**
```json
{
  "target": "HEADERS:User-Agent",
  "operator": "CONTAINS",
  "value": "sqlmap"
}
```
↳ Chặn automated security tools

## 🔍 Deep Decoding Support

Tất cả target types đều hỗ trợ **deep decoding**:
- **URL encoding** (`%20`, `%3C`)
- **HTML entities** (`&lt;`, `&#105;`) 
- **Base64 encoding** (multiple layers)
- **JavaScript escapes** (`\uXXXX`)

### Example:
```
Input:  ?search=%3Cscript%3Ealert(1)%3C/script%3E
Decoded: ?search=<script>alert(1)</script>
Rule matches: XSS detection
```

## ⚡Performance Notes

- **ARGS** và **ARGS_NAMES**: Kiểm tra multiple values → có thể slower
- **FILENAME**: Chỉ active khi có file upload
- **URL_PATH**, **URL_QUERY**: Single value → fastest
- **HEADERS**: Single value lookup → fast

## 🛡️ Security Best Practices

### 1. **Layer Defense**
```json
[
  {"target": "URL_QUERY", "value": "<script"},
  {"target": "ARGS", "value": "<script"},  
  {"target": "BODY", "value": "<script"}
]
```

### 2. **Parameter Name Security**
```json
{
  "target": "ARGS_NAMES",
  "operator": "REGEX", 
  "value": "(password|passwd|pwd).*plain"
}
```

### 3. **File Upload Restrictions**
```json
[
  {"target": "FILENAME", "value": "\\.php$"},
  {"target": "FILENAME", "value": "\\.exe$"},
  {"target": "HEADERS:Content-Type", "value": "application/x-executable"}
]
```

## 🧪 Testing Your Rules

### Test ARGS:
```bash
curl "localhost:8080/test?id=<script>alert(1)</script>"
```

### Test ARGS_NAMES:
```bash  
curl "localhost:8080/test?cmd=ls&normal=value"
```

### Test FILENAME:
```bash
curl -F "file=@shell.php" localhost:8080/upload
```

### Test Headers:
```bash
curl -H "User-Agent: sqlmap/1.0" localhost:8080/test
```