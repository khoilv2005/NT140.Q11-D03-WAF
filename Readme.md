# WebGuard: An Explainable Hybrid WAF using Attention-based CNN-BiLSTM for Evasive Attack Detection

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://docker.com)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-orange.svg)](https://mysql.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**WebGuard** is a **Web Application Firewall (WAF)** that combines rule-based detection with **Deep Learning** (Attention-based CNN-BiLSTM) to detect web attacks, including evasive attacks. The system integrates **LIME XAI** for explainable decision-making.

### Project Contribution

**Le Van Khoi:** WebGuard architecture, hybrid rule/ML detection, explainability integration, and security hardening.

**[Tiếng Việt](README.vi.md)**

---

## Table of Contents

- [Features](#-features)
- [System Architecture](#-system-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [API Endpoints](#-api-endpoints)
- [Admin Panel](#-admin-panel)
- [Deep Learning](#-deep-learning)
- [Project Structure](#-project-structure)

---

## Features

### Rule-based Detection
- **SQL Injection** - Detect common SQL injection patterns
- **XSS (Cross-Site Scripting)** - Block malicious scripts
- **Path Traversal** - Prevent unauthorized directory access
- **Command Injection** - Detect shell command injection
- **IP Blacklist** - Auto-block IPs with multiple violations

### Deep Learning Detection
- **Deep Learning Model** - PyTorch model with Attention mechanism
- **ONNX Runtime** - Fast inference with ONNX optimization
- **LIME XAI** - Explain attack detection decisions
- **Character-level Tokenization** - Detect obfuscated payloads

### Admin Panel
- **Dashboard** - Real-time activity monitoring
- **Rule Management** - Add/Edit/Delete rules
- **IP Blacklist** - Manage blocked IP addresses
- **Activity Logs** - View request history with pagination

---

## System Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│     Client      │────▶│   WAF Proxy     │────▶│  Backend App    │
│                 │     │  (Port 8080)    │     │  (Your App)     │
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
              ┌─────▼─────┐ ┌────▼────┐ ┌─────▼─────┐
              │   Rule    │ │   ML    │ │   MySQL   │
              │  Engine   │ │ Engine  │ │  Database │
              └───────────┘ └─────────┘ └───────────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │   Admin Panel     │
                                    │   (Port 5000)     │
                                    └───────────────────┘
```

---

## Installation

### Requirements
- **Docker** & **Docker Compose**
- **Git**

### Step 1: Clone repository

```bash
git clone <repository-url>
cd NT140.Q11-D03-WAF
```

### Step 2: Configure environment

```bash
cp .env.example .env
```

Edit the `.env` file as needed (see [Configuration](#-configuration)).

### Step 3: Run with Docker Compose

```bash
docker-compose up -d
```

### Step 4: Verify services

```bash
# Check running containers
docker-compose ps

# View logs
docker-compose logs -f waf_app
docker-compose logs -f waf_admin
```

---

## Configuration

### `.env` File

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `MYSQL_ROOT_PASSWORD` | MySQL root password | Must be set in `.env` |
| `MYSQL_DATABASE` | Database name | `wafdb` |
| `MYSQL_USER` | MySQL username | `waf` |
| `MYSQL_PASSWORD` | MySQL password | Must be set in `.env` |
| `WAF_LISTEN_PORT` | WAF listening port | `8080` |
| `WAF_BACKEND_ADDRESS` | Backend app address | `http://host.docker.internal:8888` |
| `WAF_BLOCK_THRESHOLD` | IP block threshold | `100000` |
| `WAF_ML_ENABLED` | Enable/disable ML detection | `true` |
| `WAF_ML_CONFIDENCE_THRESHOLD` | ML confidence threshold | `0.5` |
| `WAF_ML_LIME_ENABLED` | Enable/disable LIME XAI | `false` |
| `ADMIN_LISTEN_PORT` | Admin Panel port | `5000` |
| `ADMIN_SECRET_KEY` | Flask secret key | Must be set to a random value |
| `ADMIN_ALLOWED_IPS` | Allowed IP list | `127.0.0.1,::1` |

### ML Configuration

```bash
# Enable ML detection
WAF_ML_ENABLED=true

# Confidence threshold (0.0 - 1.0)
# Lower = more sensitive, Higher = fewer false positives
WAF_ML_CONFIDENCE_THRESHOLD=0.5

# Enable LIME explanations (affects performance)
WAF_ML_LIME_ENABLED=false
```

---

## Usage

### Access Services

| Service | URL | Description |
|---------|-----|-------------|
| **WAF Proxy** | `http://localhost:8080` | WAF reverse proxy |
| **Admin Panel** | `http://localhost:5000` | WAF management |
| **MySQL** | `localhost:3306` | Database |

### Test WAF with curl

```bash
# Valid request
curl http://localhost:8080/

# Test SQL Injection (will be blocked)
curl "http://localhost:8080/?id=1' OR '1'='1"

# Test XSS (will be blocked)
curl "http://localhost:8080/?q=<script>alert(1)</script>"

# Test Path Traversal (will be blocked)
curl "http://localhost:8080/../../../etc/passwd"
```

---

## API Endpoints

### WAF Application (Port 8080)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/{path:path}` | ALL | Reverse proxy to backend |
| `/health` | GET | Health check endpoint |
| `/reset-db-management` | POST | Reload rules from database |

### Admin Panel (Port 5000)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/api/logs/latest` | GET | Get logs API (AJAX) |
| `/rules` | GET | View rules list |
| `/rules/add` | GET, POST | Add new rule |
| `/rules/delete/<id>` | POST | Delete rule |
| `/rules/delete-all` | POST | Delete all rules |
| `/rules/import` | POST | Import rules from JSON |
| `/blacklist` | GET | View IP blacklist |
| `/blacklist/remove/<ip>` | POST | Remove IP from blacklist |
| `/reset-all` | POST | Reset all data |

---

## Admin Panel

### Dashboard
- View overall statistics (total requests, blocked, allowed)
- Real-time activity log with auto-refresh
- Analytics charts

### Rule Management
- Add/edit/delete rules
- Import rules from JSON file
- Categorize by type: SQLi, XSS, Path Traversal, etc.

### IP Blacklist
- View blocked IP list
- Remove IP from blacklist
- View triggering rule

---

## Deep Learning

### Overview

The system uses a custom **Deep Learning** model built with **PyTorch**, combining multiple advanced techniques for high-accuracy web attack detection.

### Model Architecture: WAF_Attention_Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     INPUT (Character-level)                     │
│                    Max Length: 500 characters                   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      EMBEDDING LAYER                            │
│              Vocab Size → Embedding Dim (128)                   │
│                    + Dropout (0.1)                              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│               CNN FEATURE EXTRACTION                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ ResBlock 1  │→ │ ResBlock 2  │→ │ ResBlock 3  │             │
│  │  128 → 128  │  │  128 → 256  │  │  256 → 256  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│         + Squeeze-and-Excitation (SE) Attention                 │
│         + MaxPool + Dropout                                     │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              MULTI-HEAD SELF-ATTENTION                          │
│                    8 Attention Heads                            │
│              + Layer Normalization                              │
│              + Residual Connections                             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│               BI-DIRECTIONAL LSTM                               │
│                  2 Layers, 256 Hidden                           │
│                  + Attention Pooling                            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                CLASSIFICATION HEAD                              │
│    Dense(512→256) → GELU → Dense(256→128) → Dense(128→1)       │
│              + Layer Norm + Dropout                             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      OUTPUT                                     │
│           Sigmoid → Probability (0: Normal, 1: Attack)          │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| **Multi-Head Self-Attention** | 8 heads to capture relationships between characters in payload |
| **Residual Blocks** | Skip connections for efficient deep network training |
| **SE Block (Squeeze-Excitation)** | Channel attention to focus on important features |
| **Bi-LSTM** | Capture context from both directions of sequence |
| **GELU Activation** | Smooth activation function, more effective than ReLU |
| **Layer Normalization** | Stabilize training and accelerate convergence |

### Training Pipeline

| Technique | Details |
|-----------|---------|
| **Loss Function** | Focal Loss (α=0.25, γ=2.0) - handles class imbalance |
| **Optimizer** | AdamW with weight decay |
| **Label Smoothing** | 0.1 - helps model generalize better |
| **Tokenization** | Character-level - detects payload obfuscation |
| **Mixed Precision** | FP16 training for faster speed |

### ONNX Optimization

Model is exported to **ONNX** format for faster inference in production:

```python
# Inference with ONNX Runtime
ML_FORCE_ONNX=true
ML_MODEL_ONNX_PATH=/app/models/waf_model.onnx
```

| Metric | PyTorch | ONNX Runtime |
|--------|---------|--------------|
| **Latency** | ~15ms | ~3ms |
| **Memory** | ~500MB | ~150MB |
| **Throughput** | ~65 req/s | ~300 req/s |

### Explainable AI (XAI) with LIME

When `WAF_ML_LIME_ENABLED=true`, the system uses **LIME (Local Interpretable Model-agnostic Explanations)** to:

1. **Explain decisions** - Highlight tokens contributing to prediction
2. **Detect patterns** - Auto-detect SQL, XSS, command injection patterns
3. **Debug & Audit** - Detailed logging of block reasons

```
Example LIME Output:
─────────────────────────────────────
Request: /search?q=1' OR '1'='1
Prediction: ATTACK (confidence: 0.98)

Top contributing tokens:
  [+0.45] OR
  [+0.32] '1'='1
  [+0.21] '
─────────────────────────────────────
```

### Files & Models

| File | Size | Description |
|------|------|-------------|
| `waf_model.onnx` | ~15MB | ONNX model for production |
| `waf_model.pth` | ~15MB | PyTorch checkpoint |
| `tokenizer_word_index.json` | ~1KB | Character vocabulary |
| `model.py` | - | Model architecture definition |
| `train.py` | - | Training script |
| `preprocess.py` | - | Data preprocessing |

### Deep Learning Configuration

```bash
# Enable/disable Deep Learning detection
WAF_ML_ENABLED=true

# Confidence threshold (0.0 - 1.0)
# Higher = fewer false positives, Lower = detects more
WAF_ML_CONFIDENCE_THRESHOLD=0.5

# Enable LIME explanations (adds ~100ms latency)
WAF_ML_LIME_ENABLED=false

# Force ONNX usage (recommended for production)
ML_FORCE_ONNX=true
```

---

## Project Structure

```
NT140.Q11-D03-WAF/
├── WAF_app/                      # WAF Application
│   ├── main.py                   # FastAPI reverse proxy
│   ├── ml_predictor.py           # ML inference engine
│   ├── decoder.py                # URL/HTML decoder
│   ├── Dockerfile
│   └── models/                   # ML models
│       ├── waf_model.onnx
│       └── tokenizer_word_index.json
│
├── WAF_admin/                    # Admin Panel
│   ├── main.py                   # Flask application
│   ├── Dockerfile
│   └── templates/                # HTML templates
│       └── admin_dashboard.html
│
├── shared/                       # Shared code
│   ├── models.py                 # SQLAlchemy models
│   └── database.py               # Database connection
│
├── rules/                        # WAF rules
│   └── complete_rules_import.json
│
├── docker-compose.yml            # Docker Compose config
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment template
└── README.md                     # This file
```

---

## Database Schema

### Tables

| Table | Description |
|-------|-------------|
| `rules` | WAF rules |
| `ip_blacklist` | Blocked IP list |
| `activity_log` | Activity logs |

### Rule Structure

```json
{
  "id": 1,
  "enabled": true,
  "description": "SQL Injection - Basic",
  "category": "SQLi",
  "severity": "HIGH",
  "target": "REQUEST_URI",
  "operator": "rx",
  "value": "(?i)(union\\s+select|select.*from)",
  "action": "BLOCK"
}
```

---

## Docker Commands

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f

# Rebuild containers
docker-compose up -d --build

# Access container
docker exec -it waf_app bash
docker exec -it waf_admin bash
docker exec -it waf_mysql mysql -u waf -p
```

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Contributors

- **NT140.Q11 - Group 6** - University of Information Technology (UIT)

---

## Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [Flask](https://flask.palletsprojects.com/) - Lightweight Python web framework
- [ONNX Runtime](https://onnxruntime.ai/) - High-performance inference
- [LIME](https://github.com/marcotcr/lime) - Explainable AI
- [SQLAlchemy](https://www.sqlalchemy.org/) - Python SQL toolkit
- [PyTorch](https://pytorch.org/) - Deep learning framework
