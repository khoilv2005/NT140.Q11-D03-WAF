# -*- coding: utf-8 -*-
"""
🛡️ FLASK WAF MIDDLEWARE - VÍ DỤ ĐƠN GIẢN
==========================================
Tích hợp CNN-BiLSTM WAF model vào Flask application
"""

from flask import Flask, request, jsonify, abort
import torch
import pickle
import numpy as np
from functools import wraps
import time
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# WAF MODEL LOADER
# ============================================================================

class WAFDetector:
    """WAF Detection Engine using trained CNN-BiLSTM model"""
    
    def __init__(self, model_path='./data/waf_model.pth', 
                 tokenizer_path='./data/tokenizer.pkl',
                 threshold=0.5):
        """
        Khởi tạo WAF Detector
        
        Args:
            model_path: Đường dẫn đến model đã train
            tokenizer_path: Đường dẫn đến tokenizer
            threshold: Ngưỡng phân loại (0.5 = balanced)
        """
        self.threshold = threshold
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Load tokenizer
        logger.info("Loading tokenizer...")
        with open(tokenizer_path, 'rb') as f:
            self.tokenizer = pickle.load(f)
        
        # Load model
        logger.info("Loading WAF model...")
        from model import WAF_Attention_Model
        
        vocab_size = len(self.tokenizer.word_index) + 1
        self.model = WAF_Attention_Model(
            vocab_size=vocab_size,
            embedding_dim=128,
            num_classes=1
        ).to(self.device)
        
        # Load trained weights
        checkpoint = torch.load(model_path, map_location=self.device)
        self.model.load_state_dict(checkpoint)
        self.model.eval()
        
        logger.info(f"✅ WAF Model loaded! Device: {self.device}")
        logger.info(f"   Threshold: {self.threshold}")
    
    def preprocess(self, text):
        """
        Tiền xử lý input text
        
        Args:
            text: Raw input string
        
        Returns:
            torch.Tensor: Padded sequence tensor
        """
        # Tokenize
        sequence = self.tokenizer.texts_to_sequences([text])
        
        # Pad to 500 (như khi train)
        from tensorflow.keras.preprocessing.sequence import pad_sequences
        padded = pad_sequences(sequence, maxlen=500, padding='post', truncating='post')
        
        # Convert to tensor
        tensor = torch.LongTensor(padded).to(self.device)
        return tensor
    
    def predict(self, text):
        """
        Dự đoán một payload
        
        Args:
            text: Input payload string
        
        Returns:
            dict: {
                'is_attack': bool,
                'confidence': float (0-1),
                'probability': float (0-1),
                'label': str ('ATTACK' or 'NORMAL')
            }
        """
        # Preprocess
        tensor = self.preprocess(text)
        
        # Predict
        with torch.no_grad():
            logits = self.model(tensor)
            probability = torch.sigmoid(logits).item()
        
        # Classify
        is_attack = probability > self.threshold
        confidence = probability if is_attack else (1 - probability)
        label = 'ATTACK' if is_attack else 'NORMAL'
        
        return {
            'is_attack': is_attack,
            'confidence': confidence,
            'probability': probability,
            'label': label
        }

# ============================================================================
# FLASK APPLICATION WITH WAF
# ============================================================================

# Initialize Flask app
app = Flask(__name__)

# Initialize WAF Detector (singleton)
waf = WAFDetector(
    model_path='./data/waf_model.pth',
    tokenizer_path='./data/tokenizer.pkl',
    threshold=0.5  # Có thể điều chỉnh: 0.3 (strict), 0.5 (balanced), 0.7 (loose)
)

# ============================================================================
# WAF MIDDLEWARE DECORATOR
# ============================================================================

def waf_protect(check_params=True, check_headers=True, check_body=True):
    """
    Decorator để bảo vệ route với WAF
    
    Usage:
        @app.route('/api/users')
        @waf_protect()
        def get_users():
            return jsonify({'users': [...]}
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()
            suspicious_items = []
            
            # 1. Check URL parameters
            if check_params and request.args:
                for key, value in request.args.items():
                    payload = f"{key}={value}"
                    result = waf.predict(payload)
                    
                    if result['is_attack']:
                        suspicious_items.append({
                            'type': 'URL_PARAM',
                            'key': key,
                            'value': value,
                            'confidence': result['confidence']
                        })
            
            # 2. Check request headers (optional)
            if check_headers:
                suspicious_headers = ['User-Agent', 'Referer', 'X-Forwarded-For']
                for header in suspicious_headers:
                    value = request.headers.get(header, '')
                    if value:
                        result = waf.predict(value)
                        if result['is_attack']:
                            suspicious_items.append({
                                'type': 'HEADER',
                                'key': header,
                                'value': value,
                                'confidence': result['confidence']
                            })
            
            # 3. Check request body (if JSON/Form)
            if check_body and request.method in ['POST', 'PUT', 'PATCH']:
                # JSON body
                if request.is_json:
                    data = request.get_json()
                    if data:
                        for key, value in data.items():
                            if isinstance(value, str):
                                payload = f"{key}={value}"
                                result = waf.predict(payload)
                                
                                if result['is_attack']:
                                    suspicious_items.append({
                                        'type': 'JSON_BODY',
                                        'key': key,
                                        'value': value,
                                        'confidence': result['confidence']
                                    })
                
                # Form data
                elif request.form:
                    for key, value in request.form.items():
                        payload = f"{key}={value}"
                        result = waf.predict(payload)
                        
                        if result['is_attack']:
                            suspicious_items.append({
                                'type': 'FORM_DATA',
                                'key': key,
                                'value': value,
                                'confidence': result['confidence']
                            })
            
            # 4. Block if attack detected
            if suspicious_items:
                detection_time = (time.time() - start_time) * 1000
                
                # Log attack
                logger.warning(f"🚨 ATTACK DETECTED from {request.remote_addr}")
                logger.warning(f"   URL: {request.url}")
                logger.warning(f"   Method: {request.method}")
                logger.warning(f"   Suspicious items: {len(suspicious_items)}")
                for item in suspicious_items:
                    logger.warning(f"     - {item['type']}: {item['key']}={item['value'][:50]}... (confidence: {item['confidence']:.2%})")
                
                # Return 403 Forbidden
                return jsonify({
                    'error': 'Forbidden',
                    'message': 'Your request has been blocked by WAF',
                    'details': {
                        'detected_attacks': len(suspicious_items),
                        'detection_time_ms': round(detection_time, 2)
                    }
                }), 403
            
            # 5. Log safe request
            detection_time = (time.time() - start_time) * 1000
            logger.info(f"✅ Safe request: {request.method} {request.path} ({detection_time:.2f}ms)")
            
            # Continue to route handler
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# ============================================================================
# DEMO ROUTES
# ============================================================================

@app.route('/')
def index():
    """Home page"""
    return jsonify({
        'message': 'WAF Protected API',
        'status': 'online',
        'waf': 'CNN-BiLSTM Attention Model',
        'endpoints': [
            '/api/users',
            '/api/search',
            '/api/login',
            '/api/admin',
            '/waf/test'
        ]
    })

@app.route('/api/users')
@waf_protect()
def get_users():
    """
    Protected endpoint - Get users list
    
    Test:
        ✅ Safe:   /api/users?id=123
        🚨 Attack: /api/users?id=1' OR 1=1--
    """
    user_id = request.args.get('id', '')
    
    return jsonify({
        'message': 'User data retrieved',
        'user_id': user_id,
        'data': {
            'name': 'John Doe',
            'email': 'john@example.com'
        }
    })

@app.route('/api/search')
@waf_protect()
def search():
    """
    Protected endpoint - Search
    
    Test:
        ✅ Safe:   /api/search?q=laptop
        🚨 Attack: /api/search?q=<script>alert(1)</script>
    """
    query = request.args.get('q', '')
    
    return jsonify({
        'message': 'Search completed',
        'query': query,
        'results': [
            {'id': 1, 'title': 'Product 1'},
            {'id': 2, 'title': 'Product 2'}
        ]
    })

@app.route('/api/login', methods=['POST'])
@waf_protect()
def login():
    """
    Protected endpoint - Login
    
    Test:
        ✅ Safe:   {"username": "admin", "password": "123456"}
        🚨 Attack: {"username": "admin' OR 1=1--", "password": "x"}
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    return jsonify({
        'message': 'Login successful',
        'username': username,
        'token': 'fake_jwt_token_here'
    })

@app.route('/api/admin')
@waf_protect()
def admin_panel():
    """
    Protected endpoint - Admin panel
    
    Test:
        ✅ Safe:   /api/admin?action=view
        🚨 Attack: /api/admin?cmd=; DROP TABLE users--
    """
    action = request.args.get('action', '')
    
    return jsonify({
        'message': 'Admin action executed',
        'action': action,
        'status': 'success'
    })

@app.route('/waf/test', methods=['GET', 'POST'])
def waf_test():
    """
    Public endpoint để test WAF (không bảo vệ)
    
    Usage:
        GET  /waf/test?payload=<your_payload>
        POST /waf/test with JSON: {"payload": "<your_payload>"}
    """
    if request.method == 'GET':
        payload = request.args.get('payload', '')
    else:
        data = request.get_json()
        payload = data.get('payload', '') if data else ''
    
    if not payload:
        return jsonify({
            'error': 'Please provide a payload',
            'usage': {
                'GET': '/waf/test?payload=<your_payload>',
                'POST': '/waf/test with JSON: {"payload": "<your_payload>"}'
            }
        }), 400
    
    # Predict
    result = waf.predict(payload)
    
    return jsonify({
        'payload': payload,
        'result': result,
        'verdict': '🚨 BLOCKED' if result['is_attack'] else '✅ ALLOWED'
    })

@app.route('/waf/stats')
def waf_stats():
    """WAF statistics"""
    return jsonify({
        'waf_model': 'CNN-BiLSTM-Attention',
        'threshold': waf.threshold,
        'device': str(waf.device),
        'vocab_size': len(waf.tokenizer.word_index) + 1,
        'performance': {
            'accuracy': '90.09%',
            'precision': '99.42%',
            'recall': '79.56%',
            'f1_score': '88.39%',
            'false_positive_rate': '0.42%'
        }
    })

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("="*70)
    print("🛡️  WAF FLASK SERVER - CNN-BiLSTM PROTECTION")
    print("="*70)
    print("\n📡 Server starting on http://localhost:5000")
    print("\n🔒 Protected Endpoints:")
    print("   - GET  /api/users?id=<id>")
    print("   - GET  /api/search?q=<query>")
    print("   - POST /api/login (JSON body)")
    print("   - GET  /api/admin?action=<action>")
    print("\n🧪 Test Endpoints:")
    print("   - GET  /waf/test?payload=<payload>")
    print("   - POST /waf/test (JSON: {\"payload\": \"...\"})")
    print("   - GET  /waf/stats")
    print("\n💡 Try these attacks:")
    print("   curl 'http://localhost:5000/api/users?id=1%27%20OR%201=1--'")
    print("   curl 'http://localhost:5000/api/search?q=<script>alert(1)</script>'")
    print("   curl -X POST http://localhost:5000/api/login -H 'Content-Type: application/json' -d '{\"username\":\"admin' OR 1=1--\",\"password\":\"x\"}'")
    print("\n"+"="*70)
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)