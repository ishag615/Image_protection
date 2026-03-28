from flask import Flask, render_template, request, jsonify, session, redirect, send_file
from flask_session import Session
import google.generativeai as genai
import boto3
from pathlib import Path
import os
import json
from datetime import datetime
import uuid
import secrets

app = Flask(__name__)

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
Session(app)

# Initialize APIs
genai.configure(api_key=os.getenv('GOOGLE_API_KEY', 'your-gemini-key-here'))

# Database file paths
DOCUMENTS_DB = 'documents.json'
KEY_VAULT = 'key_vault.json'

# ============================================
# HELPER FUNCTIONS - KEY MANAGEMENT
# ============================================

def load_key_vault():
    """Load admin keys from vault"""
    if Path(KEY_VAULT).exists():
        with open(KEY_VAULT, 'r') as f:
            return json.load(f)
    return {}

def save_key_vault(keys):
    """Save admin keys to vault"""
    with open(KEY_VAULT, 'w') as f:
        json.dump(keys, f, indent=2)

def generate_admin_key(email):
    """Generate unique 32-character admin key"""
    admin_key = secrets.token_hex(16)  # 32 characters
    
    key_info = {
        'key': admin_key,
        'email': email,
        'created': datetime.now().isoformat(),
        'active': True,
        'last_used': None,
        'documents_count': 0
    }
    
    keys = load_key_vault()
    keys[email] = key_info
    save_key_vault(keys)
    
    return admin_key

def verify_admin_key(email, provided_key):
    """Check if email + key combination is valid"""
    keys = load_key_vault()
    
    if email not in keys:
        return False
    
    stored_key = keys[email]['key']
    
    if provided_key == stored_key and keys[email]['active']:
        # Update last used time
        keys[email]['last_used'] = datetime.now().isoformat()
        save_key_vault(keys)
        return True
    
    return False

def get_admin_info(email):
    """Get admin profile info"""
    keys = load_key_vault()
    return keys.get(email, None)

# ============================================
# HELPER FUNCTIONS - DOCUMENTS
# ============================================

def load_documents():
    """Load all documents from database"""
    if Path(DOCUMENTS_DB).exists():
        with open(DOCUMENTS_DB, 'r') as f:
            return json.load(f)
    return {}

def save_documents(docs):
    """Save documents to database"""
    with open(DOCUMENTS_DB, 'w') as f:
        json.dump(docs, f, indent=2)

def update_document_count(email):
    """Increment document count for admin"""
    keys = load_key_vault()
    if email in keys:
        keys[email]['documents_count'] += 1
        save_key_vault(keys)

# ============================================
# ROUTES - AUTHENTICATION
# ============================================

@app.route('/')
def index():
    """Landing page - show login"""
    return render_template('login.html')

@app.route('/api/auth/admin-register', methods=['POST'])
def admin_register():
    """Admin registration - generate unique key"""
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    # Check if already registered
    keys = load_key_vault()
    if email in keys:
        return jsonify({'error': 'Email already registered'}), 409
    
    # Generate key
    admin_key = generate_admin_key(email)
    
    return jsonify({
        'success': True,
        'admin_key': admin_key,
        'message': 'Save this key safely! You\'ll need it to login.'
    })

@app.route('/api/auth/admin-login', methods=['POST'])
def admin_login():
    """Admin login with email + key"""
    data = request.json
    email = data.get('email')
    admin_key = data.get('key')
    
    if not email or not admin_key:
        return jsonify({'error': 'Email and key required'}), 400
    
    # Verify key
    if verify_admin_key(email, admin_key):
        session['user_type'] = 'admin'
        session['email'] = email
        return jsonify({
            'success': True,
            'message': 'Admin authenticated',
            'redirect': '/admin/dashboard'
        })
    
    return jsonify({'error': 'Invalid email or key'}), 401

@app.route('/api/auth/guest-login', methods=['POST'])
def guest_login():
    """Guest login - no credentials needed"""
    session['user_type'] = 'guest'
    session['email'] = 'guest-' + str(uuid.uuid4())[:8]
    
    return jsonify({
        'success': True,
        'message': 'Guest access granted',
        'redirect': '/guest/documents'
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout - clear session"""
    session.clear()
    return jsonify({'success': True, 'redirect': '/'})

# ============================================
# ROUTES - ADMIN DASHBOARD
# ============================================

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard page"""
    if session.get('user_type') != 'admin':
        return redirect('/')
    
    return render_template('admin_dashboard.html')

@app.route('/api/admin/documents', methods=['GET'])
def get_admin_documents():
    """Get all documents for admin"""
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    documents = load_documents()
    admin_docs = []
    
    for doc_id, doc in documents.items():
        admin_docs.append({
            'id': doc_id,
            'filename': doc['filename'],
            'file_type': doc['file_type'],
            'uploaded_at': doc['uploaded_at'],
            'threats_count': len(doc.get('threats', [])),
            'risk_level': doc.get('risk_level', 'LOW'),
        })
    
    return jsonify(admin_docs)

@app.route('/api/admin/audit-log')
def audit_log():
    """Get audit log for admin"""
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    email = session.get('email')
    admin_info = get_admin_info(email)
    
    if not admin_info:
        return jsonify({'error': 'Admin not found'}), 404
    
    return jsonify({
        'admin': email,
        'last_login': admin_info['last_used'],
        'documents_managed': admin_info['documents_count'],
        'account_created': admin_info['created']
    })

# ============================================
# ROUTES - GUEST VIEW
# ============================================

@app.route('/guest/documents')
def guest_documents():
    """Guest documents page"""
    if session.get('user_type') != 'guest':
        return redirect('/')
    
    return render_template('guest_view.html')

@app.route('/api/guest/documents', methods=['GET'])
def get_guest_documents():
    """Get protected documents only (guest can't see originals)"""
    if session.get('user_type') != 'guest':
        return jsonify({'error': 'Unauthorized'}), 401
    
    documents = load_documents()
    guest_docs = []
    
    for doc_id, doc in documents.items():
        guest_docs.append({
            'id': doc_id,
            'filename': doc['filename'],
            'file_type': doc['file_type'],
            'uploaded_at': doc['uploaded_at'],
            'risk_level': doc.get('risk_level', 'LOW'),
        })
    
    return jsonify(guest_docs)

# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Page not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Server error'}), 500

# ============================================
# RUN APP
# ============================================

if __name__ == '__main__':
    # Create necessary folders
    Path('uploads').mkdir(exist_ok=True)
    Path('protected_vault').mkdir(exist_ok=True)
    
    app.run(debug=True, port=5000)