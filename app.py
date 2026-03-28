# app.py
from flask import Flask, render_template, request, jsonify, session, redirect, send_file, send_from_directory
from flask_session import Session
import google.generativeai as genai
import boto3
from pathlib import Path
import os
import json
from auth import key_manager
from document_processor import DocumentProcessor
from datetime import datetime
import uuid

app = Flask(__name__)

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
Session(app)

# Initialize APIs
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
s3_client = boto3.client('s3', region_name='us-east-1')
kms_client = boto3.client('kms', region_name='us-east-1')

# Document processor
doc_processor = DocumentProcessor()

# Database (simple JSON for hackathon)
DOCUMENTS_DB = 'documents.json'

def load_documents():
    """Load document registry"""
    if Path(DOCUMENTS_DB).exists():
        with open(DOCUMENTS_DB, 'r') as f:
            return json.load(f)
    return {}

def save_documents(docs):
    """Save document registry"""
    with open(DOCUMENTS_DB, 'w') as f:
        json.dump(docs, f, indent=2)

# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.route('/')
def index():
    """Landing page - role selection"""
    return render_template('login.html')

@app.route('/api/auth/admin-login', methods=['POST'])
def admin_login():
    """Admin login with email + key"""
    data = request.json
    email = data.get('email')
    admin_key = data.get('key')
    
    if not email or not admin_key:
        return jsonify({'error': 'Email and key required'}), 400
    
    # Verify key
    if key_manager.verify_admin_key(email, admin_key):
        session['user_type'] = 'admin'
        session['email'] = email
        return jsonify({
            'success': True,
            'message': 'Admin authenticated',
            'redirect': '/admin/dashboard'
        })
    
    return jsonify({'error': 'Invalid email or key'}), 401

@app.route('/api/auth/admin-register', methods=['POST'])
def admin_register():
    """Admin registration - generate first-time key"""
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    # Check if already registered
    if key_manager.get_admin_info(email):
        return jsonify({'error': 'Email already registered'}), 409
    
    # Generate key
    admin_key = key_manager.generate_admin_key(email)
    
    return jsonify({
        'success': True,
        'admin_key': admin_key,
        'message': 'Save this key safely! You\'ll need it to login.'
    })

@app.route('/api/auth/guest-login', methods=['POST'])
def guest_login():
    """Guest/outsider login - no key needed"""
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
# ADMIN ROUTES
# ============================================

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard - view all documents (original + protected)"""
    if session.get('user_type') != 'admin':
        return redirect('/')
    
    return render_template('admin_dashboard.html', email=session.get('email'))

@app.route('/api/admin/documents', methods=['GET'])
def get_admin_documents():
    """Get all documents for admin (with access to both versions)"""
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
            'original_path': doc['original_path'],  # Admin can see original
            'protected_path': doc['protected_path'],
            'threats_count': len(doc['threats']),
            'risk_level': doc['risk_level'],
            'threats': doc['threats']
        })
    
    return jsonify(admin_docs)

@app.route('/api/admin/upload', methods=['POST'])
def admin_upload():
    """Admin upload document (image, PDF, Word, etc.)"""
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    email = session.get('email')
    
    # Save temporarily
    temp_path = f'uploads/{file.filename}'
    Path('uploads').mkdir(exist_ok=True)
    file.save(temp_path)
    
    try:
        # Process document (image, PDF, Word, etc.)
        file_type = doc_processor.get_file_type(temp_path)
        
        # Convert to images if needed (PDF, Word docs)
        images_to_analyze = doc_processor.convert_to_images(temp_path, file_type)
        
        # Analyze all images with Gemini
        all_threats = []
        mask_instructions = []
        
        for img_path in images_to_analyze:
            threats, instructions = analyze_with_gemini(img_path, file_type)
            all_threats.extend(threats)
            mask_instructions.extend(instructions)
        
        # Redact all images
        protected_images = []
        for img_path in images_to_analyze:
            protected_img = doc_processor.redact_image(img_path, mask_instructions)
            protected_images.append(protected_img)
        
        # Convert back to original format if needed
        protected_path = doc_processor.rebuild_document(
            protected_images, 
            file_type, 
            file.filename
        )
        
        # Encrypt protected file
        encrypted_path = f'protected_vault/{uuid.uuid4()}.enc'
        Path('protected_vault').mkdir(exist_ok=True)
        encrypt_file(protected_path, encrypted_path)
        
        # Create document record
        doc_id = str(uuid.uuid4())
        documents = load_documents()
        
        documents[doc_id] = {
            'id': doc_id,
            'filename': file.filename,
            'file_type': file_type,
            'uploaded_by': email,
            'uploaded_at': datetime.now().isoformat(),
            'original_path': temp_path,
            'protected_path': encrypted_path,
            'threats': all_threats,
            'risk_level': calculate_risk_level(all_threats)
        }
        
        save_documents(documents)
        key_manager.update_document_count(email)
        
        return jsonify({
            'success': True,
            'document_id': doc_id,
            'threats_detected': len(all_threats),
            'risk_level': documents[doc_id]['risk_level']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/document/<doc_id>', methods=['GET'])
def get_admin_document(doc_id):
    """Get document details (admin can see original)"""
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    documents = load_documents()
    if doc_id not in documents:
        return jsonify({'error': 'Document not found'}), 404
    
    doc = documents[doc_id]
    
    return jsonify({
        'id': doc_id,
        'filename': doc['filename'],
        'file_type': doc['file_type'],
        'uploaded_at': doc['uploaded_at'],
        'threats': doc['threats'],
        'risk_level': doc['risk_level'],
        'original_available': True,  # Admin can see original
        'protected_available': True
    })

@app.route('/api/admin/download/<doc_id>/<version>')
def admin_download(doc_id, version):
    """
    Download document
    version: 'original' or 'protected'
    Admin can access both, guest can only access 'protected'
    """
    if not session.get('email'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    documents = load_documents()
    if doc_id not in documents:
        return jsonify({'error': 'Document not found'}), 404
    
    doc = documents[doc_id]
    
    # Authorization check
    is_admin = session.get('user_type') == 'admin'
    
    if version == 'original':
        if not is_admin:
            return jsonify({'error': 'Only admin can access original'}), 401
        filepath = doc['original_path']
    else:
        filepath = doc['protected_path']
    
    if not Path(filepath).exists():
        return jsonify({'error': 'File not found'}), 404
    
    filename = f"{version}_{doc['filename']}"
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/api/admin/delete/<doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    """Delete document (admin only)"""
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    documents = load_documents()
    if doc_id not in documents:
        return jsonify({'error': 'Document not found'}), 404
    
    doc = documents[doc_id]
    
    # Delete files
    Path(doc['original_path']).unlink(missing_ok=True)
    Path(doc['protected_path']).unlink(missing_ok=True)
    
    # Delete record
    del documents[doc_id]
    save_documents(documents)
    
    return jsonify({'success': True})

@app.route('/api/admin/audit-log')
def audit_log():
    """Get audit log (admin only)"""
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Simple audit log
    email = session.get('email')
    admin_info = key_manager.get_admin_info(email)
    
    return jsonify({
        'admin': email,
        'last_login': admin_info['last_used'],
        'documents_managed': admin_info['documents_count'],
        'account_created': admin_info['created']
    })

# ============================================
# GUEST/OUTSIDER ROUTES
# ============================================

@app.route('/guest/documents')
def guest_documents():
    """Guest view - only protected documents"""
    if session.get('user_type') != 'guest':
        return redirect('/')
    
    return render_template('guest_view.html')

@app.route('/api/guest/documents', methods=['GET'])
def get_guest_documents():
    """Get protected documents only (no original access)"""
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
            'protected_path': doc['protected_path'],
            'risk_level': doc['risk_level'],
            # Guest doesn't see threats or original path
            'threats_hidden': True
        })
    
    return jsonify(guest_docs)

@app.route('/api/guest/document/<doc_id>', methods=['GET'])
def get_guest_document(doc_id):
    """Get protected document details (guest can't see original)"""
    if session.get('user_type') != 'guest':
        return jsonify({'error': 'Unauthorized'}), 401
    
    documents = load_documents()
    if doc_id not in documents:
        return jsonify({'error': 'Document not found'}), 404
    
    doc = documents[doc_id]
    
    return jsonify({
        'id': doc_id,
        'filename': doc['filename'],
        'file_type': doc['file_type'],
        'uploaded_at': doc['uploaded_at'],
        'risk_level': doc['risk_level'],
        'original_available': False,  # Guest can't see original
        'protected_available': True
    })

# ============================================
# HELPER FUNCTIONS
# ============================================

def analyze_with_gemini(image_path, file_type):
    """Use Gemini Vision to detect PII in images"""
    
    import base64
    
    with open(image_path, 'rb') as f:
        image_data = base64.standard_b64encode(f.read()).decode('utf-8')
    
    model = genai.GenerativeModel('gemini-1.5-flash')
    
    prompt = """You are a privacy detection expert. Analyze this image ONLY for these sensitive data types:

1. PERSONALLY IDENTIFIABLE INFORMATION (PII):
   - Names, Email, Phone, Social Security Numbers, Credit cards, Driver's licenses, Passports, Bank accounts

2. BIOMETRIC DATA:
   - Human faces, Fingerprints, Iris scans

3. HEALTH/FINANCIAL DATA:
   - Medical info, Insurance numbers, Financial account numbers

For each item found, provide:
- TYPE: Category
- LOCATION: Where in image
- RISK: High/Medium/Low
- MASK_INSTRUCTION: How to redact (coordinates if possible)

If NO sensitive data found, respond: "NO_PII_FOUND"

Be thorough but avoid false positives."""

    response = model.generate_content([
        prompt,
        {'mime_type': 'image/jpeg', 'data': image_data}
    ])
    
    threats = []
    instructions = []
    
    if "NO_PII_FOUND" not in response.text:
        # Parse threats from response
        lines = response.text.split('\n')
        current_threat = {}
        
        for line in lines:
            if 'TYPE:' in line:
                if current_threat:
                    threats.append(current_threat)
                current_threat = {'type': line.split('TYPE:')[1].strip()}
            elif 'LOCATION:' in line:
                current_threat['location'] = line.split('LOCATION:')[1].strip()
            elif 'RISK:' in line:
                current_threat['risk'] = line.split('RISK:')[1].strip()
            elif 'MASK_INSTRUCTION:' in line:
                instruction = line.split('MASK_INSTRUCTION:')[1].strip()
                current_threat['mask_instruction'] = instruction
                instructions.append(instruction)
        
        if current_threat:
            threats.append(current_threat)
    
    return threats, instructions

def calculate_risk_level(threats):
    """Calculate overall risk level"""
    if not threats:
        return 'LOW'
    
    risks = [t.get('risk', 'Medium') for t in threats]
    
    if 'High' in risks:
        return 'HIGH'
    elif 'Medium' in risks:
        return 'MEDIUM'
    else:
        return 'LOW'

def encrypt_file(filepath, output_path):
    """Encrypt file with AWS KMS"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        kms = boto3.client('kms', region_name='us-east-1')
        response = kms.encrypt(
            Plaintext=data,
            KeyId='alias/aws/s3'
        )
        
        with open(output_path, 'wb') as f:
            f.write(response['CiphertextBlob'])
    
    except Exception as e:
        # Fallback: local encryption
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        f = Fernet(key)
        with open(filepath, 'rb') as file:
            encrypted = f.encrypt(file.read())
        with open(output_path, 'wb') as file:
            file.write(encrypted)

if __name__ == '__main__':
    app.run(debug=True, port=5000)