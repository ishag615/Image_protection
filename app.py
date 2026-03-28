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
import base64
from document_processor import DocumentProcessor
from pii_redactor import PIIRedactor

app = Flask(__name__)

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
Session(app)

# Initialize Gemini API
GEMINI_API_KEY = os.getenv('GOOGLE_API_KEY', '')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Initialize document processor
doc_processor = DocumentProcessor()
redactor = PIIRedactor()

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
# GEMINI AI FUNCTIONS
# ============================================

def analyze_with_gemini(image_path):
    """Use Gemini Vision to detect PII in images - Enhanced detection"""
    
    try:
        with open(image_path, 'rb') as f:
            image_data = base64.standard_b64encode(f.read()).decode('utf-8')
        
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = """CRITICAL: You are an advanced PII/Sensitive Data Detection System. Your job is to identify EVERY piece of sensitive information visible in this image.

DETECTION RULES - BE EXHAUSTIVE:

1. FACIAL AND BIOMETRIC DATA *** HIGHEST PRIORITY ***
   - ANY human face visible (detect ALL faces, even partially visible)
   - Eyes, iris patterns, facial features that could identify a person
   - Fingerprints or other biometric markers
   - Silhouettes or shadows of faces
   - If you see a face, ALWAYS report it as HIGH risk

2. DOCUMENT NUMBERS AND IDENTIFIERS *** HIGHEST PRIORITY ***
   - Passport numbers (any alphanumeric passport ID)
   - Driver's license numbers
   - National ID numbers (from any country)
   - Visa/Travel document numbers
   - Social Security numbers (SSN format: XXX-XX-XXXX)
   - License plate numbers on vehicles
   - Barcode or QR code numbers that could identify documents
   - Registration numbers
   - Certificate numbers
   - Any 9-digit or ID-looking number groups

3. PERSONAL IDENTITY INFORMATION *** VERY HIGH RISK ***
   - Full names or surnames of people
   - Date of birth (any format: DD/MM/YYYY, MM/DD/YY, etc.)
   - Place of birth or origin
   - Gender or demographic markers tied to identity
   - Signature or handwriting of individuals
   - Religious or cultural symbols that could identify someone
   - Parent/family member names
   - Maiden names

4. CONTACT INFORMATION *** HIGH RISK ***
   - Phone numbers (any format with area codes)
   - Email addresses
   - Home addresses (street address + number)
   - Zip/postal codes when with other identifying info
   - Fax numbers
   - Website URLs that identify individuals
   - Apartment/unit numbers with building info

5. FINANCIAL AND PAYMENT DATA *** VERY HIGH RISK ***
   - Credit card numbers (visible digits)
   - Debit card numbers
   - Bank account numbers (any format)
   - Sort codes or routing numbers
   - IBAN numbers
   - Card expiration dates
   - CVV/CVC security codes (3-4 digit codes)
   - Card holder names
   - Bank names with account numbers
   - Wire transfer information
   - Cryptocurrency addresses

6. MEDICAL AND HEALTH DATA *** HIGH RISK ***
   - Health insurance numbers or policy numbers
   - Medical record numbers
   - Medicare/Medicaid numbers
   - Patient ID numbers
   - Hospital or clinic names with patient context
   - Prescription information
   - Medical test results
   - Medication names with patient names
   - Blood type or allergies documented
   - Organ donor status

7. GOVERNMENT AND LEGAL IDENTIFIERS *** HIGH RISK ***
   - Tax IDs or TINs
   - Voter registration numbers
   - Military service numbers
   - Court case numbers
   - Prison/inmate numbers
   - Driving record information
   - Criminal record numbers

8. DIGITAL IDENTIFIERS AND CREDENTIALS *** HIGH RISK ***
   - Passwords (any visible text that looks like a password)
   - Private/SSH keys
   - API keys or tokens
   - OAuth tokens or credentials
   - Two-factor authentication codes
   - Security PIN codes
   - Usernames with context suggesting authentication

9. COMPANY AND EMPLOYMENT DATA *** MEDIUM RISK ***
   - Employee IDs
   - Company confidential information
   - Salary information
   - Staff directory information
   - Internal reference numbers
   - Work-related certifications tied to individuals

ANALYSIS REQUIREMENTS:

For EVERY sensitive item found, provide in EXACTLY this format:
---
TYPE: [Specific type of data]
LOCATION: [Detailed location: "Top-left corner", "Center of page", "Bottom-right", etc.]
DETAILS: [What exactly you see, e.g., "Passport number A12345678", "Phone: 555-1234"]
RISK: [High/Medium]
---

CRITICAL INSTRUCTIONS:
1. If you see ANY human face - ALWAYS report as "TYPE: Human Face" with RISK: High
2. If you see numbers that look like IDs - Report them
3. If you see text that could be sensitive - Report it
4. Erase when in doubt - False positives are GOOD, false negatives are BAD
5. Multiple findings: List each separately with the format above
6. Be AGGRESSIVE in detection - Assume the worst case
7. If ABSOLUTELY NOTHING sensitive found in the image, respond with ONLY: "NO_SENSITIVE_DATA_FOUND"

Example responses:
---
TYPE: Human Face / Portrait
LOCATION: Center of image, person looking at camera
DETAILS: Clear facial features visible
RISK: High
---

---
TYPE: Passport Number
LOCATION: Top-left corner of page
DETAILS: Number visible: "A24534789"
RISK: High
---

---
TYPE: Email Address
LOCATION: Bottom of page
DETAILS: "john.smith@company.com"
RISK: High
---

---
TYPE: Phone Number
LOCATION: Right side, phone contact section
DETAILS: Format appears to be international: +1-555-123-4567
RISK: High
---"""

        response = model.generate_content([
            prompt,
            {
                'mime_type': 'image/jpeg',
                'data': image_data
            }
        ])
        
        return parse_gemini_response(response.text)
    
    except Exception as e:
        print(f"Gemini error: {e}")
        return {
            'threats': [],
            'raw_analysis': f"Error analyzing image: {str(e)}",
            'risk_level': 'UNKNOWN'
        }

def parse_gemini_response(response_text):
    """Parse Gemini response into structured format"""
    
    if "NO_SENSITIVE_DATA_FOUND" in response_text or "NO_PII_FOUND" in response_text:
        return {
            'threats': [],
            'raw_analysis': response_text,
            'risk_level': 'LOW'
        }
    
    # Parse threats from response - new format with DETAILS field
    threats = []
    lines = response_text.split('\n')
    
    current_threat = {}
    for line in lines:
        line = line.strip()
        if not line or line == '---':
            if current_threat and 'type' in current_threat:
                threats.append(current_threat)
                current_threat = {}
            continue
            
        if line.startswith('TYPE:'):
            if current_threat and 'type' in current_threat:
                threats.append(current_threat)
            current_threat = {'type': line.replace('TYPE:', '').strip()}
        elif line.startswith('LOCATION:'):
            current_threat['location'] = line.replace('LOCATION:', '').strip()
        elif line.startswith('DETAILS:'):
            current_threat['details'] = line.replace('DETAILS:', '').strip()
        elif line.startswith('RISK:'):
            risk_text = line.replace('RISK:', '').strip().lower()
            current_threat['risk'] = 'High' if 'high' in risk_text else 'Medium'
    
    if current_threat and 'type' in current_threat:
        threats.append(current_threat)
    
    # Determine overall risk - be strict
    if not threats:
        overall_risk = 'LOW'
    else:
        risk_levels = [t.get('risk', 'Medium').lower() for t in threats]
        
        # If ANY high risk found, mark as HIGH
        if any('high' in r for r in risk_levels):
            overall_risk = 'HIGH'
        # If any medium found, mark as MEDIUM
        elif any('medium' in r for r in risk_levels):
            overall_risk = 'MEDIUM'
        # Only LOW if absolutely nothing concerning
        else:
            overall_risk = 'LOW'
    
    return {
        'threats': [{
            'type': t.get('type', 'Unknown'),
            'location': t.get('location', 'Unknown location'),
            'details': t.get('details', ''),
            'risk': t.get('risk', 'Medium')
        } for t in threats],
        'raw_analysis': response_text,
        'risk_level': overall_risk
    }

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

@app.route('/api/admin/upload', methods=['POST'])
def admin_upload():
    """Admin upload document - scan with Gemini and create protected version"""
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
        # Determine file type
        file_type = doc_processor.get_file_type(temp_path)
        
        # Convert to images if needed
        images_to_analyze = doc_processor.convert_to_images(temp_path, file_type)
        
        # Analyze all images with Gemini
        all_threats = []
        
        for img_path in images_to_analyze:
            analysis = analyze_with_gemini(img_path)
            all_threats.extend(analysis['threats'])
        
        # Determine overall risk - be strict
        if not all_threats:
            overall_risk = 'LOW'
        else:
            risk_levels = [t.get('risk', 'Medium').lower() for t in all_threats]
            
            # If ANY high risk found, mark as HIGH
            if any('high' in r for r in risk_levels):
                overall_risk = 'HIGH'
            # If any medium found, mark as MEDIUM
            elif any('medium' in r for r in risk_levels):
                overall_risk = 'MEDIUM'
            # Only LOW if absolutely nothing concerning
            else:
                overall_risk = 'LOW'
        
        # ========== CREATE PROTECTED VERSION ==========
        Path('protected_documents').mkdir(exist_ok=True)
        
        protected_filename = f"protected_{uuid.uuid4()}_{Path(file.filename).stem}.{Path(file.filename).suffix.lstrip('.')}"
        protected_path = f'protected_documents/{protected_filename}'
        
        # Generate protected version based on file type
        if file_type == 'image':
            # For images, redact sensitive areas
            redactor.redact_image_from_threats(temp_path, all_threats, protected_path)
            
        else:
            # For PDFs and Word docs, redact the document
            redactor.create_protected_document(temp_path, all_threats, protected_path, file_type)
        
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
            'protected_path': protected_path,
            'threats': all_threats,
            'risk_level': overall_risk,
            'threats_count': len(all_threats)
        }
        
        save_documents(documents)
        update_document_count(email)
        
        return jsonify({
            'success': True,
            'document_id': doc_id,
            'threats_detected': len(all_threats),
            'risk_level': overall_risk,
            'message': f'Protected version created. {len(all_threats)} sensitive items detected and redacted.'
        })
    
    except Exception as e:
        print(f"Upload error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

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

@app.route('/api/admin/document/<doc_id>', methods=['GET'])
def get_admin_document(doc_id):
    """Get document details"""
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
        'threats_count': len(doc.get('threats', [])),
        'risk_level': doc.get('risk_level', 'LOW'),
        'threats': doc.get('threats', [])
    })

@app.route('/api/admin/download/<doc_id>/<version>')
def admin_download(doc_id, version):
    """
    Download document (original or protected)
    version: 'original' or 'protected'
    """
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    documents = load_documents()
    if doc_id not in documents:
        return jsonify({'error': 'Document not found'}), 404
    
    doc = documents[doc_id]
    
    if version == 'original':
        filepath = doc['original_path']
    elif version == 'protected':
        filepath = doc['protected_path']
    else:
        return jsonify({'error': 'Invalid version'}), 400
    
    if not Path(filepath).exists():
        return jsonify({'error': 'File not found on server'}), 404
    
    filename = f"{version}_{doc['filename']}"
    return send_file(filepath, as_attachment=True, download_name=filename)

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

@app.route('/api/guest/download/<doc_id>')
def guest_download(doc_id):
    """
    Download protected document (guest can only access protected version)
    """
    if session.get('user_type') != 'guest':
        return jsonify({'error': 'Unauthorized'}), 401
    
    documents = load_documents()
    if doc_id not in documents:
        return jsonify({'error': 'Document not found'}), 404
    
    doc = documents[doc_id]
    filepath = doc['protected_path']
    
    if not Path(filepath).exists():
        return jsonify({'error': 'File not found on server'}), 404
    
    filename = f"protected_{doc['filename']}"
    return send_file(filepath, as_attachment=True, download_name=filename)

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
    Path('protected_documents').mkdir(exist_ok=True)
    
    app.run(debug=True, port=5001)