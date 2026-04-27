"""
Image Protection System - Simplified Flask Application
Uses Gemini Vision AI for PII detection and blur-based redaction
"""

from flask import Flask, render_template, request, jsonify, session, redirect, send_file
from flask_session import Session
import google.generativeai as genai
from pathlib import Path
import os
import json
from datetime import datetime
import uuid
import secrets
import base64
import logging

from document_processor import DocumentProcessor
from pii_redactor import PIIRedactor
from credit_card_detector import CreditCardDetector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================
# FLASK INITIALIZATION
# ============================================

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max upload
Session(app)

# ============================================
# CORE SYSTEM INITIALIZATION
# ============================================

# Initialize Gemini API
GEMINI_API_KEY = os.getenv('GOOGLE_API_KEY', '')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Initialize processors and redactor
doc_processor = DocumentProcessor()
redactor = PIIRedactor()
credit_card_detector = CreditCardDetector(gemini_api_key=GEMINI_API_KEY)

# Database and storage paths
DOCUMENTS_DB = 'documents.json'
KEY_VAULT = 'key_vault.json'

# Create necessary directories
Path('uploads').mkdir(exist_ok=True)
Path('protected_documents').mkdir(exist_ok=True)
Path('flask_session').mkdir(exist_ok=True)

# ============================================
# DATABASE MANAGEMENT FUNCTIONS
# ============================================

def load_documents():
    """Load documents database"""
    if Path(DOCUMENTS_DB).exists():
        with open(DOCUMENTS_DB, 'r') as f:
            return json.load(f)
    return {}

def save_documents(docs):
    """Save documents database"""
    with open(DOCUMENTS_DB, 'w') as f:
        json.dump(docs, f, indent=2)

def load_key_vault():
    """Load admin keys"""
    if Path(KEY_VAULT).exists():
        with open(KEY_VAULT, 'r') as f:
            return json.load(f)
    return {}

def save_key_vault(keys):
    """Save admin keys"""
    with open(KEY_VAULT, 'w') as f:
        json.dump(keys, f, indent=2)

# ============================================
# AI ANALYSIS FUNCTIONS
# ============================================

def analyze_with_gemini(image_path):
    """Use Gemini Vision to detect PII in images"""
    try:
        if not GEMINI_API_KEY:
            return {'success': False, 'error': 'Gemini API key not configured'}
        
        with open(image_path, 'rb') as f:
            image_data = base64.standard_b64encode(f.read()).decode('utf-8')
        
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = """You are a PII/Sensitive Data Detection System. Identify ALL sensitive information visible in this image.

DETECTION CATEGORIES:

1. FACIAL AND BIOMETRIC DATA (HIGHEST PRIORITY)
   - Human faces (detect ALL faces, even partially visible)
   - Eyes, facial features, fingerprints
   
2. DOCUMENT NUMBERS (HIGHEST PRIORITY)
   - Passport, driver's license, ID numbers
   - Social Security numbers, license plates
   - Barcode or document numbers

3. PERSONAL IDENTITY
   - Full names, surnames, dates of birth
   - Place of birth, signatures, handwriting

4. CONTACT INFORMATION
   - Phone numbers, email addresses
   - Home addresses, zip codes

5. FINANCIAL DATA (VERY HIGH RISK)
   - Credit/debit card numbers
   - Bank account numbers, routing numbers
   - Card holder names, CVV codes

6. MEDICAL INFORMATION
   - Health insurance numbers
   - Medical record numbers, prescriptions

7. GOVERNMENT IDENTIFIERS
   - Tax IDs, voter registration, military numbers
   - Court case numbers, prison numbers

For each item found, provide:
TYPE: [category name]
LOCATION: [describe location in image]
RISK: [HIGH/MEDIUM/LOW]
DETAILS: [brief description]

Be EXHAUSTIVE and err on the side of caution."""
        
        response = model.generate_content([
            {"mime_type": "image/jpeg", "data": image_data},
            prompt
        ])
        
        analysis_text = response.text
        
        # Parse detected entities
        entities = []
        lines = analysis_text.split('\n')
        
        current_entity = {}
        for line in lines:
            if line.startswith('TYPE:'):
                if current_entity:
                    entities.append(current_entity)
                current_entity = {'type': line.replace('TYPE:', '').strip()}
            elif line.startswith('LOCATION:'):
                current_entity['location'] = line.replace('LOCATION:', '').strip()
            elif line.startswith('RISK:'):
                current_entity['risk'] = line.replace('RISK:', '').strip()
            elif line.startswith('DETAILS:'):
                current_entity['details'] = line.replace('DETAILS:', '').strip()
        
        if current_entity:
            entities.append(current_entity)
        
        # Determine overall risk level
        risk_levels = [e.get('risk', 'LOW') for e in entities]
        if 'HIGH' in risk_levels:
            risk_level = 'HIGH'
        elif 'MEDIUM' in risk_levels:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'success': True,
            'entities': entities,
            'risk_level': risk_level,
            'analysis': analysis_text
        }
    
    except Exception as e:
        logger.error(f"Gemini analysis error: {e}")
        return {'success': False, 'error': str(e)}

# ============================================
# AUTHENTICATION FUNCTIONS  
# ============================================

def generate_admin_key(email):
    """Generate unique admin key"""
    admin_key = secrets.token_hex(16)
    
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
    """Verify admin email and key"""
    keys = load_key_vault()
    
    if email not in keys:
        return False
    
    key_info = keys[email]
    if provided_key == key_info['key'] and key_info.get('active', False):
        key_info['last_used'] = datetime.now().isoformat()
        save_key_vault(keys)
        return True
    
    return False

def get_admin_info(email):
    """Get admin profile information"""
    keys = load_key_vault()
    return keys.get(email, None)

# ============================================
# ROUTES - AUTHENTICATION
# ============================================

@app.route('/')
def index():
    """Landing page"""
    return render_template('login.html')

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Admin registration"""
    try:
        data = request.json
        email = data.get('email', '').strip()
        
        if not email or '@' not in email:
            return jsonify({'error': 'Invalid email'}), 400
        
        keys = load_key_vault()
        if email in keys:
            return jsonify({'error': 'Email already registered'}), 409
        
        admin_key = generate_admin_key(email)
        
        return jsonify({
            'success': True,
            'admin_key': admin_key,
            'message': 'Registration successful! Save your key carefully.'
        })
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/admin-register', methods=['POST'])
def admin_register():
    """Admin registration (alias for register)"""
    return register()

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Admin login with key"""
    try:
        data = request.json
        email = data.get('email', '').strip()
        admin_key = data.get('key', '')
        
        if not email or not admin_key:
            return jsonify({'error': 'Email and key required'}), 400
        
        if verify_admin_key(email, admin_key):
            session['user_type'] = 'admin'
            session['email'] = email
            return jsonify({
                'success': True,
                'redirect': '/dashboard'
            })
        
        return jsonify({'error': 'Invalid email or key'}), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/admin-login', methods=['POST'])
def admin_login():
    """Admin login (alias for login)"""
    return login()

@app.route('/api/auth/guest-login', methods=['POST'])
def guest_login():
    """Guest access (no credentials required)"""
    try:
        session['user_type'] = 'guest'
        session['email'] = 'guest'
        return jsonify({
            'success': True,
            'redirect': '/guest-view'
        })
    except Exception as e:
        logger.error(f"Guest login error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/logout',  methods=['POST'])
def logout():
    """Logout"""
    session.clear()
    return jsonify({'success': True, 'redirect': '/'})

# ============================================
# ROUTES - DASHBOARD
# ============================================

@app.route('/dashboard')
def dashboard():
    """Admin dashboard"""
    if session.get('user_type') != 'admin':
        return redirect('/')
    return render_template('admin_dashboard.html')

@app.route('/guest-view')
def guest_view():
    """Guest view of protected documents"""
    if session.get('user_type') != 'guest':
        return redirect('/')
    return render_template('guest_view.html')

@app.route('/api/documents')
@app.route('/api/admin/documents')
def get_documents():
    """Get all documents"""
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        docs = load_documents()
        doc_list = []
        
        for doc_id, doc in docs.items():
            doc_list.append({
                'id': doc_id,
                'filename': doc.get('filename', 'Unknown'),
                'file_type': doc.get('file_type', ''),
                'uploaded_at': doc.get('uploaded_at', ''),
                'status': doc.get('status', 'analyzed'),
                'risk_level': doc.get('risk_level', 'UNKNOWN'),
                'threats_count': len(doc.get('entities', [])),
                'entity_count': len(doc.get('entities', [])),
                'has_protected': bool(doc.get('protected_path'))
            })
        
        return jsonify(doc_list)
    except Exception as e:
        logger.error(f"Error getting documents: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================
# ROUTES - FILE UPLOAD & PROTECTION
# ============================================

@app.route('/api/upload', methods=['POST'])
@app.route('/api/admin/upload', methods=['POST'])
def upload_file():
    """
    Upload file, analyze with Gemini, apply blur, return protected version
    """
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        email = session.get('email')
        
        if not file.filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        # Save temporarily
        doc_id = str(uuid.uuid4())
        temp_path = f'uploads/{doc_id}_{file.filename}'
        Path('uploads').mkdir(exist_ok=True)
        file.save(temp_path)
        
        try:
            # Step 1: Determine file type
            file_type = doc_processor.get_file_type(temp_path)
            
            # Step 2: Convert to image if needed
            image_paths = []
            if file_type == 'image':
                image_paths = [temp_path]
            else:
                # Convert document to images
                image_paths = doc_processor.convert_to_images(temp_path, file_type)
            
            if not image_paths:
                return jsonify({'error': 'Could not process file'}), 400
            
            # Step 3: Analyze first image with Gemini
            analysis = analyze_with_gemini(image_paths[0])
            
            if not analysis.get('success'):
                logger.warning(f"Analysis failed: {analysis.get('error')}")
                entities = []
                risk_level = 'UNKNOWN'
            else:
                entities = analysis.get('entities', [])
                risk_level = analysis.get('risk_level', 'LOW')
            
            # Step 4: Store original image and return analysis
            Path('protected_documents').mkdir(exist_ok=True)
            protected_filename = f"protected_{doc_id}_{Path(file.filename).stem}.jpg"
            protected_path = f'protected_documents/{protected_filename}'
            
            # Step 5: Save to database
            documents = load_documents()
            documents[doc_id] = {
                'id': doc_id,
                'filename': file.filename,
                'file_type': file_type,
                'uploaded_by': email,
                'uploaded_at': datetime.now().isoformat(),
                'original_path': temp_path,
                'protected_path': None,
                'status': 'analyzed',
                'entities': entities,
                'risk_level': risk_level,
                'entity_count': len(entities)
            }
            save_documents(documents)
            
            # Update admin document count
            keys = load_key_vault()
            if email in keys:
                keys[email]['documents_count'] = keys[email].get('documents_count', 0) + 1
                save_key_vault(keys)
            
            return jsonify({
                'success': True,
                'document_id': doc_id,
                'filename': file.filename,
                'file_type': file_type,
                'risk_level': risk_level,
                'threats_detected': len(entities),
                'entity_count': len(entities),
                'entities': entities,
                'message': f'Analysis complete. {len(entities)} PII items detected.'
            })
        
        except Exception as e:
            logger.error(f"Analysis/protection error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'Processing failed: {str(e)}'}), 500
    
    except Exception as e:
        logger.error(f"Upload error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/blur-image/<doc_id>', methods=['POST'])
@app.route('/api/admin/blur-image/<doc_id>/<blur_type>', methods=['POST'])
def blur_image_endpoint(doc_id, blur_type='blur'):
    """Apply blur effect to uploaded image"""
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        docs = load_documents()
        if doc_id not in docs:
            return jsonify({'error': 'Document not found'}), 404
        
        doc = docs[doc_id]
        original_path = doc.get('original_path')
        
        if not Path(original_path).exists():
            return jsonify({'error': 'Original file not found'}), 404
        
        # Create protected version with blur
        Path('protected_documents').mkdir(exist_ok=True)
        protected_filename = f"protected_{doc_id}_{Path(doc.get('filename')).stem}.jpg"
        protected_path = f'protected_documents/{protected_filename}'
        
        try:
            # Apply blur or pixelation to the image
            if blur_type == 'pixelate':
                redactor.pixelate_image(original_path, protected_path, pixel_size=20)
            else:  # default to blur
                redactor.blur_image(original_path, protected_path, blur_strength=51)
            
            # Update document
            doc['protected_path'] = protected_path
            doc['status'] = 'protected'
            doc['blur_type'] = blur_type
            docs[doc_id] = doc
            save_documents(docs)
            
            logger.info(f"Applied {blur_type} to document {doc_id}")
            
            # Return the blurred image file for download
            return send_file(protected_path, as_attachment=True, download_name=f"{blur_type}_{doc_id}.jpg")
        
        except Exception as e:
            logger.error(f"Error processing blur: {e}")
            raise
    
    except Exception as e:
        logger.error(f"Blur error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ============================================
# ROUTES - CREDIT CARD DETECTION & PROTECTION
# ============================================

@app.route('/api/detect-credit-card/<doc_id>', methods=['GET'])
def detect_credit_card(doc_id):
    """
    Detect credit card in uploaded image
    Returns detection result with blur regions if card found
    """
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        docs = load_documents()
        if doc_id not in docs:
            return jsonify({'error': 'Document not found'}), 404
        
        doc = docs[doc_id]
        original_path = doc.get('original_path')
        
        if not Path(original_path).exists():
            return jsonify({'error': 'Original file not found'}), 404
        
        # Detect credit card
        detection_result = credit_card_detector.detect_credit_card_regions(original_path)
        
        if not detection_result.get('has_credit_card'):
            return jsonify({
                'success': True,
                'has_credit_card': False,
                'message': 'No credit card detected in this image'
            })
        
        # Store detection result in document
        doc['credit_card_detected'] = True
        doc['credit_card_detection'] = detection_result
        docs[doc_id] = doc
        save_documents(docs)
        
        return jsonify({
            'success': True,
            'has_credit_card': True,
            'confidence': detection_result.get('confidence', 0),
            'regions': detection_result.get('regions', []),
            'card_region': detection_result.get('card_region'),
            'message': 'Credit card detected! Ready to blur sensitive information.',
            'detection_method': detection_result.get('method')
        })
    
    except Exception as e:
        logger.error(f"Credit card detection error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/blur-credit-card/<doc_id>', methods=['POST'])
def blur_credit_card(doc_id):
    """
    Blur sensitive regions of credit card (number, CVV, expiration)
    and return protected version for download
    """
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.json or {}
        blur_type = data.get('blur_type', 'regions')  # 'regions' or 'full'
        
        docs = load_documents()
        if doc_id not in docs:
            return jsonify({'error': 'Document not found'}), 404
        
        doc = docs[doc_id]
        original_path = doc.get('original_path')
        
        if not Path(original_path).exists():
            return jsonify({'error': 'Original file not found'}), 404
        
        if not doc.get('credit_card_detected'):
            return jsonify({'error': 'No credit card detected. Run detection first.'}), 400
        
        detection_result = doc.get('credit_card_detection', {})
        
        # Create protected version
        Path('protected_documents').mkdir(exist_ok=True)
        protected_filename = f"cc_protected_{doc_id}_{Path(doc.get('filename')).stem}.jpg"
        protected_path = f'protected_documents/{protected_filename}'
        
        try:
            if blur_type == 'full' or not detection_result.get('regions'):
                # Blur entire card
                if detection_result.get('card_region'):
                    credit_card_detector.blur_credit_card_full(
                        original_path, 
                        protected_path,
                        detection_result['card_region'],
                        blur_strength=51
                    )
                else:
                    # Fallback: use regular blur
                    redactor.blur_image(original_path, protected_path, blur_strength=51)
            else:
                # Blur specific regions (number, CVV, expiration)
                credit_card_detector.blur_credit_card_regions(
                    original_path,
                    protected_path,
                    detection_result['regions'],
                    blur_strength=31
                )
            
            # Update document
            doc['credit_card_protected_path'] = protected_path
            doc['credit_card_blur_type'] = blur_type
            doc['status'] = 'credit_card_protected'
            docs[doc_id] = doc
            save_documents(docs)
            
            logger.info(f"Applied credit card {blur_type} blur to document {doc_id}")
            
            # Return the blurred image file for download
            return send_file(
                protected_path,
                as_attachment=True,
                download_name=f"protected_credit_card_{doc_id}.jpg"
            )
        
        except Exception as e:
            logger.error(f"Error processing credit card blur: {e}")
            raise
    
    except Exception as e:
        logger.error(f"Credit card blur error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<doc_id>')
def get_report(doc_id):
    """
    Get document analysis details
    """
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        docs = load_documents()
        if doc_id not in docs:
            return jsonify({'error': 'Document not found'}), 404
        
        doc = docs[doc_id]
        return jsonify({
            'document': doc.get('filename'),
            'uploaded': doc.get('uploaded_at'),
            'risk_level': doc.get('risk_level'),
            'entities': doc.get('entities', []),
            'entity_count': len(doc.get('entities', []))
        })
    
    except Exception as e:
        logger.error(f"Error getting report: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================
# ROUTES - DOWNLOADS
# ============================================

@app.route('/api/download/<doc_id>/<version>')
def download(doc_id, version):
    """
    Download document
    version: 'original' or 'protected'
    """
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        docs = load_documents()
        if doc_id not in docs:
            return jsonify({'error': 'Document not found'}), 404
        
        doc = docs[doc_id]
        filename = doc.get('filename', 'document')
        
        if version == 'original':
            path = doc.get('original_path')
            if not path or not Path(path).exists():
                return jsonify({'error': 'Original not found'}), 404
            return send_file(path, as_attachment=True, download_name=f"original_{filename}")
        
        elif version == 'protected':
            path = doc.get('protected_path')
            if not path or not Path(path).exists():
                return jsonify({'error': 'Protected version not found'}), 404
            return send_file(path, as_attachment=True, download_name=f"protected_{filename}")
        
        return jsonify({'error': 'Invalid version'}), 400
    
    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large (max 500MB)'}), 413

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    logger.info("Starting Image Protection System...")
    if GEMINI_API_KEY:
        logger.info("✓ Gemini Vision API configured")
    else:
        logger.warning("⚠ Gemini API key not found - analysis will not work")
    logger.info("✓ Document Processor initialized")
    logger.info("✓ PII Redactor initialized")
    app.run(debug=False, port=5001, host='127.0.0.1')
