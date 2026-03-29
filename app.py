"""
Image Protection System - Production-Grade Flask Application
Implements Presidio-based PII detection with user-controlled safeguarding
"""

from flask import Flask, render_template, request, jsonify, session, redirect, send_file, Response
from flask_session import Session
from pathlib import Path
import os
import json
from datetime import datetime
import uuid
import secrets
import base64
import logging
import traceback

# Import new analysis and safeguarding modules
from pii_detector import PresidioAnalyzer
from ocr_processor import OCRProcessor
from report_generator import ReportGenerator
from encryption_engine import EncryptionEngine
from pii_redactor import PIIRedactor
from document_processor import DocumentProcessor

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

# Initialize analysis and processing engines
pii_analyzer = PresidioAnalyzer()
ocr_processor = OCRProcessor()
report_generator = ReportGenerator()
encryption_engine = EncryptionEngine()
redactor = PIIRedactor(encryption_engine)
doc_processor = DocumentProcessor()

# Database and storage paths
DOCUMENTS_DB = 'documents.json'
ANALYSIS_DB = 'analysis_reports.json'
KEY_VAULT = 'key_vault.json'


Path('uploads').mkdir(exist_ok=True)
Path('protected_documents').mkdir(exist_ok=True)
Path('reports').mkdir(exist_ok=True)
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

def load_analysis_reports():
    """Load analysis reports database"""
    if Path(ANALYSIS_DB).exists():
        with open(ANALYSIS_DB, 'r') as f:
            return json.load(f)
    return {}

def save_analysis_reports(reports):
    """Save analysis reports database"""
    with open(ANALYSIS_DB, 'w') as f:
        json.dump(reports, f, indent=2)

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
    return render_template('dashboard.html')

@app.route('/api/documents')
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
                'status': doc.get('status', 'uploaded'),
                'risk_level': doc.get('risk_level', 'UNKNOWN'),
                'entity_count': len(doc.get('entities', []))
            })
        
        return jsonify(doc_list)
    except Exception as e:
        logger.error(f"Error getting documents: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================
# ROUTES - FILE ANALYSIS & REPORTS
# ============================================

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """
    Upload file and trigger Presidio analysis  
    Returns report for user approval
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
            
            # Step 2: Extract text using OCR  
            ocr_result = ocr_processor.extract_from_file(temp_path)
            
            if not ocr_result.get('success'):
                logger.warning(f"OCR extraction failed: {ocr_result.get('error')}")
                extracted_text = ''
            else:
                extracted_text = ocr_result.get('text', '')
            
            # Step 3: Analyze with Presidio
            analysis = pii_analyzer.analyze_text(extracted_text, temp_path)
            
            if not analysis.get('success'):
                logger.warning(f"Presidio analysis failed: {analysis.get('error')}")
                entities = []
                risk_level = 'UNKNOWN'
            else:
                entities = analysis.get('entities', [])
                risk_level = analysis.get('risk_level', 'LOW')
            
            # Step 4: Generate reports (HTML and JSON)
            html_report_path = f'reports/{doc_id}_report.html'
            pdf_report_path = f'reports/{doc_id}_report.pdf'
            
            html_report = report_generator.generate_html_report(
                temp_path, file.filename, entities, risk_level, html_report_path
            )
            
            try:
                pdf_path = report_generator.generate_pdf_report(
                    temp_path, file.filename, entities, risk_level, pdf_report_path
                )
            except Exception as e:
                logger.warning(f"PDF generation failed: {e}")
                pdf_path = None
            
            # Step 5: Save to database
            documents = load_documents()
            documents[doc_id] = {
                'id': doc_id,
                'filename': file.filename,
                'file_type': file_type,
                'uploaded_by': email,
                'uploaded_at': datetime.now().isoformat(),
                'original_path': temp_path,
                'status': 'report_ready',  # Waiting for user to approve safeguards
                'entities': entities,
                'risk_level': risk_level,
                'entity_count': len(entities)
            }
            save_documents(documents)
            
            # Return report for user approval
            return jsonify({
                'success': True,
                'document_id': doc_id,
                'filename': file.filename,
                'file_type': file_type,
                'risk_level': risk_level,
                'entity_count': len(entities),
                'entities': entities,
                'html_report': html_report,
                'has_pdf': bool(pdf_path),
                'message': f'Analysis complete. {len(entities)} PII items detected. Please review recommendations and approve safeguarding methods.'
            })
        
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            traceback.print_exc()
            return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
    
    except Exception as e:
        logger.error(f"Upload error: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<doc_id>')
def get_report(doc_id):
    """
    Get analysis report for document
    Query param: format (html, pdf, json)
    """
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        docs = load_documents()
        if doc_id not in docs:
            return jsonify({'error': 'Document not found'}), 404
        
        doc = docs[doc_id]
        report_format = request.args.get('format', 'html')
        
        if report_format == 'html':
            report_path = f'reports/{doc_id}_report.html'
            if Path(report_path).exists():
                with open(report_path, 'r') as f:
                    return f.read()
            return jsonify({'error': 'Report not found'}), 404
        
        elif report_format == 'pdf':
            report_path = f'reports/{doc_id}_report.pdf'
            if Path(report_path).exists():
                return send_file(report_path, mimetype='application/pdf', as_attachment=True)
            return jsonify({'error': 'PDF report not found'}), 404
        
        elif report_format == 'json':
            return jsonify({
                'document': doc.get('filename'),
                'uploaded': doc.get('uploaded_at'),
                'risk_level': doc.get('risk_level'),
                'entities': doc.get('entities', [])
            })
        
        return jsonify({'error': 'Invalid format'}), 400
    
    except Exception as e:
        logger.error(f"Error getting report: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================
# ROUTES - SAFEGUARD APPROVAL & APPLICATION
# ============================================

@app.route('/api/approve-safeguards/<doc_id>', methods=['POST'])
def approve_safeguards(doc_id):
    """
    User approves and selects safeguarding methods for each entity
    POST data: { entity_choices: { 0: 'blur', 1: 'redact', ... } }
    """
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.json
        entity_choices = data.get('entity_choices', {})
        
        docs = load_documents()
        if doc_id not in docs:
            return jsonify({'error': 'Document not found'}), 404
        
        doc = docs[doc_id]
        
        # Validate choices
        valid_methods = redactor.get_safeguard_methods().keys()
        for idx, method in entity_choices.items():
            if method not in valid_methods:
                return jsonify({'error': f'Invalid safeguard method: {method}'}), 400
        
        # Save approval
        doc['safeguard_approvals'] = entity_choices
        doc['status'] = 'approved'
        doc['approved_at'] = datetime.now().isoformat()
        docs[doc_id] = doc
        save_documents(docs)
        
        return jsonify({
            'success': True,
            'message': 'Safeguarding methods approved. Applying now...'
        })
    
    except Exception as e:
        logger.error(f"Approval error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/apply-safeguards/<doc_id>', methods=['POST'])
def apply_safeguards(doc_id):
    """
    Apply approved safeguarding methods to document
    Creates protected version for download
    """
    if session.get('user_type') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        docs = load_documents()
        if doc_id not in docs:
            return jsonify({'error': 'Document not found'}), 404
        
        doc = docs[doc_id]
        
        if doc.get('status') != 'approved':
            return jsonify({'error': 'Document not approved for safeguarding'}), 400
        
        original_path = doc.get('original_path')
        entities = doc.get('entities', [])
        safeguard_selections = doc.get('safeguard_approvals', {})
        file_type = doc.get('file_type', 'image')
        
        if not Path(original_path).exists():
            return jsonify({'error': 'Original file not found'}), 404
        
        # Create protected version
        Path('protected_documents').mkdir(exist_ok=True)
        protected_filename = f"protected_{doc_id}_{Path(doc.get('filename')).stem}.{Path(doc.get('filename')).suffix.lstrip('.')}"
        protected_path = f'protected_documents/{protected_filename}'
        
        try:
            # Apply safeguarding based on file type
            if file_type == 'word':
                redactor.apply_redaction_to_document(
                    original_path, entities, 
                    {int(k): v for k, v in safeguard_selections.items()},
                    protected_path, file_type
                )
            else:
                # For images, PDFs, etc.
                redactor.apply_redaction_to_image(
                    original_path, entities,
                    {int(k): v for k, v in safeguard_selections.items()},
                    protected_path
                )
            
            # Update document status
            doc['status'] = 'protected'
            doc['protected_path'] = protected_path
            doc['protected_at'] = datetime.now().isoformat()
            docs[doc_id] = doc
            save_documents(docs)
            
            return jsonify({
                'success': True,
                'protected_path': protected_path,
                'message': 'Safeguarding applied successfully'
            })
        
        except Exception as e:
            logger.error(f"Error applying safeguards: {e}")
            return jsonify({'error': f'Safeguarding failed: {str(e)}'}), 500
    
    except Exception as e:
        logger.error(f"Apply safeguards error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================
# ROUTES - DOWNLOADS
# ============================================

@app.route('/api/download/<doc_id>/<version>')
def download(doc_id, version):
    """
    Download document
    version: 'original', 'protected', or 'report'
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
        
        elif version == 'report':
            report_path = f'reports/{doc_id}_report.pdf'
            if not Path(report_path).exists():
                report_path = f'reports/{doc_id}_report.html'
            
            if not Path(report_path).exists():
                return jsonify({'error': 'Report not found'}), 404
            
            return send_file(report_path, as_attachment=True)
        
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
    logger.info(f"✓ Presidio Analyzer initialized")
    logger.info(f"✓ OCR Processor initialized")
    logger.info(f"✓ Report Generator initialized")
    logger.info(f"✓ Encryption Engine initialized")
    app.run(debug=False, port=5001, host='127.0.0.1')
