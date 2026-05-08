"""
PrivacyGuard — Data Regulation Intelligence
Flask application: scan, classify, redact, and protect sensitive documents.
"""

from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
import json
import re
import mimetypes
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import uuid
import logging
import shutil
import pytesseract
import cv2
from PIL import Image

from document_processor import DocumentProcessor
from pii_redactor import PIIRedactor
from ocr_processor import OCRProcessor
from sensitive_data import (
    analyze_sensitive_text, calculate_risk_level, make_document_entity,
    public_entities, get_regulation_impact,
)

try:
    from pii_detector import PresidioAnalyzer
except ImportError as exc:
    PresidioAnalyzer = None
    PRESIDIO_IMPORT_ERROR = exc
else:
    PRESIDIO_IMPORT_ERROR = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Flask init ────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config['SECRET_KEY'] = 'privacyguard-secret-key-change-in-production'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# ── Processor init ────────────────────────────────────────────────────────────

doc_processor = DocumentProcessor()
ocr_processor = OCRProcessor()
redactor = PIIRedactor()

try:
    if PresidioAnalyzer is None:
        raise PRESIDIO_IMPORT_ERROR
    presidio = PresidioAnalyzer()
    presidio_engine = presidio.analyzer
except Exception as exc:
    logger.warning(f"Presidio unavailable; falling back to regex rules only: {exc}")
    presidio_engine = None

# ── Storage paths ─────────────────────────────────────────────────────────────

DOCUMENTS_DB = 'documents.json'
USERS_DB = 'users.json'

# In-memory: maps guest session-id -> list of doc_ids
# Cleared on server restart so guests cannot see previous sessions' uploads.
GUEST_SESSIONS: Dict[str, List[str]] = {}

Path('uploads').mkdir(exist_ok=True)
Path('protected_documents').mkdir(exist_ok=True)
Path('temp_images').mkdir(exist_ok=True)

SUPPORTED_EXTENSIONS = {
    '.jpg': 'image', '.jpeg': 'image', '.png': 'image',
    '.bmp': 'image', '.gif': 'image', '.webp': 'image', '.tiff': 'image',
    '.pdf': 'pdf',
    '.docx': 'docx',
}

# ── User management ───────────────────────────────────────────────────────────

def load_users() -> Dict:
    if Path(USERS_DB).exists():
        with open(USERS_DB) as f:
            return json.load(f)
    return {}

def save_users(users: Dict) -> None:
    with open(USERS_DB, 'w') as f:
        json.dump(users, f, indent=2)

def current_user_id() -> Optional[str]:
    return session.get('user_id')

def get_guest_sid() -> str:
    """Return (or create) the in-memory session ID for the current guest."""
    if 'sid' not in session:
        session['sid'] = str(uuid.uuid4())
    return session['sid']

# ── Document database ─────────────────────────────────────────────────────────

def load_documents() -> Dict:
    if Path(DOCUMENTS_DB).exists():
        with open(DOCUMENTS_DB) as f:
            return json.load(f)
    return {}

def save_documents(docs: Dict) -> None:
    with open(DOCUMENTS_DB, 'w') as f:
        json.dump(docs, f, indent=2)

def get_current_user_docs() -> Dict:
    """Return only the documents visible to the current request's owner."""
    all_docs = load_documents()
    user_id = current_user_id()
    if user_id:
        return {k: v for k, v in all_docs.items() if v.get('owner_id') == user_id}
    sid = get_guest_sid()
    guest_ids = set(GUEST_SESSIONS.get(sid, []))
    return {k: v for k, v in all_docs.items() if k in guest_ids}

def can_access_doc(doc: Dict) -> bool:
    """Return True if the current session owns this document."""
    user_id = current_user_id()
    if user_id:
        return doc.get('owner_id') == user_id
    sid = get_guest_sid()
    return doc.get('id') in GUEST_SESSIONS.get(sid, [])

# ── Core analysis helpers ─────────────────────────────────────────────────────

def detect_file_type(filepath: str) -> str:
    ext = Path(filepath).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {ext}")
    return SUPPORTED_EXTENSIONS[ext]


def build_protected_path(doc_id: str, filename: str, file_type: str) -> str:
    original = Path(filename)
    ext = original.suffix.lower()
    if file_type == 'pdf':
        ext = '.pdf'
    elif file_type == 'image':
        ext = ext if ext in {'.jpg', '.jpeg', '.png', '.bmp', '.webp', '.tiff'} else '.jpg'
    elif file_type == 'docx':
        ext = '.docx'
    else:
        ext = original.suffix or '.dat'
    safe_stem = secure_filename(original.stem) or 'document'
    return str(Path('protected_documents') / f"protected_{doc_id}_{safe_stem}{ext}")


def extract_image_boxes(image_path: str) -> List[Dict]:
    try:
        image = Image.open(image_path)
        data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
        boxes = []
        for idx, text in enumerate(data.get('text', [])):
            text = (text or '').strip()
            try:
                confidence = float(data.get('conf', ['-1'])[idx])
            except ValueError:
                confidence = -1
            if not text or confidence < 25:
                continue
            boxes.append({
                'text': text,
                'confidence': confidence,
                'x': int(data['left'][idx]),
                'y': int(data['top'][idx]),
                'width': int(data['width'][idx]),
                'height': int(data['height'][idx]),
                'line_num': data.get('line_num', [0])[idx],
                'block_num': data.get('block_num', [0])[idx],
            })
        return boxes
    except Exception as exc:
        logger.warning(f"OCR boxes extraction failed for {image_path}: {exc}")
        return []


def _find_entity_boxes(ocr_boxes: List[Dict], raw_value: str, entity_type: str) -> List[Dict]:
    if not raw_value or not ocr_boxes:
        return []
    NUMERIC_TYPES = {
        'US_SSN', 'CREDIT_CARD', 'US_ROUTING_NUMBER', 'CARD_EXPIRATION',
        'CARD_SECURITY_CODE', 'PHONE_NUMBER', 'IBAN_CODE',
    }
    result = []
    if entity_type in NUMERIC_TYPES:
        target_digits = re.sub(r'\D', '', raw_value)
        if not target_digits:
            return []
        for box in ocr_boxes:
            box_digits = re.sub(r'\D', '', box['text'])
            if not box_digits or len(box_digits) < 3:
                continue
            if box_digits in target_digits or target_digits in box_digits:
                result.append({k: box[k] for k in ('x', 'y', 'width', 'height')})
    else:
        words = [re.sub(r'[^a-z]', '', w.lower()) for w in raw_value.split()]
        words = [w for w in words if len(w) >= 2]
        if not words:
            return []
        for box in ocr_boxes:
            box_alpha = re.sub(r'[^a-z]', '', box['text'].lower())
            if not box_alpha or len(box_alpha) < 2:
                continue
            for word in words:
                if word in box_alpha or box_alpha in word:
                    result.append({k: box[k] for k in ('x', 'y', 'width', 'height')})
                    break
    return result


def attach_boxes_to_entities(image_path: str, entities: List[Dict]) -> List[Dict]:
    ocr_boxes = extract_image_boxes(image_path)
    if not ocr_boxes:
        return entities
    all_text_boxes = [
        {'x': b['x'], 'y': b['y'], 'width': b['width'], 'height': b['height']}
        for b in ocr_boxes
    ]
    for entity in entities:
        if entity.get('doc_level'):
            entity['boxes'] = []
            continue
        entity_type = entity.get('type', '')
        raw_value = entity.get('raw_value', '')
        matched = _find_entity_boxes(ocr_boxes, raw_value, entity_type)
        if not matched and entity.get('risk_level') in {'HIGH', 'CRITICAL'}:
            matched = all_text_boxes
        entity['boxes'] = matched
    return entities


def looks_like_payment_card(image_path: str) -> Optional[Dict]:
    try:
        image = cv2.imread(str(image_path))
        if image is None:
            return None
        height, width = image.shape[:2]
        image_area = height * width
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        edges = cv2.Canny(blurred, 50, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        best = None
        for contour in contours:
            area = cv2.contourArea(contour)
            if area < image_area * 0.12:
                continue
            x, y, w, h = cv2.boundingRect(contour)
            if w == 0 or h == 0:
                continue
            aspect_ratio = max(w, h) / min(w, h)
            fill_ratio = area / float(w * h)
            if 1.35 <= aspect_ratio <= 1.85 and fill_ratio >= 0.45:
                score = min(0.72, 0.42 + min(area / image_area, 0.3))
                candidate = {
                    'confidence': round(score, 3),
                    'evidence': ['card-sized rectangular object detected', f'aspect ratio {aspect_ratio:.2f}'],
                }
                if best is None or candidate['confidence'] > best['confidence']:
                    best = candidate
        return best
    except Exception as exc:
        logger.debug(f"Payment card visual heuristic failed: {exc}")
        return None


def default_safeguards(entities: List[Dict], method: str = 'blur') -> Dict:
    return {idx: method for idx, _ in enumerate(entities)}


def analyze_upload(file_path: str, file_type: str):
    if file_type == 'image':
        extraction = ocr_processor.extract_from_file(file_path)
        entities = analyze_sensitive_text(extraction.get('text', ''), presidio_engine)
        has_any_doc_type = any(e.get('doc_level') for e in entities)
        has_text_entities = any(not e.get('doc_level') for e in entities)
        if not has_any_doc_type and not has_text_entities:
            card_visual = looks_like_payment_card(file_path)
            if card_visual:
                entities.append(make_document_entity(
                    'CREDIT_CARD_DOCUMENT', card_visual['confidence'], card_visual['evidence'],
                ))
        entities = attach_boxes_to_entities(file_path, entities)
        return extraction, entities

    if file_type == 'pdf':
        page_entities = []
        page_text = []
        image_paths = doc_processor.convert_to_images(file_path, 'pdf')
        for page_idx, image_path in enumerate(image_paths, start=1):
            extraction = ocr_processor.extract_from_file(image_path)
            text = extraction.get('text', '')
            page_text.append(text)
            entities = analyze_sensitive_text(text, presidio_engine)
            entities = attach_boxes_to_entities(image_path, entities)
            for entity in entities:
                entity['page'] = page_idx
                entity['source_image'] = image_path
            page_entities.extend(entities)
        return {
            'success': True,
            'text': '\n--- PAGE BREAK ---\n'.join(page_text),
            'page_count': len(image_paths),
            'metadata': {'extraction_method': 'PDF pages OCR'},
        }, page_entities

    extraction = ocr_processor.extract_from_file(file_path)
    entities = analyze_sensitive_text(extraction.get('text', ''), presidio_engine)
    return extraction, entities


def create_protected_copy(file_path: str, file_type: str, filename: str, doc_id: str, entities: List[Dict]) -> str:
    protected_path = build_protected_path(doc_id, filename, file_type)
    if not entities:
        shutil.copy(file_path, protected_path)
        return protected_path
    if file_type == 'image':
        redactor.apply_redaction_to_image(file_path, entities, default_safeguards(entities, 'blur'), protected_path)
        return protected_path
    if file_type == 'pdf':
        source_images = doc_processor.convert_to_images(file_path, 'pdf')
        protected_images = []
        for page_num, image_path in enumerate(source_images, start=1):
            page_entities = [e for e in entities if e.get('page') == page_num]
            page_output = str(Path('temp_images') / f'protected_{doc_id}_page_{page_num}.jpg')
            if page_entities:
                redactor.apply_redaction_to_image(image_path, page_entities, default_safeguards(page_entities, 'blur'), page_output)
            else:
                shutil.copy(image_path, page_output)
            protected_images.append(page_output)
        if protected_images:
            rebuilt_path = doc_processor.rebuild_document(protected_images, 'pdf', Path(protected_path).name)
            if rebuilt_path != protected_path:
                shutil.move(rebuilt_path, protected_path)
            return protected_path
    if file_type == 'docx':
        redactor.apply_redaction_to_document(file_path, entities, default_safeguards(entities, 'redact'), protected_path, file_type='word')
        return protected_path
    shutil.copy(file_path, protected_path)
    return protected_path


def summarize_documents(docs: Dict) -> List[Dict]:
    rows = []
    for doc_id, doc in docs.items():
        rows.append({
            'id': doc_id,
            'filename': doc.get('filename', 'Unknown'),
            'file_type': doc.get('file_type', ''),
            'uploaded_at': doc.get('uploaded_at', ''),
            'status': doc.get('status', 'protected'),
            'risk_level': doc.get('risk_level', 'LOW'),
            'threats_count': len(doc.get('entities', [])),
            'entity_count': len(doc.get('entities', [])),
            'has_protected': bool(doc.get('protected_path')),
            'document_types': doc.get('document_types', []),
            'regulations': doc.get('regulations', []),
        })
    return sorted(rows, key=lambda item: item.get('uploaded_at', ''), reverse=True)


def document_report(doc: Dict) -> Dict:
    entities = doc.get('entities', [])
    return {
        'document': doc.get('filename'),
        'uploaded': doc.get('uploaded_at'),
        'file_type': doc.get('file_type'),
        'risk_level': doc.get('risk_level', 'LOW'),
        'entities': entities,
        'entity_count': len(entities),
        'document_types': doc.get('document_types', []),
        'regulations': doc.get('regulations', []),
        'extraction': doc.get('extraction', {}),
    }


def detected_document_types(entities: List[Dict]) -> List[Dict]:
    return [
        {
            'type': e.get('type'),
            'display_name': e.get('display_name'),
            'confidence': e.get('confidence'),
            'risk_level': e.get('risk_level'),
            'evidence': e.get('evidence', []),
        }
        for e in entities if e.get('doc_level')
    ]


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/login')
def login_page():
    if current_user_id():
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/api/auth/me')
def auth_me():
    user_id = current_user_id()
    if user_id:
        users = load_users()
        user = users.get(user_id, {})
        return jsonify({'logged_in': True, 'user_id': user_id, 'username': user.get('username', '')})
    return jsonify({'logged_in': False})

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip().lower()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    users = load_users()
    for user_id, user in users.items():
        if user.get('username', '').lower() == username:
            if check_password_hash(user['password_hash'], password):
                session.clear()
                session['user_id'] = user_id
                session.permanent = True
                return jsonify({'success': True, 'username': user['username']})
            return jsonify({'error': 'Incorrect password'}), 401
    return jsonify({'error': 'No account found with that username'}), 401

@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    users = load_users()
    if any(u.get('username', '').lower() == username.lower() for u in users.values()):
        return jsonify({'error': 'Username already taken'}), 409
    user_id = str(uuid.uuid4())
    users[user_id] = {
        'username': username,
        'password_hash': generate_password_hash(password),
        'created_at': datetime.now().isoformat(),
    }
    save_users(users)
    session.clear()
    session['user_id'] = user_id
    session.permanent = True
    return jsonify({'success': True, 'username': username})

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    session.clear()
    return jsonify({'success': True})


# ── Dashboard route ───────────────────────────────────────────────────────────

@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


# ── Document API ──────────────────────────────────────────────────────────────

@app.route('/api/documents')
def get_documents():
    try:
        return jsonify(summarize_documents(get_current_user_docs()))
    except Exception as e:
        logger.error(f"Error getting documents: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        file = request.files['file']
        if not file.filename:
            return jsonify({'error': 'Invalid filename'}), 400

        doc_id = str(uuid.uuid4())
        safe_filename = secure_filename(file.filename)
        if not safe_filename:
            return jsonify({'error': 'Invalid filename'}), 400

        temp_path = f'uploads/{doc_id}_{safe_filename}'
        Path('uploads').mkdir(exist_ok=True)
        file.save(temp_path)

        try:
            file_type = detect_file_type(temp_path)
            extraction, entities = analyze_upload(temp_path, file_type)
            if not extraction.get('success'):
                return jsonify({'error': extraction.get('error', 'Could not extract text')}), 400

            risk_level = calculate_risk_level(entities)
            protected_path = create_protected_copy(temp_path, file_type, safe_filename, doc_id, entities)
            safe_entities = public_entities(entities)
            document_types = detected_document_types(safe_entities)
            regulations = get_regulation_impact(safe_entities)

            user_id = current_user_id()
            doc_record = {
                'id': doc_id,
                'filename': safe_filename,
                'file_type': file_type,
                'uploaded_at': datetime.now().isoformat(),
                'original_path': temp_path,
                'protected_path': protected_path,
                'status': 'protected',
                'entities': safe_entities,
                'document_types': document_types,
                'risk_level': risk_level,
                'regulations': regulations,
                'entity_count': len(entities),
                'owner_id': user_id,  # None for guests
                'extraction': {
                    'char_count': extraction.get('char_count', len(extraction.get('text', ''))),
                    'word_count': extraction.get('word_count', len(extraction.get('text', '').split())),
                    'confidence': extraction.get('confidence'),
                    'metadata': extraction.get('metadata', {}),
                },
            }

            documents = load_documents()
            documents[doc_id] = doc_record
            save_documents(documents)

            # Track guest uploads in memory so they can access them this session
            if not user_id:
                sid = get_guest_sid()
                GUEST_SESSIONS.setdefault(sid, []).append(doc_id)

            return jsonify({
                'success': True,
                'document_id': doc_id,
                'filename': safe_filename,
                'file_type': file_type,
                'risk_level': risk_level,
                'threats_detected': len(entities),
                'entity_count': len(entities),
                'entities': safe_entities,
                'document_types': document_types,
                'regulations': regulations,
                'has_protected': True,
                'protected_download_url': f'/api/download/{doc_id}/protected',
                'message': f'Analysis complete. {len(entities)} sensitive item(s) detected.',
            })

        except Exception as e:
            logger.error(f"Analysis error: {e}")
            import traceback; traceback.print_exc()
            return jsonify({'error': f'Processing failed: {str(e)}'}), 500

    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/<doc_id>')
def get_report(doc_id):
    try:
        all_docs = load_documents()
        if doc_id not in all_docs:
            return jsonify({'error': 'Document not found'}), 404
        doc = all_docs[doc_id]
        if not can_access_doc(doc):
            return jsonify({'error': 'Access denied'}), 403
        return jsonify(document_report(doc))
    except Exception as e:
        logger.error(f"Report error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/preview/<doc_id>/<version>')
def preview(doc_id, version):
    try:
        all_docs = load_documents()
        if doc_id not in all_docs:
            return jsonify({'error': 'Document not found'}), 404
        doc = all_docs[doc_id]
        if not can_access_doc(doc):
            return jsonify({'error': 'Access denied'}), 403
        if doc.get('file_type') != 'image':
            return jsonify({'error': 'Preview only available for images'}), 400
        path = doc.get('original_path') if version == 'original' else doc.get('protected_path')
        if not path or not Path(path).exists():
            return jsonify({'error': 'File not found'}), 404
        mime_type, _ = mimetypes.guess_type(path)
        return send_file(path, mimetype=mime_type or 'image/jpeg')
    except Exception as e:
        logger.error(f"Preview error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/download/<doc_id>/<version>')
def download(doc_id, version):
    try:
        all_docs = load_documents()
        if doc_id not in all_docs:
            return jsonify({'error': 'Document not found'}), 404
        doc = all_docs[doc_id]
        if not can_access_doc(doc):
            return jsonify({'error': 'Access denied'}), 403
        filename = doc.get('filename', 'document')
        if version == 'original':
            path = doc.get('original_path')
            if not path or not Path(path).exists():
                return jsonify({'error': 'Original not found'}), 404
            return send_file(path, as_attachment=True, download_name=f'original_{filename}')
        elif version == 'protected':
            path = doc.get('protected_path')
            if not path or not Path(path).exists():
                return jsonify({'error': 'Protected version not found'}), 404
            return send_file(path, as_attachment=True, download_name=f'protected_{filename}')
        return jsonify({'error': 'Invalid version'}), 400
    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/delete/<doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    try:
        all_docs = load_documents()
        if doc_id not in all_docs:
            return jsonify({'error': 'Document not found'}), 404
        doc = all_docs[doc_id]
        if not can_access_doc(doc):
            return jsonify({'error': 'Access denied'}), 403
        for pk in ('original_path', 'protected_path'):
            path = doc.get(pk)
            if path:
                Path(path).unlink(missing_ok=True)
        del all_docs[doc_id]
        save_documents(all_docs)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Delete error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/documents/bulk-delete', methods=['POST'])
def bulk_delete():
    try:
        data = request.get_json() or {}
        doc_ids = data.get('doc_ids', [])
        if not doc_ids:
            return jsonify({'error': 'No document IDs provided'}), 400
        all_docs = load_documents()
        deleted = 0
        for doc_id in doc_ids:
            if doc_id not in all_docs:
                continue
            doc = all_docs[doc_id]
            if not can_access_doc(doc):
                continue
            for pk in ('original_path', 'protected_path'):
                path = doc.get(pk)
                if path:
                    Path(path).unlink(missing_ok=True)
            del all_docs[doc_id]
            deleted += 1
        save_documents(all_docs)
        return jsonify({'success': True, 'deleted': deleted})
    except Exception as e:
        logger.error(f"Bulk delete error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/protect/<doc_id>', methods=['POST'])
def apply_safeguards_endpoint(doc_id):
    try:
        all_docs = load_documents()
        if doc_id not in all_docs:
            return jsonify({'error': 'Document not found'}), 404
        doc = all_docs[doc_id]
        if not can_access_doc(doc):
            return jsonify({'error': 'Access denied'}), 403

        data = request.get_json() or {}
        safeguard_map = {int(k): v for k, v in data.get('safeguards', {}).items()}
        file_path = doc.get('original_path')
        file_type = doc.get('file_type', 'image')

        if not file_path or not Path(file_path).exists():
            return jsonify({'error': 'Original file not found'}), 404

        extraction, entities = analyze_upload(file_path, file_type)
        active_safeguards = {idx: method for idx, method in safeguard_map.items() if method != 'keep'}
        protected_path = build_protected_path(doc_id, doc['filename'], file_type)

        if file_type == 'image':
            redactor.apply_redaction_to_image(file_path, entities, active_safeguards, protected_path)
        elif file_type == 'docx':
            redactor.apply_redaction_to_document(file_path, entities, active_safeguards, protected_path, file_type='word')
        else:
            shutil.copy(file_path, protected_path)

        all_docs[doc_id]['protected_path'] = protected_path
        save_documents(all_docs)

        return jsonify({
            'success': True,
            'preview_url': f'/api/preview/{doc_id}/protected',
            'download_url': f'/api/download/{doc_id}/protected',
        })

    except Exception as e:
        logger.error(f'apply_safeguards error: {e}')
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large (max 500MB)'}), 413

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    logger.info("Starting PrivacyGuard...")
    app.run(debug=False, port=5001, host='127.0.0.1')
