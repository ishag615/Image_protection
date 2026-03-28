# Image Protection System 🛡️

An intelligent document protection platform that detects and redacts personally identifiable information (PII) from images and documents using Google Gemini Vision AI.

## Features ✨

### 🔍 Advanced PII Detection
- **Comprehensive Detection**: Identifies 9+ categories of sensitive information:
  - Biometric data (faces, fingerprints, iris scans)
  - Document numbers (passports, driver's licenses, IDs)
  - Personal identifiers (names, dates of birth, signatures)
  - Contact information (emails, phone numbers, addresses)
  - Financial data (credit cards, bank accounts, routing numbers)
  - Medical information (insurance numbers, medical records)
  - Digital credentials (passwords, API keys, security codes)
  - Legal identifiers (tax IDs, court records, etc.)
  - Employment data (employee IDs, salary info)

- **AI-Powered Analysis**: Uses Google Gemini 1.5 Flash Vision model with carefully engineered prompts for aggressive and accurate detection

### 🎨 Intelligent Redaction
- **Image Protection**:
  - Multi-layer blur and pixelation (89x89 Gaussian blur + median blur + pixelation)
  - Automatic text region detection and obscuration
  - Aggressive redaction for high-risk items (faces, IDs) - completely black out sensitive areas
  - Moderate redaction for medium-risk items (phone numbers, addresses)
  - Preserves document legibility while protecting sensitive data

- **Document Protection**:
  - Text pattern matching for common sensitive formats (SSN, phone, email, credit card, IP addresses)
  - Automatic redaction of detected patterns with [REDACTED] placeholders
  - Name and address extraction and removal
  - Support for Word documents and PDFs

### 👥 Role-Based Access Control
- **Admin Portal**: 
  - Upload multiple document types (images, PDFs, Word documents)
  - View all uploaded documents with threat analysis
  - Download both original and protected versions
  - View detailed threat detection reports
  - Manage admin keys and audit logs

- **Guest Access**:
  - Browse available documents
  - Download only protected versions (cannot access originals)
  - View risk levels and threat summaries

### 📊 Detailed Threat Analysis
- Type of sensitive data detected
- Exact location in document
- Risk level classification (High/Medium/Low)
- Detailed descriptions of each finding
- Raw Gemini analysis for transparency

## System Setup 🚀

### Prerequisites
- Python 3.8+
- Google Gemini API Key
- Virtual environment (recommended)

### Installation

1. **Clone Repository**
```bash
git clone https://github.com/ishag615/Image_protection.git
cd Image_protection
```

2. **Create Virtual Environment**
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Set Environment Variables**
```bash
export GOOGLE_API_KEY="your-google-gemini-api-key"
```

### Running the Application

```bash
source .venv/bin/activate
export GOOGLE_API_KEY="your-api-key"
python3 app.py
```

The application will start on `http://localhost:5001`

## Usage Guide 📖

### Admin Workflow

1. **Register**: 
   - Go to home page
   - Click "Admin Register"
   - Enter your email
   - Save the generated admin key securely

2. **Login**:
   - Enter email and admin key
   - Access admin dashboard

3. **Upload Document**:
   - Click "Upload Document"
   - Select image, PDF, or Word document
   - Wait for AI analysis (~10-30 seconds depending on file size)
   - View threat detection report
   - Download protected version

4. **Download Versions**:
   - Original: Full unmodified document (admin only)
   - Protected: Redacted version with PII removed/blurred

### Guest Workflow

1. **Access**:
   - Click "Guest Access"
   - Instant access to protected documents

2. **Browse**:
   - View all available documents
   - See risk levels and threat summaries

3. **Download**:
   - Download only protected versions
   - Cannot access original documents

## Technical Architecture 🏗️

### Core Components

1. **Gemini Vision Integration** (`analyze_with_gemini`)
   - Sends images to Google Gemini 1.5 Flash
   - Comprehensive prompt with detailed PII categories
   - Parses structured responses with TYPE, LOCATION, DETAILS, RISK

2. **PIIRedactor Class** (`pii_redactor.py`)
   - `redact_image_from_threats()`: Multi-layer image redaction
   - `_apply_aggressive_redaction()`: Black-out and heavy blur for high-risk
   - `_apply_moderate_redaction()`: Blur for medium-risk
   - `_blur_text_regions()`: Auto-detect and blur text
   - `_pixelate()`: Apply pixelation effect
   - `redact_document_text()`: Text pattern matching and redaction
   - `create_protected_document()`: Generate safeguarded docs

3. **DocumentProcessor Class** (`document_processor.py`)
   - Converts documents to images for analysis
   - Supports: JPEG, PNG, PDF, DOCX, PPTX
   - Extracts images from documents
   - Creates text renderings for document-only files

4. **Flask Server** (`app.py`)
   - Authentication (admin key + email)
   - File upload and analysis pipeline
   - Protected version generation
   - Download endpoints
   - Audit logging

### Data Flow

```
Upload File
    ↓
Detect File Type
    ↓
Convert to Images (if needed)
    ↓
Send to Gemini Vision for Analysis
    ↓
Parse Threats (TYPE, LOCATION, DETAILS, RISK)
    ↓
Create Protected Version (Redact PII)
    ↓
Store Original + Protected in protected_documents/
    ↓
Return Analysis & Links to Download
```

## API Endpoints 🔌

### Authentication
- `POST /api/auth/admin-register` - Generate admin key
- `POST /api/auth/admin-login` - Admin login
- `POST /api/auth/guest-login` - Guest access
- `POST /api/auth/logout` - Logout

### Admin Operations
- `GET /api/admin/documents` - List all documents
- `POST /api/admin/upload` - Upload and analyze document
- `GET /api/admin/document/<id>` - Get document details
- `GET /api/admin/download/<id>/<version>` - Download original/protected
- `GET /api/admin/audit-log` - View admin activity

### Guest Operations
- `GET /api/guest/documents` - List protected documents
- `GET /api/guest/download/<id>` - Download protected version

## Security Features 🔒

1. **Session-Based Authentication**: Flask session management with secure keys
2. **Role-Based Access Control**: Admin-only and guest-only endpoints
3. **PII Exposure Prevention**: Multi-layer redaction ensures sensitive data cannot be recovered
4. **Audit Logging**: Track all admin activities
5. **Secure Key Management**: Admin keys stored separately from sessions
6. **File Validation**: Type checking and safe file storage

## Redaction Techniques 🎭

### For Images
- **Gaussian Blur (89x89)**: Smooth pixel averaging
- **Median Blur (51x51)**: Additional smoothing for text
- **Pixelation (15-20px blocks)**: Further obscuration
- **Complete Black-Out**: For highest risk items like faces and IDs
- **Dynamic Text Detection**: Auto-finds and blurs text regions

### For Documents  
- **Pattern-Based Redaction**:
  - SSN: `\b\d{3}-\d{2}-\d{4}\b`
  - Phone: Flexible format matching
  - Email: Standard email pattern
  - Credit Card: 13-19 digit number blocks
  - IP Address: Dotted quad notation
  - Dates: Multiple date formats
  
- **Content-Based Redaction**:
  - Name extraction from capitalized words
  - Address detection and removal
  - Placeholder replacement: `[REDACTED]`, `[NAME]`, `[ADDRESS]`

## File Structure 📁

```
Image_protection/
├── app.py                      # Main Flask application
├── pii_redactor.py            # PII redaction engine
├── document_processor.py       # Document conversion & processing
├── auth.py                     # Authentication module
├── requirements.txt           # Python dependencies
├── documents.json             # Document metadata database
├── key_vault.json             # Admin keys storage
├── templates/                 # HTML templates
│   ├── login.html
│   ├── admin_dashboard.html
│   └── guest_view.html
├── uploads/                   # Temporary file storage
├── protected_documents/       # Protected version storage
└── temp_images/              # Temporary image conversion
```

## Configuration ⚙️

### Environment Variables
```bash
GOOGLE_API_KEY = "your-gemini-api-key"  # Required
SECRET_KEY    = "your-secret-key"       # For Flask sessions
```

### Customizable Parameters
In `pii_redactor.py`:
- `blur_kernel`: Blur intensity (default: (89, 89))
- `min_confidence`: Confidence threshold
- Pixel size for pixelation effects

## Performance Considerations ⚡

- **Image Analysis**: ~10-20 seconds per image
- **PDF Processing**: ~3-5 seconds per page
- **Document Redaction**: Real-time after analysis
- **File Size Limit**: Recommended max 50MB per document

## Troubleshooting 🔧

### API Key Issues
```bash
# Verify API key is set
echo $GOOGLE_API_KEY

# Re-export if needed
export GOOGLE_API_KEY="your-key"
```

### Import Errors
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Check specific packages
pip list | grep -E "opencv|pillow|google"
```

### Port Already in Use
```bash
# Change port in app.py
app.run(debug=True, port=5002)  # Use different port

# Or kill the process
lsof -i :5001
kill -9 <PID>
```

## Future Enhancements 🚀

- [ ] OCR for embedded text detection in images
- [ ] Facial recognition for better face detection
- [ ] Database storage for scalability
- [ ] Encryption for protected documents
- [ ] Batch processing for multiple files
- [ ] Custom redaction rules for enterprise use
- [ ] Integration with AWS Rekognition
- [ ] API rate limiting and quotas
- [ ] Document versioning and history

## License 📜

MIT License - See LICENSE file for details

## Contributing 👥

Contributions welcome! Please feel free to:
- Report bugs
- Suggest improvements  
- Submit pull requests
- Share feedback

## Support 💬

For issues or questions, please create an issue on GitHub.

---

**Built with ❤️ using Flask, Google Gemini AI, and OpenCV**
