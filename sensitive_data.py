"""
Sensitive data definitions and deterministic PII analysis helpers.

Source of truth for what should be treated as sensitive before a protected
copy is created. Supports document-level classification (passport, SSN card,
debit card, student ID, bank statement, credentials, etc.) and field-level
entity detection (SSN, credit card number, password, routing number, etc.).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class SensitiveType:
    entity_type: str
    display_name: str
    risk_level: str
    description: str
    recommendation: str


SENSITIVE_TYPES: Dict[str, SensitiveType] = {
    # ── Payment instruments ─────────────────────────────────────────────────
    "CREDIT_CARD": SensitiveType(
        "CREDIT_CARD", "Credit Card Number", "HIGH",
        "Payment card primary account number.",
        "Mask or redact before sharing. This is high-risk financial data.",
    ),
    "CARD_EXPIRATION": SensitiveType(
        "CARD_EXPIRATION", "Card Expiration Date", "HIGH",
        "Payment card expiration date.",
        "Mask together with the card number and cardholder name.",
    ),
    "CARD_SECURITY_CODE": SensitiveType(
        "CARD_SECURITY_CODE", "Card Security Code (CVV)", "HIGH",
        "Payment card CVV/CVC/CID security code.",
        "Never share visibly. Fully redact or blur.",
    ),
    # ── Government identifiers ──────────────────────────────────────────────
    "US_SSN": SensitiveType(
        "US_SSN", "Social Security Number", "HIGH",
        "US Social Security Number.",
        "Fully redact or encrypt. Exposure can enable identity theft.",
    ),
    "US_DRIVER_LICENSE": SensitiveType(
        "US_DRIVER_LICENSE", "Driver License Number", "HIGH",
        "Government-issued driver license identifier.",
        "Redact or encrypt unless there is a strict business need.",
    ),
    "US_PASSPORT": SensitiveType(
        "US_PASSPORT", "Passport Number", "HIGH",
        "Government-issued passport identifier.",
        "Redact or encrypt before external sharing.",
    ),
    # ── Financial ───────────────────────────────────────────────────────────
    "IBAN_CODE": SensitiveType(
        "IBAN_CODE", "Bank Account Number (IBAN)", "HIGH",
        "Banking account identifier such as an IBAN.",
        "Redact or encrypt. This can expose financial accounts.",
    ),
    "US_ROUTING_NUMBER": SensitiveType(
        "US_ROUTING_NUMBER", "Bank Routing Number", "HIGH",
        "ABA/ACH routing number identifying a US financial institution.",
        "Redact or encrypt. Combined with account number enables wire fraud.",
    ),
    # ── Contact ─────────────────────────────────────────────────────────────
    "EMAIL_ADDRESS": SensitiveType(
        "EMAIL_ADDRESS", "Email Address", "MEDIUM",
        "Personal or business email address.",
        "Replace or mask when the recipient does not need direct contact info.",
    ),
    "PHONE_NUMBER": SensitiveType(
        "PHONE_NUMBER", "Phone Number", "MEDIUM",
        "Personal or business phone number.",
        "Mask or replace to reduce spam and social-engineering risk.",
    ),
    "LOCATION": SensitiveType(
        "LOCATION", "Address or Location", "MEDIUM",
        "Street address or precise location.",
        "Generalize, mask, or redact if it identifies a private residence.",
    ),
    # ── Network ─────────────────────────────────────────────────────────────
    "IP_ADDRESS": SensitiveType(
        "IP_ADDRESS", "IP Address", "MEDIUM",
        "Network address.",
        "Mask if it reveals internal systems or personal network details.",
    ),
    # ── Identity ────────────────────────────────────────────────────────────
    "PERSON": SensitiveType(
        "PERSON", "Person Name", "MEDIUM",
        "Individual person name.",
        "Review context and mask when identity is not required.",
    ),
    "DATE_TIME": SensitiveType(
        "DATE_TIME", "Date / Time", "LOW",
        "Date or time value.",
        "Review when combined with other identifiers.",
    ),
    # ── Credentials ─────────────────────────────────────────────────────────
    "USERNAME": SensitiveType(
        "USERNAME", "Username", "MEDIUM",
        "Login username or online handle.",
        "Mask unless the recipient explicitly requires it.",
    ),
    "PASSWORD": SensitiveType(
        "PASSWORD", "Password / Credential", "CRITICAL",
        "Login password, passphrase, or secret credential.",
        "Immediately redact. Never store or transmit in plain text.",
    ),
    # ── Document-level types ────────────────────────────────────────────────
    "CREDIT_CARD_DOCUMENT": SensitiveType(
        "CREDIT_CARD_DOCUMENT", "Credit Card", "HIGH",
        "Image or document appears to contain a credit card.",
        "Protect the full card image or mask card number, expiry, CVV, and name.",
    ),
    "DEBIT_CARD_DOCUMENT": SensitiveType(
        "DEBIT_CARD_DOCUMENT", "Debit Card", "HIGH",
        "Image or document appears to contain a debit card.",
        "Protect card number, expiry, and cardholder name. PIN must never be stored.",
    ),
    "SSN_DOCUMENT": SensitiveType(
        "SSN_DOCUMENT", "Social Security Card / Document", "HIGH",
        "Document appears to contain Social Security information.",
        "Redact SSN values and any identity fields before sharing.",
    ),
    "PASSPORT_DOCUMENT": SensitiveType(
        "PASSPORT_DOCUMENT", "Passport", "HIGH",
        "Document appears to be a passport or passport information page.",
        "Protect passport number, name, nationality, date of birth, and address fields.",
    ),
    "DRIVER_LICENSE_DOCUMENT": SensitiveType(
        "DRIVER_LICENSE_DOCUMENT", "Driver License", "HIGH",
        "Document appears to be a driver license or government ID card.",
        "Protect license number, address, date of birth, name, and document identifiers.",
    ),
    "STUDENT_ID_DOCUMENT": SensitiveType(
        "STUDENT_ID_DOCUMENT", "Student ID", "HIGH",
        "Document appears to be a student identification card.",
        "Protect student number, name, and institution under FERPA guidelines.",
    ),
    "BIRTH_CERTIFICATE_DOCUMENT": SensitiveType(
        "BIRTH_CERTIFICATE_DOCUMENT", "Birth Certificate", "HIGH",
        "Document appears to be a birth certificate.",
        "Protect full name, date and place of birth, parent names, and certificate number.",
    ),
    "HEALTH_INSURANCE_DOCUMENT": SensitiveType(
        "HEALTH_INSURANCE_DOCUMENT", "Health Insurance Card", "HIGH",
        "Document appears to contain health insurance information.",
        "Protect member ID, group number, plan details, and subscriber name.",
    ),
    "MEDICAL_RECORD_DOCUMENT": SensitiveType(
        "MEDICAL_RECORD_DOCUMENT", "Medical Record", "CRITICAL",
        "Document appears to contain medical or health records.",
        "Fully redact all health identifiers, diagnoses, medications, and treatment info.",
    ),
    "BANK_STATEMENT_DOCUMENT": SensitiveType(
        "BANK_STATEMENT_DOCUMENT", "Bank Statement", "CRITICAL",
        "Document appears to contain a banking account statement.",
        "Redact account number, routing number, balances, and all transaction details.",
    ),
    "CREDENTIALS_DOCUMENT": SensitiveType(
        "CREDENTIALS_DOCUMENT", "Credentials / Login Document", "CRITICAL",
        "Document appears to contain usernames, passwords, or API credentials.",
        "Immediately redact all credentials. Rotate any exposed secrets.",
    ),
    "BROWSER_HISTORY_DOCUMENT": SensitiveType(
        "BROWSER_HISTORY_DOCUMENT", "Browser / Search History", "MEDIUM",
        "Document appears to contain browser or search history.",
        "Review URLs for sensitive sites (banking, healthcare, personal) before sharing.",
    ),
}


# ── Regex patterns ────────────────────────────────────────────────────────────

REGEX_PATTERNS = {
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "US_SSN": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"
    ),
    "EMAIL_ADDRESS": re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE
    ),
    "PHONE_NUMBER": re.compile(
        r"(?<!\w)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\w)"
    ),
    "IP_ADDRESS": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "US_PASSPORT": re.compile(r"\b[A-Z][0-9]{8}\b"),
    "IBAN_CODE": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "US_ROUTING_NUMBER": re.compile(
        r"(?:routing|aba|rtn|ach)\s*(?:number|no|#)?\s*[:#-]?\s*(\d{9})\b",
        re.IGNORECASE,
    ),
    "PASSWORD": re.compile(
        r"(?:password|passwd|pwd|pass(?:phrase|code)?|secret)\s*[:#=]\s*(\S{4,})",
        re.IGNORECASE,
    ),
    "USERNAME": re.compile(
        r"(?:(?:username|user(?:\s*name)?|login(?:\s*id)?|user\s*id)\s*[:#=]\s*([A-Za-z0-9_.@-]{3,64})"
        r"|@([A-Za-z0-9_]{3,30})\b)",
        re.IGNORECASE,
    ),
}

FIELD_PATTERNS = {
    "CARD_EXPIRATION": re.compile(
        r"\b(?:exp(?:ires|iration)?|valid\s+thru|good\s+thru)?\s*(0[1-9]|1[0-2])\s*[/.-]\s*(\d{2}|\d{4})\b",
        re.IGNORECASE,
    ),
    "CARD_CVV": re.compile(
        r"\b(?:cvv|cvc|cid|security\s+code)\s*[:#-]?\s*\d{3,4}\b", re.IGNORECASE
    ),
    "CARDHOLDER_NAME": re.compile(
        r"\b(?:card\s*holder|cardholder|name)\s*[:#-]?\s*[A-Z][A-Z .'-]{2,}\s+[A-Z][A-Z .'-]{2,}\b",
        re.IGNORECASE,
    ),
    "DRIVER_LICENSE_NUMBER": re.compile(
        r"\b(?:dl|dln|driver'?s?\s+license|license|lic)\s*(?:no|number|#)?\s*[:#-]?\s*[A-Z0-9-]{5,18}\b",
        re.IGNORECASE,
    ),
    "PASSPORT_NUMBER": re.compile(
        r"\b(?:passport\s*(?:no|number|#)?\s*[:#-]?\s*)?[A-Z][0-9]{7,9}\b",
        re.IGNORECASE,
    ),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:dob|date\s+of\s+birth|birth\s+date)\s*[:#-]?\s*(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})\b",
        re.IGNORECASE,
    ),
}

DOCUMENT_KEYWORDS: Dict[str, Dict] = {
    "CREDIT_CARD_DOCUMENT": {
        "display_name": "Credit Card",
        "keywords": [
            "visa", "mastercard", "american express", "amex", "discover",
            "credit", "valid thru", "good thru", "expires", "cardholder",
            "card holder", "member since", "cvv", "cvc", "bank", "chase",
            "capital one", "wells fargo", "bank of america", "citibank",
        ],
    },
    "DEBIT_CARD_DOCUMENT": {
        "display_name": "Debit Card",
        "keywords": [
            "debit", "checking", "atm card", "bank card", "savings",
            "pin", "withdraw", "debit card", "interac", "maestro",
            "debit visa", "debit mastercard",
        ],
    },
    "SSN_DOCUMENT": {
        "display_name": "Social Security Card",
        "keywords": [
            "social security", "social security number", "ssn", "ssa",
            "social security administration", "taxpayer identification",
            "health and human services", "human services",
            "department of health", "established for",
        ],
    },
    "PASSPORT_DOCUMENT": {
        "display_name": "Passport",
        "keywords": [
            "passport", "passport no", "passport number", "nationality",
            "citizenship", "place of birth", "date of issue", "date of expiry",
            "issuing authority", "surname", "given names",
        ],
    },
    "DRIVER_LICENSE_DOCUMENT": {
        "display_name": "Driver License",
        "keywords": [
            "driver license", "driver's license", "drivers license",
            "license number", "driver", "class", "endorsements", "restrictions",
            "department of motor vehicles", "dmv", "date of birth", "dob",
            "height", "eyes", "sex", "address",
        ],
    },
    "STUDENT_ID_DOCUMENT": {
        "display_name": "Student ID",
        "keywords": [
            "student id", "student identification", "student number", "student #",
            "enrollment", "enrolled", "university", "college", "institute",
            "campus id", "campus card", "faculty", "department",
            "semester", "academic", "graduation", "class of", "gpa",
            "grade point", "student name", "academic year", "matriculation",
            "polytechnic", "academy",
        ],
    },
    "BIRTH_CERTIFICATE_DOCUMENT": {
        "display_name": "Birth Certificate",
        "keywords": [
            "birth certificate", "certificate of birth", "live birth",
            "place of birth", "registrar", "registration number", "vital records",
            "department of health", "county clerk", "born to",
            "certificate of live birth", "state file number",
        ],
    },
    "HEALTH_INSURANCE_DOCUMENT": {
        "display_name": "Health Insurance Card",
        "keywords": [
            "health insurance", "insurance card", "member id", "member #",
            "group number", "group #", "subscriber", "deductible", "copay",
            "co-pay", "benefits", "coverage", "anthem", "aetna", "cigna",
            "humana", "unitedhealthcare", "united health", "blue cross",
            "blue shield", "kaiser", "rxbin", "rx bin", "rxpcn", "rx pcn",
            "pharmacy benefits", "in-network", "out-of-network",
        ],
    },
    "MEDICAL_RECORD_DOCUMENT": {
        "display_name": "Medical Record",
        "keywords": [
            "medical record", "patient", "diagnosis", "prescription", "medication",
            "physician", "treatment", "laboratory", "lab results", "discharge",
            "patient id", "mrn", "medical record number", "allergies",
            "vital signs", "clinical notes", "icd", "chief complaint",
            "history of present illness", "assessment and plan",
        ],
    },
    "BANK_STATEMENT_DOCUMENT": {
        "display_name": "Bank Statement",
        "keywords": [
            "bank statement", "account statement", "statement of account",
            "checking account", "savings account", "routing number",
            "aba number", "aba routing", "account number", "account balance",
            "opening balance", "closing balance", "available balance",
            "current balance", "beginning balance", "ending balance",
            "transaction history", "transaction date", "direct deposit",
            "wire transfer", "overdraft", "deposits", "withdrawals",
        ],
    },
    "CREDENTIALS_DOCUMENT": {
        "display_name": "Credentials / Login",
        "keywords": [
            "username", "password", "user id", "userid", "login",
            "sign in", "signin", "credentials", "authentication",
            "api key", "access token", "secret key", "private key",
            "auth token", "bearer", "oauth", "jwt", "passphrase",
            "passcode", "account name", "user name",
        ],
    },
    "BROWSER_HISTORY_DOCUMENT": {
        "display_name": "Browser / Search History",
        "keywords": [
            "browser history", "search history", "browsing history",
            "visited", "last visited", "chrome history", "firefox history",
            "safari history", "recently visited", "history export",
            "web history", "internet history",
        ],
    },
}

PAYMENT_CARD_BRANDS = {
    "visa", "mastercard", "american express", "amex", "discover", "diners club",
    "jcb", "capital one", "chase", "wells fargo", "bank of america", "citibank",
    "citi", "hsbc",
}

# Maps entity types to applicable data-protection regulations
REGULATION_IMPACT: Dict[str, List[str]] = {
    "CREDIT_CARD":               ["PCI DSS"],
    "CREDIT_CARD_DOCUMENT":      ["PCI DSS"],
    "DEBIT_CARD_DOCUMENT":       ["PCI DSS"],
    "US_SSN":                    ["FERPA", "CCPA", "GDPR"],
    "SSN_DOCUMENT":              ["FERPA", "CCPA", "GDPR"],
    "PASSPORT_DOCUMENT":         ["GDPR", "US Privacy Act"],
    "DRIVER_LICENSE_DOCUMENT":   ["DPPA", "CCPA", "GDPR"],
    "STUDENT_ID_DOCUMENT":       ["FERPA", "GDPR"],
    "HEALTH_INSURANCE_DOCUMENT": ["HIPAA", "CCPA"],
    "MEDICAL_RECORD_DOCUMENT":   ["HIPAA", "CCPA", "GDPR"],
    "BANK_STATEMENT_DOCUMENT":   ["GLBA", "CCPA", "GDPR"],
    "CREDENTIALS_DOCUMENT":      ["GDPR", "NIST CSF"],
    "BIRTH_CERTIFICATE_DOCUMENT":["GDPR", "US Privacy Act"],
    "BROWSER_HISTORY_DOCUMENT":  ["CCPA", "GDPR"],
    "EMAIL_ADDRESS":             ["CAN-SPAM Act", "GDPR"],
    "PASSWORD":                  ["NIST SP 800-63B", "GDPR"],
    "USERNAME":                  ["GDPR"],
    "IBAN_CODE":                 ["PSD2 (EU)", "GDPR"],
    "US_ROUTING_NUMBER":         ["GLBA", "CCPA"],
    "PHONE_NUMBER":              ["GDPR", "TCPA"],
    "LOCATION":                  ["GDPR", "CCPA"],
}

# ── Document-type-aware field limits ──────────────────────────────────────────
# For each document type, defines the field-level entity types that are
# realistically present and the maximum count of each.
# This prevents over-detection — e.g., Presidio reporting 15 PERSON names
# on a single driver's license photo.
DOCUMENT_FIELD_LIMITS: Dict[str, Dict[str, int]] = {
    'SSN_DOCUMENT': {
        'PERSON': 1,
        'US_SSN': 1,
        'DATE_TIME': 1,
    },
    'DRIVER_LICENSE_DOCUMENT': {
        'PERSON': 1,
        'US_DRIVER_LICENSE': 1,
        'DATE_TIME': 2,       # DOB + expiry
        'LOCATION': 1,
    },
    'PASSPORT_DOCUMENT': {
        'PERSON': 1,
        'US_PASSPORT': 1,
        'DATE_TIME': 2,
        'LOCATION': 1,
        'NRP': 1,
    },
    'CREDIT_CARD_DOCUMENT': {
        'PERSON': 1,
        'CREDIT_CARD': 1,
        'CARD_EXPIRATION': 1,
        'CARD_SECURITY_CODE': 1,
    },
    'DEBIT_CARD_DOCUMENT': {
        'PERSON': 1,
        'CREDIT_CARD': 1,
        'CARD_EXPIRATION': 1,
        'CARD_SECURITY_CODE': 1,
    },
    'STUDENT_ID_DOCUMENT': {
        'PERSON': 1,
        'DATE_TIME': 2,
        'EMAIL_ADDRESS': 1,
        'LOCATION': 1,
    },
    'HEALTH_INSURANCE_DOCUMENT': {
        'PERSON': 2,          # subscriber + dependent
        'DATE_TIME': 2,
        'PHONE_NUMBER': 1,
        'LOCATION': 1,
    },
    'MEDICAL_RECORD_DOCUMENT': {
        'PERSON': 2,          # patient + provider
        'DATE_TIME': 5,
        'PHONE_NUMBER': 2,
        'LOCATION': 2,
        'EMAIL_ADDRESS': 1,
    },
    'BANK_STATEMENT_DOCUMENT': {
        'PERSON': 2,
        'US_ROUTING_NUMBER': 1,
        'IBAN_CODE': 2,
        'DATE_TIME': 8,
        'PHONE_NUMBER': 1,
        'LOCATION': 2,
        'EMAIL_ADDRESS': 1,
    },
    'CREDENTIALS_DOCUMENT': {
        'USERNAME': 20,
        'PASSWORD': 20,
        'EMAIL_ADDRESS': 10,
    },
    'BIRTH_CERTIFICATE_DOCUMENT': {
        'PERSON': 3,          # child + two parents
        'DATE_TIME': 2,
        'LOCATION': 2,
    },
    'BROWSER_HISTORY_DOCUMENT': {
        'EMAIL_ADDRESS': 5,
        'PHONE_NUMBER': 2,
        'PERSON': 2,
    },
}


# ── Value masking ─────────────────────────────────────────────────────────────

def mask_value(value: str, entity_type: str) -> str:
    clean = value.strip()
    if not clean:
        return "[DETECTED]"
    if entity_type in {
        "CREDIT_CARD", "US_SSN", "PHONE_NUMBER", "IBAN_CODE",
        "CARD_EXPIRATION", "CARD_SECURITY_CODE", "US_ROUTING_NUMBER",
    }:
        digits = re.sub(r"\D", "", clean)
        if len(digits) > 4:
            return f"{'*' * max(len(digits) - 4, 0)}{digits[-4:]}"
    if entity_type == "EMAIL_ADDRESS" and "@" in clean:
        local, domain = clean.split("@", 1)
        return f"{local[:1]}***@{domain}"
    if entity_type == "PASSWORD":
        return "●" * min(len(clean), 10)
    if len(clean) <= 4:
        return "*" * len(clean)
    return f"{clean[:1]}{'*' * (len(clean) - 2)}{clean[-1:]}"


def normalize_ocr_text(text: str) -> str:
    """Normalize common OCR spacing and punctuation issues without hiding evidence."""
    normalized = text.replace("–", "-").replace("—", "-").replace("−", "-")
    normalized = re.sub(r"(?<=\d)\s+[/.-]\s+(?=\d)", "-", normalized)
    normalized = re.sub(r"(?<=\d)\s+(?=\d)", " ", normalized)
    normalized = re.sub(r"[|]", "I", normalized)
    return normalized


# ── Risk and regulation helpers ───────────────────────────────────────────────

def calculate_risk_level(entities: Iterable[Dict[str, Any]]) -> str:
    scores = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    entity_list = list(entities)
    if not entity_list:
        return "LOW"
    high_count = sum(1 for e in entity_list if e.get("risk_level") in {"HIGH", "CRITICAL"})
    max_score = max(scores.get(e.get("risk_level", "LOW"), 1) for e in entity_list)
    if max_score >= 4 or high_count >= 3:
        return "CRITICAL"
    if max_score >= 3:
        return "HIGH"
    if max_score == 2:
        return "MEDIUM"
    return "LOW"


def get_regulation_impact(entities: Iterable[Dict[str, Any]]) -> List[str]:
    """Return sorted list of applicable data-protection regulations for detected entities."""
    regs: set = set()
    for entity in entities:
        regs.update(REGULATION_IMPACT.get(entity.get("type", ""), []))
    return sorted(regs)


# ── Checksum validators ───────────────────────────────────────────────────────

def _luhn_valid(value: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", value)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _aba_valid(routing: str) -> bool:
    """Validate ABA routing number via the standard mod-10 checksum."""
    digits = [int(c) for c in re.sub(r"\D", "", routing)]
    if len(digits) != 9:
        return False
    return (
        3 * (digits[0] + digits[3] + digits[6])
        + 7 * (digits[1] + digits[4] + digits[7])
        + (digits[2] + digits[5] + digits[8])
    ) % 10 == 0


# ── Entity construction ───────────────────────────────────────────────────────

def _add_structured_entity(
    entities: List[Dict[str, Any]],
    seen: set,
    text: str,
    entity_type: str,
    start: int,
    end: int,
    score: float,
    method: str,
    raw_value: Optional[str] = None,
    doc_level: bool = False,
    evidence: Optional[List[str]] = None,
) -> None:
    value = (raw_value if raw_value is not None else text[start:end]).strip()
    if not value:
        return
    info = SENSITIVE_TYPES.get(
        entity_type,
        SensitiveType(
            entity_type,
            entity_type.replace("_", " ").title(),
            "MEDIUM",
            "Sensitive data",
            "Review and protect if needed.",
        ),
    )
    key = (entity_type, value.lower())
    if key in seen:
        return
    seen.add(key)

    entity: Dict[str, Any] = {
        "type": entity_type,
        "display_name": info.display_name,
        "value": mask_value(value, entity_type) if not doc_level else value,
        "raw_value": value,
        "confidence": round(score, 3),
        "risk_level": info.risk_level,
        "start": start,
        "end": end,
        "description": info.description,
        "recommendation": info.recommendation,
        "detection_method": method,
        "safeguard_options": [
            {"method": "blur",         "description": "Gaussian blur over the region"},
            {"method": "redact",       "description": "Black-box redaction"},
            {"method": "pixelate",     "description": "Pixelation effect"},
            {"method": "full_encrypt", "description": "Encrypt the retained value"},
        ],
    }
    if doc_level:
        entity["doc_level"] = True
    if evidence:
        entity["evidence"] = evidence
    entities.append(entity)


def make_document_entity(doc_type: str, confidence: float, evidence: List[str]) -> Dict[str, Any]:
    """Create a document-level sensitive finding (e.g. from visual heuristic)."""
    info = SENSITIVE_TYPES[doc_type]
    return {
        "type": doc_type,
        "display_name": info.display_name,
        "value": info.display_name,
        "raw_value": info.display_name,
        "confidence": round(confidence, 3),
        "risk_level": info.risk_level,
        "start": 0,
        "end": 0,
        "description": info.description,
        "recommendation": info.recommendation,
        "detection_method": "document-classifier",
        "doc_level": True,
        "evidence": evidence,
        "safeguard_options": [
            {"method": "blur",     "description": "Blur the whole sensitive document image"},
            {"method": "redact",   "description": "Block sensitive document content"},
            {"method": "pixelate", "description": "Pixelate the document area"},
        ],
    }


# ── Document-level classifier ─────────────────────────────────────────────────

def classify_sensitive_document(text: str) -> List[Dict[str, Any]]:
    """
    Classify whether text appears to originate from a sensitive document type.
    Returns a confidence-sorted list of matching document classifications.
    """
    normalized = normalize_ocr_text(text)
    lowered = normalized.lower()
    classifications = []

    def keyword_hits(doc_type: str) -> List[str]:
        return [kw for kw in DOCUMENT_KEYWORDS[doc_type]["keywords"] if kw in lowered]

    STRONG_KEYWORDS = {
        "social security", "social security number", "social security administration",
        "passport", "driver license", "driver's license", "drivers license",
        "birth certificate", "certificate of birth", "certificate of live birth",
        "health insurance", "insurance card",
        "medical record", "bank statement", "account statement", "statement of account",
        "browser history", "browsing history", "search history",
        "student id", "student identification",
        "debit card", "credentials",
    }

    for doc_type, config in DOCUMENT_KEYWORDS.items():
        evidence: List[str] = []
        hits = keyword_hits(doc_type)
        evidence.extend([f'keyword "{hit}"' for hit in hits[:5]])
        is_strong_pattern = False

        if doc_type == "CREDIT_CARD_DOCUMENT":
            card_candidates = list(REGEX_PATTERNS["CREDIT_CARD"].finditer(normalized))
            has_card_number = any(_luhn_valid(m.group(0)) for m in card_candidates)
            has_loose = any(
                13 <= len(re.sub(r"\D", "", m.group(0))) <= 19 for m in card_candidates
            )
            if has_card_number:
                evidence.append("Luhn-valid 13-19 digit card number")
            elif has_loose:
                evidence.append("13-19 digit card-like number")
            if FIELD_PATTERNS["CARD_EXPIRATION"].search(normalized):
                evidence.append("expiration date pattern")
            if FIELD_PATTERNS["CARD_CVV"].search(normalized):
                evidence.append("CVV/CVC pattern")
            if any(brand in lowered for brand in PAYMENT_CARD_BRANDS):
                evidence.append("payment card brand or bank name")

        elif doc_type == "DEBIT_CARD_DOCUMENT":
            card_candidates = list(REGEX_PATTERNS["CREDIT_CARD"].finditer(normalized))
            if any(_luhn_valid(m.group(0)) for m in card_candidates):
                evidence.append("Luhn-valid card number")
            if FIELD_PATTERNS["CARD_EXPIRATION"].search(normalized):
                evidence.append("expiration date pattern")
            if any(brand in lowered for brand in PAYMENT_CARD_BRANDS):
                evidence.append("card network or bank name")

        elif doc_type == "SSN_DOCUMENT":
            if REGEX_PATTERNS["US_SSN"].search(normalized):
                evidence.append("SSN pattern xxx-xx-xxxx")
                is_strong_pattern = True
            elif re.search(r"\b(?!000|666|9\d{2})\d{9}\b", normalized):
                evidence.append("9-digit number (possible SSN without separators)")
            if re.search(r"\baccount\b", lowered):
                evidence.append('keyword "account"')

        elif doc_type == "PASSPORT_DOCUMENT":
            if FIELD_PATTERNS["PASSPORT_NUMBER"].search(normalized):
                evidence.append("passport-number-like identifier")
            if "nationality" in lowered or "citizenship" in lowered:
                evidence.append("nationality/citizenship field")

        elif doc_type == "DRIVER_LICENSE_DOCUMENT":
            if FIELD_PATTERNS["DRIVER_LICENSE_NUMBER"].search(normalized):
                evidence.append("driver-license-number-like identifier")
            if FIELD_PATTERNS["DATE_OF_BIRTH"].search(normalized):
                evidence.append("date of birth field")

        elif doc_type == "STUDENT_ID_DOCUMENT":
            if re.search(
                r"\b(?:student\s*(?:id|identification|number|no|#)|campus\s*id)\s*[:#-]?\s*[A-Z0-9-]{4,15}\b",
                normalized, re.IGNORECASE,
            ):
                evidence.append("student ID number pattern")
                is_strong_pattern = True
            if re.search(r"\b(?:university|college|institute|polytechnic|academy)\b", lowered):
                evidence.append("educational institution")
            if re.search(r"\b(?:enrollment|enrolled|semester|gpa|grade\s+point|matric)\b", lowered):
                evidence.append("academic field")

        elif doc_type == "BIRTH_CERTIFICATE_DOCUMENT":
            if re.search(
                r"\bcertificate\s*(?:no|number|#)?\s*[:#]?\s*[A-Z0-9-]{4,15}\b",
                normalized, re.IGNORECASE,
            ):
                evidence.append("certificate number pattern")
            if re.search(r"\bregistrar\b", normalized, re.IGNORECASE):
                evidence.append("registrar field")
            if FIELD_PATTERNS["DATE_OF_BIRTH"].search(normalized):
                evidence.append("date of birth field")

        elif doc_type == "HEALTH_INSURANCE_DOCUMENT":
            if re.search(
                r"\bmember\s*(?:id|#)\s*[:#]?\s*[A-Z0-9-]{4,15}\b",
                normalized, re.IGNORECASE,
            ):
                evidence.append("member ID pattern")
            if re.search(r"\brx\s*(?:bin|pcn)\s*[:#]?\s*\d{4,8}\b", normalized, re.IGNORECASE):
                evidence.append("pharmacy benefit ID (RxBIN/RxPCN)")
            if re.search(
                r"\bgroup\s*(?:no|number|#)?\s*[:#]?\s*[A-Z0-9-]{4,15}\b",
                normalized, re.IGNORECASE,
            ):
                evidence.append("group number pattern")

        elif doc_type == "MEDICAL_RECORD_DOCUMENT":
            if re.search(
                r"\b(?:mrn|medical\s+record\s+(?:no|number|#))\s*[:#]?\s*[A-Z0-9-]{4,15}\b",
                normalized, re.IGNORECASE,
            ):
                evidence.append("medical record number (MRN)")
            if re.search(r"\bicd[\s-]?(?:10|11|9)?\s*[:#]?\s*[A-Z]\d{2,3}", normalized, re.IGNORECASE):
                evidence.append("ICD diagnosis code")
            if FIELD_PATTERNS["DATE_OF_BIRTH"].search(normalized):
                evidence.append("date of birth field")

        elif doc_type == "BANK_STATEMENT_DOCUMENT":
            rn_match = re.search(
                r"(?:routing|aba|rtn)\s*(?:number|no|#)?\s*[:#-]?\s*(\d{9})\b",
                normalized, re.IGNORECASE,
            )
            if rn_match:
                if _aba_valid(rn_match.group(1)):
                    evidence.append("valid ABA routing number")
                    is_strong_pattern = True
                else:
                    evidence.append("9-digit routing-like number")
            if re.search(
                r"\baccount\s*(?:number|no|#)?\s*[:#-]?\s*[X*\d]{4,17}\b",
                normalized, re.IGNORECASE,
            ):
                evidence.append("account number pattern")
            if re.search(
                r"\b(?:opening|closing|available|current|beginning|ending)\s+balance\b",
                normalized, re.IGNORECASE,
            ):
                evidence.append("balance field")
            if re.search(
                r"\b(?:deposit|withdrawal)\s+\$?[\d,]+\.\d{2}\b",
                normalized, re.IGNORECASE,
            ):
                evidence.append("transaction amounts")

        elif doc_type == "CREDENTIALS_DOCUMENT":
            if REGEX_PATTERNS["PASSWORD"].search(normalized):
                evidence.append("password field detected")
                is_strong_pattern = True
            if re.search(
                r"\b(?:username|user\s*(?:id|name)|login(?:\s*id)?)\s*[:#=]\s*\S+",
                normalized, re.IGNORECASE,
            ):
                evidence.append("username field detected")
            if re.search(
                r"\b(?:api[_\s]?key|access[_\s]?token|secret[_\s]?key|auth(?:entication)?\s+token|bearer)\b",
                lowered,
            ):
                evidence.append("API credential keyword")
                is_strong_pattern = True

        elif doc_type == "BROWSER_HISTORY_DOCUMENT":
            url_count = len(re.findall(r"https?://[^\s]{4,}", normalized))
            if url_count >= 5:
                evidence.append(f"{url_count} URLs detected")
            elif url_count >= 2:
                evidence.append(f"{url_count} URL patterns detected")

        score = min(0.98, 0.35 + 0.13 * len(evidence))
        strong_keyword = any(hit in STRONG_KEYWORDS for hit in hits)

        if len(evidence) >= 2 or strong_keyword or is_strong_pattern:
            classifications.append({
                "type": doc_type,
                "display_name": config["display_name"],
                "confidence": round(score, 3),
                "risk_level": SENSITIVE_TYPES[doc_type].risk_level,
                "evidence": evidence,
            })

    classifications.sort(key=lambda item: item["confidence"], reverse=True)

    # Debit card is more specific — suppress generic credit card detection when confirmed
    types_found = {c["type"] for c in classifications}
    if "DEBIT_CARD_DOCUMENT" in types_found:
        classifications = [c for c in classifications if c["type"] != "CREDIT_CARD_DOCUMENT"]

    return classifications


# ── Full text analyzer ────────────────────────────────────────────────────────

def analyze_sensitive_text(
    text: str, presidio_analyzer: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """
    Analyze text for all PII and sensitive data.
    Runs document-level classification first, then field-level patterns and Presidio.
    """
    text = normalize_ocr_text(text)
    entities: List[Dict[str, Any]] = []
    seen: set = set()

    def add_entity(entity_type: str, start: int, end: int, score: float, method: str) -> None:
        value = text[start:end].strip()
        if not value:
            return
        if entity_type == "CREDIT_CARD" and not _luhn_valid(value):
            window = text[max(0, start - 80): min(len(text), end + 80)].lower()
            has_card_ctx = any(
                kw in window for kw in DOCUMENT_KEYWORDS["CREDIT_CARD_DOCUMENT"]["keywords"]
            )
            if not has_card_ctx:
                return
            score = min(score, 0.72)
        _add_structured_entity(entities, seen, text, entity_type, start, end, score, method)

    def add_field_entity(
        field_name: str, entity_type: str, match: re.Match, score: float
    ) -> None:
        raw_value = match.group(0)
        if field_name == "CARD_EXPIRATION":
            window = text[max(0, match.start() - 80): min(len(text), match.end() + 80)].lower()
            has_exp_label = re.search(
                r"\b(?:exp(?:ires|iration)?|valid\s+thru|good\s+thru)\b",
                match.group(0), re.IGNORECASE,
            )
            has_card_ctx = any(
                kw in window for kw in DOCUMENT_KEYWORDS["CREDIT_CARD_DOCUMENT"]["keywords"]
            )
            if not has_exp_label and not has_card_ctx:
                return
            raw_value = f"{match.group(1)}/{match.group(2)}"
        elif field_name == "CARD_CVV":
            digits = re.findall(r"\d{3,4}", match.group(0))
            raw_value = digits[-1] if digits else match.group(0)
        elif field_name == "CARDHOLDER_NAME":
            window = text[max(0, match.start() - 80): min(len(text), match.end() + 80)].lower()
            if not any(kw in window for kw in DOCUMENT_KEYWORDS["CREDIT_CARD_DOCUMENT"]["keywords"]):
                return
            raw_value = re.sub(
                r"^(?:card\s*holder|cardholder|name)\s*[:#-]?\s*", "", match.group(0),
                flags=re.IGNORECASE,
            ).strip()
            raw_value = re.split(
                r"\b(?:cvv|cvc|cid|valid|good\s+thru|exp(?:ires|iration)?)\b",
                raw_value, flags=re.IGNORECASE,
            )[0].strip()
            name_tokens = re.findall(r"[A-Z][A-Z.'-]+", raw_value, flags=re.IGNORECASE)
            if len(name_tokens) >= 2:
                raw_value = " ".join(name_tokens[:4])
        elif field_name == "DRIVER_LICENSE_NUMBER":
            tokens = re.findall(r"[A-Z0-9-]{5,18}", match.group(0), flags=re.IGNORECASE)
            raw_value = tokens[-1] if tokens else match.group(0)
        elif field_name == "PASSPORT_NUMBER":
            window = text[max(0, match.start() - 50): min(len(text), match.end() + 50)].lower()
            if "passport" not in window:
                return
            tokens = re.findall(r"[A-Z][0-9]{7,9}", match.group(0), flags=re.IGNORECASE)
            raw_value = tokens[-1] if tokens else match.group(0)
        elif field_name == "DATE_OF_BIRTH":
            dates = re.findall(r"\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}", match.group(0))
            raw_value = dates[-1] if dates else match.group(0)

        _add_structured_entity(
            entities, seen, text, entity_type,
            match.start(), match.end(), score, "field-pattern", raw_value=raw_value,
        )

    # 1. Document-level classification
    for doc_cls in classify_sensitive_document(text):
        _add_structured_entity(
            entities, seen, text,
            doc_cls["type"], 0, 0, doc_cls["confidence"],
            "document-classifier",
            raw_value=doc_cls["display_name"],
            doc_level=True,
            evidence=doc_cls.get("evidence", []),
        )

    # 2. Field-level pattern matching
    field_entity_map = {
        "CARD_EXPIRATION":       ("CARD_EXPIRATION",   0.78),
        "CARD_CVV":              ("CARD_SECURITY_CODE", 0.76),
        "CARDHOLDER_NAME":       ("PERSON",             0.70),
        "DRIVER_LICENSE_NUMBER": ("US_DRIVER_LICENSE",  0.82),
        "PASSPORT_NUMBER":       ("US_PASSPORT",        0.84),
        "DATE_OF_BIRTH":         ("DATE_TIME",          0.72),
    }
    for field_name, pattern in FIELD_PATTERNS.items():
        entity_type, score = field_entity_map[field_name]
        for match in pattern.finditer(text):
            add_field_entity(field_name, entity_type, match, score)

    # 3. Payment card brand evidence (even when card number is embossed/unreadable)
    for brand in PAYMENT_CARD_BRANDS:
        match = re.search(rf"\b{re.escape(brand)}\b", text, re.IGNORECASE)
        if match:
            _add_structured_entity(
                entities, seen, text,
                "CREDIT_CARD_DOCUMENT", match.start(), match.end(),
                0.70, "card-brand",
                raw_value=brand.title(), doc_level=True,
            )

    # 4. Credential detection (password and username)
    for match in REGEX_PATTERNS["PASSWORD"].finditer(text):
        raw = match.group(1) if match.lastindex and match.group(1) else match.group(0)
        _add_structured_entity(
            entities, seen, text, "PASSWORD",
            match.start(), match.end(), 0.95, "credential-pattern", raw_value=raw,
        )

    for match in REGEX_PATTERNS["USERNAME"].finditer(text):
        raw = next((g for g in match.groups() if g), match.group(0))
        _add_structured_entity(
            entities, seen, text, "USERNAME",
            match.start(), match.end(), 0.82, "credential-pattern", raw_value=raw,
        )

    # 5. Routing number detection with ABA checksum validation
    for match in REGEX_PATTERNS["US_ROUTING_NUMBER"].finditer(text):
        routing = match.group(1) if match.lastindex and match.group(1) else re.sub(r"\D", "", match.group(0))[-9:]
        if _aba_valid(routing):
            _add_structured_entity(
                entities, seen, text, "US_ROUTING_NUMBER",
                match.start(), match.end(), 0.91, "regex", raw_value=routing,
            )

    # 6. Presidio NLP-based analysis
    if presidio_analyzer:
        try:
            for result in presidio_analyzer.analyze(
                text=text, language="en", score_threshold=0.45
            ):
                mapped = "IBAN_CODE" if result.entity_type == "IBAN" else result.entity_type
                if mapped in SENSITIVE_TYPES:
                    add_entity(mapped, result.start, result.end, result.score, "presidio")
        except Exception:
            pass

    # 7. Regex sweeps for remaining field types
    for entity_type, pattern in REGEX_PATTERNS.items():
        if entity_type in {"US_ROUTING_NUMBER", "PASSWORD", "USERNAME"}:
            continue  # handled above
        for match in pattern.finditer(text):
            add_entity(entity_type, match.start(), match.end(), 0.90, "regex")

    # Remove shorter spans fully subsumed by a wider span of the same type.
    entities = _deduplicate_overlapping_entities(entities)
    # Cap entity counts per type based on the detected document type.
    entities = _apply_document_field_limits(entities)
    entities.sort(key=lambda item: (item["start"], item["end"], item["type"]))
    return entities


def _deduplicate_overlapping_entities(
    entities: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    For each entity type, drop any span that is fully contained within a longer
    span of the same type.  Doc-level entities (start == end == 0) are kept as-is.
    """
    positioned = [e for e in entities if e.get("start", 0) < e.get("end", 0)]
    unpositioned = [e for e in entities if e.get("start", 0) >= e.get("end", 0)]

    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for e in positioned:
        by_type.setdefault(e["type"], []).append(e)

    kept: List[Dict[str, Any]] = []
    for group in by_type.values():
        # Wider spans first; among equal widths, higher confidence wins
        group.sort(key=lambda e: (-(e["end"] - e["start"]), -e.get("confidence", 0)))
        accepted: List[Dict[str, Any]] = []
        for entity in group:
            s, e_ = entity["start"], entity["end"]
            # Skip if fully contained within any already-accepted span
            if any(s >= a["start"] and e_ <= a["end"] for a in accepted):
                continue
            accepted.append(entity)
        kept.extend(accepted)

    return kept + unpositioned


def _apply_document_field_limits(
    entities: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Cap field-level entity counts based on what is realistically present in the
    detected document type.  E.g., a driver's license has exactly one person name,
    not fifteen.  HIGH/CRITICAL field types are always kept (at most 1) even when
    not listed for the detected document type, as a safety-first fallback.
    """
    doc_entities = [e for e in entities if e.get('doc_level')]
    field_entities = [e for e in entities if not e.get('doc_level')]

    if not doc_entities or not field_entities:
        return entities

    # Pick the highest-confidence document type that has known limits
    best_doc_type: Optional[str] = None
    best_conf = 0.0
    for de in doc_entities:
        t = de.get('type', '')
        c = de.get('confidence', 0.0)
        if t in DOCUMENT_FIELD_LIMITS and c > best_conf:
            best_doc_type = t
            best_conf = c

    if best_doc_type is None:
        return entities

    limits = DOCUMENT_FIELD_LIMITS[best_doc_type]

    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for e in field_entities:
        by_type.setdefault(e['type'], []).append(e)

    filtered: List[Dict[str, Any]] = []
    for etype, group in by_type.items():
        limit = limits.get(etype)
        group_sorted = sorted(group, key=lambda e: -e.get('confidence', 0))
        if limit is not None:
            filtered.extend(group_sorted[:limit])
        else:
            # Not listed for this doc type — keep only if HIGH or CRITICAL risk
            info = SENSITIVE_TYPES.get(etype)
            if info and info.risk_level in {'HIGH', 'CRITICAL'}:
                filtered.append(group_sorted[0])

    return doc_entities + filtered


def public_entities(entities: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return entities safe for API responses (strips raw_value)."""
    cleaned = []
    for entity in entities:
        item = dict(entity)
        item.pop("raw_value", None)
        cleaned.append(item)
    return cleaned
