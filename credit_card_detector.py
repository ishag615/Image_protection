"""
Credit Card Detection and Analysis Module
Detects credit cards in images and identifies sensitive fields
Supports VISA, MASTERCARD, AMEX, DISCOVER card detection
"""

import re
from typing import Dict, List, Any, Tuple
import logging
from PIL import Image
import pytesseract
import cv2
import numpy as np

logger = logging.getLogger(__name__)


class CreditCardDetector:
    """
    Specialized detector for credit cards in images
    Identifies card details: number, CVV, name, expiration, bank
    
    Detects:
    - 16-digit card numbers (with/without spaces/dashes)
    - CVV/CVC codes (3-4 digits)
    - Expiration dates (MM/YY, MM-YY format)
    - Cardholder names
    - Bank/Issuer names
    """
    
    def __init__(self):
        """Initialize credit card detector with patterns and rules"""
        self.patterns = {
            # 16-digit card number (with or without spaces/dashes)
            'card_number': re.compile(r'\b(\d{4}[\s\-]?){3}\d{4}\b'),
            # CVV: 3-4 digits, usually on back (often isolated)
            'cvv': re.compile(r'\b(?:CVV|CVC|CID|CARD SECURITY CODE)\s*[:=]?\s*(\d{3,4})\b', re.IGNORECASE),
            # Expiration: MM/YY or MM-YY format
            'expiration': re.compile(r'\b(0[1-9]|1[0-2])[/\-](2[0-9]|9[0-9])\b'),
            # Cardholder name: usually 2-4 words, all caps or proper case
            'cardholder': re.compile(r'^[A-Z][A-Z\s]{3,30}$', re.MULTILINE),
            # Bank/Issuer keywords
            'bank': re.compile(
                r'\b(VISA|MASTERCARD|AMERICAN EXPRESS|AMEX|DISCOVER|DINERS|JCB|'
                r'CITIBANK|CHASE|BOFA|WELLS FARGO|CAPITAL ONE|HSBC|BANK OF AMERICA)\b',
                re.IGNORECASE
            )
        }
        
        # Known card patterns for validation
        self.card_issuers = {
            'VISA': r'^4',  # Starts with 4
            'MASTERCARD': r'^(5[1-5]|2[2-7])',  # Starts with 51-55 or 22-27
            'AMEX': r'^3[47]',  # Starts with 34 or 37
            'DISCOVER': r'^6(?:011|5)',  # Starts with 6011 or 65
        }
        
        logger.info("✓ Credit Card Detector initialized")
    
    def is_credit_card_image(self, image_path: str) -> Dict[str, Any]:
        """
        Determine if image is a credit card
        
        Args:
            image_path: Path to image file
            
        Returns:
            {
                'is_credit_card': bool,
                'confidence': float (0-1),
                'detected_fields': {
                    'card_number': { 'value': str, 'confidence': float, ... },
                    'cvv': { 'value': str, 'confidence': float, ... },
                    'expiration': { 'value': str, 'confidence': float, ... },
                    'cardholder': { 'value': str, 'confidence': float, ... },
                    'bank': { 'value': str, 'confidence': float, ... }
                },
                'card_type': str (VISA, MASTERCARD, AMEX, DISCOVER, UNKNOWN),
                'risk_level': str (CRITICAL for card)
            }
        """
        try:
            # Extract text from image
            extracted_text = self._extract_text(image_path)
            
            if not extracted_text.strip():
                return {
                    'is_credit_card': False,
                    'confidence': 0.0,
                    'detected_fields': {},
                    'card_type': 'UNKNOWN',
                    'risk_level': 'LOW'
                }
            
            # Detect credit card fields
            detected_fields = self._detect_card_fields(extracted_text, image_path)
            
            # Determine if image is a credit card
            is_card, confidence = self._is_card_decision(detected_fields)
            
            # Identify card type
            card_type = self._identify_card_type(detected_fields)
            
            return {
                'is_credit_card': is_card,
                'confidence': confidence,
                'detected_fields': detected_fields,
                'card_type': card_type,
                'risk_level': 'CRITICAL' if is_card else 'LOW',
                'extracted_text': extracted_text[:500] if extracted_text else ""  # First 500 chars for review
            }
        
        except Exception as e:
            logger.error(f"Error detecting credit card: {e}")
            return {
                'is_credit_card': False,
                'confidence': 0.0,
                'detected_fields': {},
                'card_type': 'UNKNOWN',
                'risk_level': 'UNKNOWN',
                'error': str(e)
            }
    
    def get_blur_regions(self, image_path: str, detected_fields: Dict) -> List[Dict[str, Any]]:
        """
        Get regions to blur for credit card
        
        Args:
            image_path: Path to image
            detected_fields: Detected card fields
            
        Returns:
            List of regions to blur with field information
        """
        try:
            regions = []
            
            # Map fields to blur regions
            blur_fields = ['card_number', 'cvv', 'expiration', 'cardholder']
            
            for field in blur_fields:
                if field in detected_fields and detected_fields[field]:
                    regions.append({
                        'field': field,
                        'description': self._get_field_description(field),
                        'positions': detected_fields[field].get('positions', []),
                        'blur_level': self._get_blur_level(field)
                    })
            
            return regions
        
        except Exception as e:
            logger.error(f"Error getting blur regions: {e}")
            return []
    
    def _extract_text(self, image_path: str) -> str:
        """Extract text from image using OCR with preprocessing"""
        try:
            img = Image.open(image_path)
            img_array = np.array(img)
            
            # Enhance image for OCR
            if len(img_array.shape) == 3:
                gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            else:
                gray = img_array
            
            # Apply preprocessing
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced = clahe.apply(gray)
            
            # Upscale for better recognition
            upscaled = cv2.resize(enhanced, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
            
            # Extract text
            text = pytesseract.image_to_string(upscaled)
            
            logger.info(f"Extracted {len(text)} characters from image")
            return text
        
        except Exception as e:
            logger.warning(f"Error extracting text: {e}")
            return ""
    
    def _detect_card_fields(self, text: str, image_path: str = None) -> Dict[str, Dict[str, Any]]:
        """Detect credit card fields in extracted text"""
        detected = {}
        
        # Detect card number
        card_match = self.patterns['card_number'].search(text)
        if card_match:
            card_num = card_match.group(0).replace(' ', '').replace('-', '')
            detected['card_number'] = {
                'value': card_num,
                'confidence': 0.9,  # Regex match = high confidence
                'raw_value': card_match.group(0),
                'positions': self._find_text_positions(text, card_match.group(0))
            }
        
        # Detect CVV
        cvv_match = self.patterns['cvv'].search(text)
        if cvv_match:
            detected['cvv'] = {
                'value': cvv_match.group(1),
                'confidence': 0.85,
                'raw_value': cvv_match.group(0),
                'positions': self._find_text_positions(text, cvv_match.group(0))
            }
        else:
            # Look for isolated 3-4 digit numbers that might be CVV
            cvv_isolated = re.findall(r'\b(\d{3,4})\b', text)
            if cvv_isolated:
                # Last 3-4 digit sequence is often CVV (back of card)
                detected['cvv'] = {
                    'value': cvv_isolated[-1],
                    'confidence': 0.5,  # Lower confidence for isolated numbers
                    'raw_value': cvv_isolated[-1],
                    'positions': self._find_text_positions(text, cvv_isolated[-1])
                }
        
        # Detect expiration date
        exp_match = self.patterns['expiration'].search(text)
        if exp_match:
            detected['expiration'] = {
                'value': exp_match.group(0),
                'confidence': 0.85,
                'raw_value': exp_match.group(0),
                'positions': self._find_text_positions(text, exp_match.group(0))
            }
        
        # Detect cardholder name
        # Look for proper case or all caps, 2-4 word names
        name_candidates = re.findall(
            r'\b([A-Z][a-z]+ [A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b',
            text
        )
        if name_candidates:
            # Pick the longest name (usually cardholder)
            name = max(name_candidates, key=len)
            detected['cardholder'] = {
                'value': name,
                'confidence': 0.75,  # Name patterns have lower confidence
                'raw_value': name,
                'positions': self._find_text_positions(text, name)
            }
        
        # Detect bank/issuer
        bank_match = self.patterns['bank'].search(text)
        if bank_match:
            detected['bank'] = {
                'value': bank_match.group(0),
                'confidence': 0.95,
                'raw_value': bank_match.group(0),
                'positions': self._find_text_positions(text, bank_match.group(0))
            }
        
        return detected
    
    def _find_text_positions(self, text: str, search_text: str) -> List[Dict[str, Any]]:
        """
        Find positions of text in the original text
        Returns character offsets which can be mapped to image coordinates
        """
        positions = []
        start = 0
        while True:
            pos = text.find(search_text, start)
            if pos == -1:
                break
            positions.append({
                'start': pos,
                'end': pos + len(search_text),
                'text': search_text
            })
            start = pos + 1
        
        return positions if positions else [{'start': 0, 'end': len(search_text)}]
    
    def _is_card_decision(self, detected_fields: Dict) -> Tuple[bool, float]:
        """
        Determine if image is a credit card based on detected fields
        
        Scoring:
        - Card number: 0.6 (highest indicator)
        - Expiration: 0.3 (strong indicator)
        - CVV: 0.15 (additional confirmation)
        - Cardholder: 0.15 (additional confirmation)
        - Bank: 0.1 (weak indicator)
        
        Threshold: 0.65 = likely a credit card
        
        Returns: (is_card: bool, confidence: float)
        """
        if not detected_fields:
            return False, 0.0
        
        # Score based on field detection
        score = 0.0
        
        # Card number: highest indicator
        if 'card_number' in detected_fields:
            score += 0.6
        
        # Expiration date: strong indicator
        if 'expiration' in detected_fields:
            score += 0.3
        
        # CVV or cardholder: additional confirmation
        if 'cvv' in detected_fields:
            score += 0.15
        
        if 'cardholder' in detected_fields:
            score += 0.15
        
        # Bank name: weak indicator
        if 'bank' in detected_fields:
            score += 0.1
        
        # Decision threshold
        is_card = score >= 0.65
        
        return is_card, min(score, 1.0)
    
    def _identify_card_type(self, detected_fields: Dict) -> str:
        """
        Identify card type based on card number
        Returns: 'VISA', 'MASTERCARD', 'AMEX', 'DISCOVER', or 'UNKNOWN'
        """
        if 'card_number' not in detected_fields:
            return 'UNKNOWN'
        
        card_num = detected_fields['card_number']['value']
        
        # Check against issuer patterns
        for issuer, pattern in self.card_issuers.items():
            if re.match(pattern, card_num):
                return issuer
        
        return 'UNKNOWN'
    
    def _get_field_description(self, field: str) -> str:
        """Get human-readable description of field"""
        descriptions = {
            'card_number': 'Card Number (16 digits)',
            'cvv': 'CVV/CVC (3-4 digits)',
            'expiration': 'Expiration Date (MM/YY)',
            'cardholder': 'Cardholder Name',
            'bank': 'Bank/Issuer Name'
        }
        return descriptions.get(field, field)
    
    def _get_blur_level(self, field: str) -> int:
        """
        Get blur intensity for each field (0-100)
        Higher = more aggressive blur
        """
        blur_levels = {
            'card_number': 100,    # Maximum blur for card number
            'cvv': 95,             # Maximum blur for CVV
            'expiration': 80,      # Strong blur for expiration
            'cardholder': 75       # Moderate blur for name
        }
        return blur_levels.get(field, 75)
    
    def validate_card_number(self, card_num: str) -> bool:
        """
        Validate card number using Luhn algorithm
        
        Args:
            card_num: Card number without spaces/dashes
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Remove any non-digit characters
            card_num = re.sub(r'\D', '', card_num)
            
            # Must be 13-19 digits (most are 16)
            if not (13 <= len(card_num) <= 19):
                return False
            
            # Luhn algorithm
            digits = [int(d) for d in card_num]
            checksum = 0
            
            # Process from right to left
            for i, digit in enumerate(reversed(digits)):
                if i % 2 == 1:  # Every second digit from right
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            
            return checksum % 10 == 0
        
        except Exception as e:
            logger.warning(f"Error validating card number: {e}")
            return False