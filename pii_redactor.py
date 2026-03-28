"""
PII Redaction Engine - Blur, mask, and remove sensitive information from images and documents
"""

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFilter
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import re


class PIIRedactor:
    """Redact PII from images and documents"""
    
    def __init__(self):
        self.blur_kernel = (89, 89)  # Large blur for sensitive areas
        self.min_confidence = 0.5
        
    def redact_image_from_threats(self, image_path: str, threats: List[Dict], output_path: str) -> str:
        """
        Redact image based on detected threats
        
        Args:
            image_path: Path to original image
            threats: List of threat dicts with 'type', 'location', 'risk'
            output_path: Path to save protected image
            
        Returns:
            Path to redacted image
        """
        try:
            img = Image.open(image_path).convert('RGB')
            img_array = np.array(img)
            
            # Convert to OpenCV format (BGR)
            img_cv = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
            
            # Apply aggressive redaction based on threat types
            for threat in threats:
                threat_type = threat.get('type', '').lower()
                location = threat.get('location', '').lower()
                risk = threat.get('risk', 'Medium').lower()
                
                # Aggressive redaction for high-risk items
                if 'high' in risk:
                    img_cv = self._apply_aggressive_redaction(img_cv, threat_type, location)
                else:
                    img_cv = self._apply_moderate_redaction(img_cv, threat_type, location)
            
            # Additional security: Apply edge detection to find text regions and blur
            img_cv = self._blur_text_regions(img_cv)
            
            # Convert back to PIL and save
            img_rgb = cv2.cvtColor(img_cv, cv2.COLOR_BGR2RGB)
            protected_img = Image.fromarray(img_rgb)
            protected_img.save(output_path, quality=95)
            
            return output_path
            
        except Exception as e:
            print(f"Error redacting image: {e}")
            # Fallback: return original path
            return image_path
    
    def _apply_aggressive_redaction(self, img: np.ndarray, threat_type: str, location: str) -> np.ndarray:
        """Apply aggressive redaction (solid black or heavy blur) for high-risk threats"""
        
        h, w = img.shape[:2]
        
        # Face/biometric detection - redact entire regions
        if any(x in threat_type for x in ['face', 'eye', 'fingerprint', 'iris', 'biometric']):
            # Apply multiple passes of heavy blur + pixelation
            img = cv2.GaussianBlur(img, self.blur_kernel, 0)
            # Also apply median blur for extra obscuration
            img = cv2.medianBlur(img, 51)
            # Pixelate
            img = self._pixelate(img, pixel_size=15)
            
        # Document numbers - black out large regions
        elif any(x in threat_type for x in ['passport', 'id', 'license', 'ssn', 'social security']):
            # Draw large black rectangles over document areas
            cv2.rectangle(img, (0, 0), (w, h), (0, 0, 0), -1)  # Black out
            
        # Card numbers, account numbers - heavy obfuscation
        elif any(x in threat_type for x in ['card', 'account', 'credit', 'debit', 'bank']):
            img = cv2.GaussianBlur(img, self.blur_kernel, 0)
            img = cv2.medianBlur(img, 41)
            img = self._pixelate(img, pixel_size=20)
            
        # Generic high-risk - multiple blur passes
        else:
            img = cv2.GaussianBlur(img, self.blur_kernel, 0)
            img = cv2.blur(img, (81, 81))
            
        return img
    
    def _apply_moderate_redaction(self, img: np.ndarray, threat_type: str, location: str) -> np.ndarray:
        """Apply moderate redaction for medium-risk threats"""
        
        # Apply strong blur for medium-risk items
        img = cv2.GaussianBlur(img, (71, 71), 0)
        img = cv2.medianBlur(img, 31)
        img = self._pixelate(img, pixel_size=10)
        
        return img
    
    def _pixelate(self, img: np.ndarray, pixel_size: int = 10) -> np.ndarray:
        """Apply pixelation effect to obscure details"""
        h, w = img.shape[:2]
        
        # Resize down then back up to create pixelation
        temp = cv2.resize(img, (w // pixel_size, h // pixel_size), interpolation=cv2.INTER_LINEAR)
        pixelated = cv2.resize(temp, (w, h), interpolation=cv2.INTER_NEAREST)
        
        return pixelated
    
    def _blur_text_regions(self, img: np.ndarray, blur_strength: int = 51) -> np.ndarray:
        """Automatically detect and blur text regions"""
        try:
            # Convert to grayscale
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # Use Canny edge detection to find text
            _, binary = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
            
            # Find contours
            contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            # Blur regions with text-like contours
            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                
                # Only blur if region is reasonable size (text-like)
                if 5 < w < img.shape[1] // 2 and 5 < h < img.shape[0] // 2:
                    roi = img[y:y+h, x:x+w]
                    blurred = cv2.GaussianBlur(roi, (blur_strength, blur_strength), 0)
                    img[y:y+h, x:x+w] = blurred
                    
        except Exception as e:
            print(f"Text region detection error: {e}")
        
        return img
    
    def redact_document_text(self, content: str, threats: List[Dict]) -> Tuple[str, List[str]]:
        """
        Redact sensitive text from document content
        
        Args:
            content: Text content from document
            threats: List of detected threats
            
        Returns:
            Tuple of (redacted_content, redaction_summary)
        """
        redacted_content = content
        redaction_summary = []
        
        # Build patterns to match for redaction
        patterns = {
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'phone': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'credit_card': r'\b(?:\d[ -]*?){13,19}\b',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'date': r'\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:\d{4}|\d{2})\b',
        }
        
        # Redact each pattern
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                # Replace matches with [REDACTED]
                redacted_content = re.sub(pattern, '[REDACTED]', redacted_content)
                redaction_summary.append(f"{pattern_name}: {len(matches)} instance(s) redacted")
        
        # Also redact based on detected threats
        for threat in threats:
            threat_type = threat.get('type', '').lower()
            
            # Redact threat-specific patterns
            if 'name' in threat_type:
                # Remove capitalized words that look like names
                redacted_content = re.sub(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b', '[NAME]', redacted_content)
                redaction_summary.append(f"names: redacted")
                
            elif 'address' in threat_type:
                # Remove lines with address-like patterns
                lines = redacted_content.split('\n')
                new_lines = []
                for line in lines:
                    if not re.search(r'\d+\s+[A-Za-z]+\s+(?:St|Ave|Rd|Lane|Street|Avenue|Road)', line):
                        new_lines.append(line)
                    else:
                        new_lines.append('[ADDRESS REDACTED]')
                redacted_content = '\n'.join(new_lines)
                redaction_summary.append(f"addresses: redacted")
        
        return redacted_content, redaction_summary
    
    def create_protected_document(self, 
                                 original_path: str, 
                                 threats: List[Dict],
                                 output_path: str,
                                 file_type: str) -> str:
        """
        Create a protected version of a document
        
        Args:
            original_path: Path to original document
            threats: List of detected threats
            output_path: Where to save protected version
            file_type: 'pdf', 'word', 'image'
            
        Returns:
            Path to protected document
        """
        try:
            from docx import Document
            from docx.shared import Pt, RGBColor
            
            if file_type == 'word':
                # Open original document
                doc = Document(original_path)
                
                # Redact all paragraphs
                for para in doc.paragraphs:
                    if para.text.strip():
                        redacted_text, _ = self.redact_document_text(para.text, threats)
                        # Clear original and set redacted
                        para.clear()
                        para.add_run(redacted_text)
                        
                        # Style redacted text
                        for run in para.runs:
                            run.font.color.rgb = RGBColor(100, 100, 100)  # Gray color
                
                # Save protected version
                doc.save(output_path)
                return output_path
                
            elif file_type in ['image', 'pdf']:
                # For images and PDFs, use image redaction
                return self.redact_image_from_threats(original_path, threats, output_path)
            else:
                return original_path
                
        except Exception as e:
            print(f"Error creating protected document: {e}")
            return original_path
    
    def blend_redaction(self, original: np.ndarray, redacted: np.ndarray, 
                       alpha: float = 0.7) -> np.ndarray:
        """
        Blend original and redacted versions for additional obfuscation
        
        Args:
            original: Original image array
            redacted: Redacted image array
            alpha: Blend ratio (higher = more redacted)
            
        Returns:
            Blended image array
        """
        if original.shape != redacted.shape:
            return redacted
        
        blended = cv2.addWeighted(original, 1 - alpha, redacted, alpha, 0)
        return blended
