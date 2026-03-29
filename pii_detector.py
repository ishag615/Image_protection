"""
Presidio-based PII Detection and Analysis
Replaces Gemini with Microsoft Presidio for more accurate PII detection
"""

from presidio_analyzer import AnalyzerEngine
import pytesseract
from PIL import Image
import cv2
import numpy as np
from typing import List, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class PresidioAnalyzer:
    """
    Enhanced PII detection using Microsoft Presidio and Tesseract OCR
    """
    
    def __init__(self):
        """Initialize Presidio Analyzer engine"""
        try:
            self.analyzer = AnalyzerEngine()
            logger.info("✓ Presidio engine initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing Presidio: {e}")
            raise
    
    def analyze_image(self, image_path: str) -> Dict[str, Any]:
        """
        Analyze image for PII by extracting text with Tesseract then analyzing
        
        Args:
            image_path: Path to image file
            
        Returns:
            Dictionary with detected entities, confidence scores, and recommendations
        """
        try:
            # Extract text from image using Tesseract
            extracted_text = self._extract_text_from_image(image_path)
            
            if not extracted_text.strip():
                return {
                    'success': True,
                    'text_extracted': '',
                    'entities': [],
                    'raw_analysis': 'No text found in image',
                    'risk_level': 'LOW'
                }
            
            # Analyze extracted text for PII
            entities = self.analyzer.analyze(
                text=extracted_text,
                language='en',
                score_threshold=0.35  # Lower threshold for higher sensitivity
            )
            
            # Convert to structured format
            structured_entities = self._structure_entities(entities, image_path)
            
            # Determine risk level
            risk_level = self._calculate_risk_level(structured_entities)
            
            return {
                'success': True,
                'text_extracted': extracted_text,
                'entities': structured_entities,
                'raw_analysis': f"Detected {len(structured_entities)} PII entities",
                'risk_level': risk_level,
                'entity_count': len(structured_entities)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing image {image_path}: {e}")
            return {
                'success': False,
                'error': str(e),
                'entities': [],
                'risk_level': 'UNKNOWN'
            }
    
    def analyze_text(self, text: str, document_context: str = '') -> Dict[str, Any]:
        """
        Analyze plain text for PII
        
        Args:
            text: Text content to analyze
            document_context: Optional context (e.g., document name) for better detection
            
        Returns:
            Dictionary with detected entities and recommendations
        """
        try:
            if document_context:
                text = f"{document_context}\n{text}"
            
            entities = self.analyzer.analyze(
                text=text,
                language='en',
                score_threshold=0.35
            )
            
            structured_entities = self._structure_entities(entities)
            risk_level = self._calculate_risk_level(structured_entities)
            
            return {
                'success': True,
                'text_analyzed': len(text),
                'entities': structured_entities,
                'risk_level': risk_level,
                'entity_count': len(structured_entities)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing text: {e}")
            return {
                'success': False,
                'error': str(e),
                'entities': [],
                'risk_level': 'UNKNOWN'
            }
    
    def _extract_text_from_image(self, image_path: str) -> str:
        """
        Extract text from image using Tesseract OCR
        
        Args:
            image_path: Path to image
            
        Returns:
            Extracted text
        """
        try:
            # Try with PIL first
            img = Image.open(image_path)
            
            # Enhance image for better OCR
            img_array = np.array(img)
            
            # Convert BGR to grayscale if needed
            if len(img_array.shape) == 3:
                gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            else:
                gray = img_array
            
            # Apply CLAHE (Contrast Limited Adaptive Histogram Equalization)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced = clahe.apply(gray)
            
            # Upscale for better recognition
            upscaled = cv2.resize(enhanced, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
            
            # Apply bilateral filter to denoise while preserving edges
            denoised = cv2.bilateralFilter(upscaled, 9, 75, 75)
            
            # Extract text using Tesseract
            text = pytesseract.image_to_string(denoised)
            
            logger.info(f"Extracted {len(text)} characters from image via OCR")
            return text
            
        except Exception as e:
            logger.warning(f"Error extracting text with Tesseract: {e}")
            return ""
    
    def _structure_entities(self, presidio_entities: List[Any], 
                           image_path: str = None) -> List[Dict[str, Any]]:
        """
        Convert Presidio entities to structured format with recommendations
        
        Args:
            presidio_entities: List of RecognizerResult objects from Presidio
            image_path: Optional path to source image
            
        Returns:
            List of structured entity dictionaries
        """
        structured = []
        
        for entity in presidio_entities:
            # Map Presidio entity types to human-readable names and risk levels
            entity_info = self._get_entity_info(entity.entity_type)
            
            structured_entity = {
                'type': entity.entity_type,
                'display_name': entity_info['display_name'],
                'value': entity.name if hasattr(entity, 'name') else 'Detected',
                'confidence': round(entity.score, 3),
                'risk_level': entity_info['risk_level'],
                'start': entity.start,
                'end': entity.end,
                'recommendations': entity_info['recommendations'],
                'safeguard_options': entity_info['safeguard_options']
            }
            
            structured.append(structured_entity)
        
        return structured
    
    def _get_entity_info(self, entity_type: str) -> Dict[str, Any]:
        """
        Get detailed information about an entity type including risk and safeguarding options
        
        Args:
            entity_type: The type of entity detected by Presidio
            
        Returns:
            Dictionary with display name, risk level, and recommendations
        """
        entity_map = {
            # HIGHEST RISK
            'PERSON': {
                'display_name': 'Person Name',
                'risk_level': 'HIGH',
                'recommendations': [
                    'This is a person\'s name. Consider removing or replacing with placeholder.',
                    'Could be used for identity theft or social engineering.'
                ],
                'safeguard_options': [
                    {'method': 'blur', 'description': 'Blur the text/area'},
                    {'method': 'redact', 'description': 'Full blackout redaction'},
                    {'method': 'replace', 'description': 'Replace with [NAME]'},
                    {'method': 'fpe_encrypt', 'description': 'Format-preserving encryption'}
                ]
            },
            'CREDIT_CARD': {
                'display_name': 'Credit Card Number',
                'risk_level': 'HIGH',
                'recommendations': [
                    'Credit card data detected. This is highly sensitive financial information.',
                    'Must be completely removed or encrypted. Never leave visible.',
                    'Recommend full encryption or complete redaction.'
                ],
                'safeguard_options': [
                    {'method': 'redact', 'description': 'Complete blackout (strongest)'},
                    {'method': 'full_encrypt', 'description': 'Full field encryption'},
                    {'method': 'replace', 'description': 'Replace with [REDACTED]'},
                    {'method': 'blur', 'description': 'Blur the area'}
                ]
            },
            'IBAN': {
                'display_name': 'IBAN Number',
                'risk_level': 'HIGH',
                'recommendations': [
                    'Bank account IBAN detected. Extremely sensitive financial data.',
                    'Should be encrypted or completely removed.'
                ],
                'safeguard_options': [
                    {'method': 'redact', 'description': 'Complete blackout'},
                    {'method': 'full_encrypt', 'description': 'Full encryption'},
                    {'method': 'replace', 'description': 'Replace with [IBAN]'}
                ]
            },
            'EMAIL_ADDRESS': {
                'display_name': 'Email Address',
                'risk_level': 'MEDIUM',
                'recommendations': [
                    'Email address found. Could enable spam, phishing, or contact-based attacks.',
                    'Consider replacing with generic placeholder or light encryption.'
                ],
                'safeguard_options': [
                    {'method': 'replace', 'description': 'Replace with [EMAIL]'},
                    {'method': 'fpe_encrypt', 'description': 'Format-preserving encryption'},
                    {'method': 'blur', 'description': 'Blur the text'},
                    {'method': 'full_encrypt', 'description': 'Full encryption'}
                ]
            },
            'PHONE_NUMBER': {
                'display_name': 'Phone Number',
                'risk_level': 'MEDIUM',
                'recommendations': [
                    'Phone number detected. Can enable social engineering or spam.',
                    'Recommend replacement or encryption.'
                ],
                'safeguard_options': [
                    {'method': 'replace', 'description': 'Replace with [PHONE]'},
                    {'method': 'fpe_encrypt', 'description': 'Format-preserving encryption'},
                    {'method': 'blur', 'description': 'Blur the text'},
                    {'method': 'full_encrypt', 'description': 'Full encryption'}
                ]
            },
            'URL': {
                'display_name': 'Web URL',
                'risk_level': 'LOW',
                'recommendations': [
                    'Website URL detected. May or may not be sensitive depending on context.',
                    'Recommend review - remove if it reveals personal information.'
                ],
                'safeguard_options': [
                    {'method': 'replace', 'description': 'Replace with [URL]'},
                    {'method': 'blur', 'description': 'Blur the text'},
                    {'method': 'keep', 'description': 'Keep as-is (if non-sensitive)'}
                ]
            },
            'IP_ADDRESS': {
                'display_name': 'IP Address',
                'risk_level': 'MEDIUM',
                'recommendations': [
                    'IP address detected. Could reveal network or location information.',
                    'Should be replaced or encrypted if it reveals sensitive details.'
                ],
                'safeguard_options': [
                    {'method': 'replace', 'description': 'Replace with [IP]'},
                    {'method': 'fpe_encrypt', 'description': 'Format-preserving encryption'},
                    {'method': 'blur', 'description': 'Blur the text'}
                ]
            },
            'MEDICAL_LICENSE': {
                'display_name': 'Medical License',
                'risk_level': 'HIGH',
                'recommendations': [
                    'Medical license number detected. Sensitive professional credential.',
                    'Should be completely removed or encrypted.'
                ],
                'safeguard_options': [
                    {'method': 'redact', 'description': 'Complete blackout'},
                    {'method': 'full_encrypt', 'description': 'Full encryption'},
                    {'method': 'replace', 'description': 'Replace with [LICENSE]'}
                ]
            },
            'US_SSN': {
                'display_name': 'Social Security Number',
                'risk_level': 'HIGH',
                'recommendations': [
                    'Social Security Number detected. This is extremely sensitive.',
                    'MUST be removed or encrypted. Exposure enables identity theft.'
                ],
                'safeguard_options': [
                    {'method': 'redact', 'description': 'Complete blackout (strongest)'},
                    {'method': 'full_encrypt', 'description': 'Full field encryption'},
                    {'method': 'replace', 'description': 'Replace with [SSN]'}
                ]
            },
            'US_PASSPORT': {
                'display_name': 'Passport Number',
                'risk_level': 'HIGH',
                'recommendations': [
                    'Passport number detected. Travel document - highly sensitive.',
                    'Should be completely removed or encrypted.'
                ],
                'safeguard_options': [
                    {'method': 'redact', 'description': 'Complete blackout'},
                    {'method': 'full_encrypt', 'description': 'Full encryption'},
                    {'method': 'replace', 'description': 'Replace with [PASSPORT]'}
                ]
            },
            'US_DRIVER_LICENSE': {
                'display_name': 'Driver License Number',
                'risk_level': 'HIGH',
                'recommendations': [
                    'Driver license number detected. Can enable identity fraud.',
                    'Must be removed or encrypted.'
                ],
                'safeguard_options': [
                    {'method': 'redact', 'description': 'Complete blackout'},
                    {'method': 'full_encrypt', 'description': 'Full encryption'},
                    {'method': 'replace', 'description': 'Replace with [LICENSE]'}
                ]
            },
            'DATE_TIME': {
                'display_name': 'Date/Time',
                'risk_level': 'LOW',
                'recommendations': [
                    'Date/time found. Risk depends on context and specificity.',
                    'If combined with other data, could identify individuals. Review context.'
                ],
                'safeguard_options': [
                    {'method': 'keep', 'description': 'Keep as-is (if not sensitive)'},
                    {'method': 'replace', 'description': 'Replace with [DATE]'},
                    {'method': 'fpe_encrypt', 'description': 'Format-preserving encryption'}
                ]
            },
            'LOCATION': {
                'display_name': 'Location/Address',
                'risk_level': 'MEDIUM',
                'recommendations': [
                    'Location or address detected. Could enable physical harm or harassment.',
                    'Consider replacing with general area or removing specific details.'
                ],
                'safeguard_options': [
                    {'method': 'replace', 'description': 'Replace with [ADDRESS]'},
                    {'method': 'fpe_encrypt', 'description': 'Format-preserving encryption'},
                    {'method': 'blur', 'description': 'Blur the text'}
                ]
            },
        }
        
        # Return entity info if found, otherwise return generic entry
        if entity_type in entity_map:
            return entity_map[entity_type]
        else:
            return {
                'display_name': entity_type,
                'risk_level': 'MEDIUM',
                'recommendations': [
                    f'Detected: {entity_type}. Please review for sensitivity.',
                    'Use recommended safeguarding method based on context.'
                ],
                'safeguard_options': [
                    {'method': 'replace', 'description': f'Replace with [REDACTED]'},
                    {'method': 'blur', 'description': 'Blur the area'},
                    {'method': 'full_encrypt', 'description': 'Full encryption'},
                    {'method': 'keep', 'description': 'Keep as-is'}
                ]
            }
    
    def _calculate_risk_level(self, entities: List[Dict[str, Any]]) -> str:
        """
        Calculate overall document risk based on detected entities
        
        Args:
            entities: List of detected entities
            
        Returns:
            Risk level: 'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'
        """
        if not entities:
            return 'LOW'
        
        risk_scores = {
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        # Get scores for all entities
        risks = [risk_scores.get(e.get('risk_level', 'LOW'), 1) for e in entities]
        average_risk = sum(risks) / len(risks)
        
        # Determine overall risk
        high_risk_count = sum(1 for e in entities if e.get('risk_level') == 'HIGH')
        
        if high_risk_count >= 3 or average_risk >= 2.8:
            return 'CRITICAL'
        elif high_risk_count >= 1 or average_risk >= 2.5:
            return 'HIGH'
        elif average_risk >= 1.5:
            return 'MEDIUM'
        else:
            return 'LOW'
