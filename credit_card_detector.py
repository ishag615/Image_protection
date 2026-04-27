"""
Smart Credit Card Detection and Blurring Module
Detects credit cards specifically by identifying:
- 16-digit card number
- Expiration date (MM/YY or MM/YYYY)
- CVV/CVC code (3-4 digits)
- Cardholder name
- Bank/issuer name
"""

import cv2
import numpy as np
from PIL import Image
from pathlib import Path
import logging
from typing import List, Dict, Tuple, Optional
import google.generativeai as genai
import json
import re

logger = logging.getLogger(__name__)


class CreditCardDetector:
    """
    Intelligently detects credit cards by identifying specific card elements
    """
    
    def __init__(self, gemini_api_key: Optional[str] = None):
        """
        Initialize Credit Card Detector
        
        Args:
            gemini_api_key: Optional Gemini API key for vision-based detection
        """
        self.gemini_api_key = gemini_api_key
        if gemini_api_key:
            genai.configure(api_key=gemini_api_key)
        logger.info("✓ Smart Credit Card Detector initialized")
    
    def detect_credit_card_regions(self, image_path: str) -> Dict:
        """
        Intelligently detect credit card and identify sensitive elements
        
        Args:
            image_path: Path to image file
            
        Returns:
            Dict containing:
            - has_credit_card: bool - whether credit card is detected
            - regions: List of regions to blur (with specific element types)
            - confidence: float - detection confidence (0-1)
            - found_elements: List of card elements found
            - details: Detailed detection information
        """
        try:
            logger.info(f"🔍 Starting smart credit card detection for: {image_path}")
            
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                logger.warning(f"❌ Could not load image: {image_path}")
                return {'has_credit_card': False, 'error': 'Could not load image'}
            
            logger.info(f"✓ Image loaded. Size: {img.shape}")
            
            # Use Gemini Vision to identify credit card elements
            if self.gemini_api_key:
                logger.info("📡 Attempting Gemini Vision detection...")
                result = self._detect_with_gemini(image_path, img)
                logger.info(f"✓ Gemini detection complete. Card detected: {result.get('has_credit_card')}")
                return result
            else:
                logger.warning("⚠️ No Gemini API key available")
                return {'has_credit_card': False, 'error': 'No API key'}
        
        except Exception as e:
            logger.error(f"❌ Detection error: {e}", exc_info=True)
            return {'has_credit_card': False, 'error': str(e)}
    
    def _detect_with_gemini(self, image_path: str, img_cv) -> Dict:
        """
        Use Gemini Vision to identify credit card elements
        """
        try:
            # Read and encode image
            logger.info(f"📡 Reading image from: {image_path}")
            with open(image_path, 'rb') as f:
                image_data = f.read()
            
            logger.info(f"✓ Image encoded. Size: {len(image_data)} bytes")
            
            # Get available model
            logger.info("🤖 Initializing Gemini model...")
            models_to_try = [
                'gemini-2.0-flash',
                'gemini-1.5-pro',
                'gemini-1.5-flash',
                'gemini-pro-vision',
                'gemini-pro'
            ]
            
            model = None
            for model_name in models_to_try:
                try:
                    logger.debug(f"Trying model: {model_name}")
                    model = genai.GenerativeModel(model_name)
                    logger.info(f"✓ Initialized {model_name}")
                    break
                except Exception as e:
                    logger.debug(f"Model {model_name} not available: {e}")
                    continue
            
            if model is None:
                raise Exception("No suitable Gemini model available")
            
            # Create detailed prompt for credit card element detection
            prompt = """Analyze this image for credit card elements. Respond with ONLY a valid JSON object (no markdown, no backticks, valid JSON only) like this:
{
  "is_credit_card": true,
  "confidence": 95,
  "elements_found": ["card_number", "expiration", "cvv", "cardholder_name"],
  "card_region_percent": {"top": 5, "left": 10, "width": 80, "height": 70},
  "elements": {
    "card_number": {"region_percent": {"top": 20, "left": 15, "width": 70, "height": 15}, "visible": true},
    "expiration": {"region_percent": {"top": 60, "left": 65, "width": 30, "height": 12}, "visible": true},
    "cvv": {"region_percent": {"top": 30, "left": 70, "width": 25, "height": 12}, "visible": true},
    "cardholder_name": {"region_percent": {"top": 50, "left": 15, "width": 40, "height": 10}, "visible": true},
    "bank_name": {"region_percent": {"top": 10, "left": 15, "width": 50, "height": 10}, "visible": false}
  },
  "reason": "Credit card with all essential elements visible"
}

CRITICAL RULES:
1. ONLY return is_credit_card=true if image shows an ACTUAL PHYSICAL CREDIT CARD
2. The card must have AT LEAST 3 of these specific visible elements:
   - A 16-digit card number (printed numbers in 4 groups of 4)
   - An expiration date (MM/YY or MM/YYYY format)
   - A CVV/CVC code (3-4 digits, usually on back but sometimes visible on front)
   - A cardholder name (person's name embossed or printed)
   - A bank/issuer name or logo

3. If image shows: screenshots, photos of screens, documents, other objects, or only partially visible cards, return is_credit_card=false
4. For each visible element, provide its position as a percentage (0-100) of image dimensions
5. All numbers in JSON must be valid integers/floats, not strings

Do NOT return anything except valid JSON."""
            
            logger.info("📤 Sending request to Gemini API...")
            
            response = model.generate_content([
                {
                    "mime_type": "image/png",
                    "data": image_data
                },
                prompt
            ])
            
            logger.info("✓ Received response from Gemini")
            response_text = response.text.strip()
            logger.debug(f"Raw response: {response_text[:500]}...")
            
            # Parse JSON response
            # Remove markdown code blocks if present
            response_text = response_text.replace('```json', '').replace('```', '').strip()
            
            try:
                data = json.loads(response_text)
                logger.info(f"✓ Parsed JSON response")
            except json.JSONDecodeError as e:
                logger.error(f"❌ Failed to parse JSON: {e}")
                logger.error(f"Response: {response_text[:500]}")
                return {'has_credit_card': False, 'error': 'Invalid response format', 'raw': response_text[:200]}
            
            # Check if credit card detected
            is_credit_card = data.get('is_credit_card', False)
            confidence = data.get('confidence', 0) / 100.0  # Convert to 0-1
            elements_found = data.get('elements_found', [])
            
            logger.info(f"📊 Detection result: is_card={is_credit_card}, confidence={confidence:.2f}, elements={elements_found}")
            
            if not is_credit_card or len(elements_found) < 3:
                logger.info(f"ℹ️ Not a credit card (is_card={is_credit_card}, elements={len(elements_found)})")
                return {
                    'has_credit_card': False,
                    'reason': data.get('reason', 'Insufficient credit card elements'),
                    'confidence': confidence,
                    'elements_found': elements_found
                }
            
            # Extract image dimensions
            img_height, img_width = img_cv.shape[:2]
            logger.info(f"Image dimensions: {img_width}x{img_height}")
            
            # Build regions to blur from detected elements
            regions = []
            elements_dict = data.get('elements', {})
            
            element_config = {
                'card_number': {'blur_strength': 41, 'priority': 1},
                'expiration': {'blur_strength': 35, 'priority': 2},
                'cvv': {'blur_strength': 41, 'priority': 1},
                'cardholder_name': {'blur_strength': 31, 'priority': 3},
                'bank_name': {'blur_strength': 25, 'priority': 4}
            }
            
            for element_type, element_data in elements_dict.items():
                if not element_data.get('visible', False):
                    continue
                
                region_percent = element_data.get('region_percent', {})
                if not region_percent:
                    continue
                
                # Convert percentages to pixel coordinates
                top = int(region_percent.get('top', 0) * img_height / 100)
                left = int(region_percent.get('left', 0) * img_width / 100)
                width = int(region_percent.get('width', 0) * img_width / 100)
                height = int(region_percent.get('height', 0) * img_height / 100)
                
                # Validate coordinates
                top = max(0, top)
                left = max(0, left)
                bottom = min(img_height, top + height)
                right = min(img_width, left + width)
                
                if right > left and bottom > top:
                    config = element_config.get(element_type, {'blur_strength': 31, 'priority': 5})
                    region = {
                        'type': element_type,
                        'coords': (left, top, right, bottom),
                        'blur_strength': config['blur_strength'],
                        'description': f'{element_type.replace("_", " ").title()} region',
                        'priority': config['priority']
                    }
                    regions.append(region)
                    logger.info(f"  ✓ {element_type}: ({left}, {top}, {right}, {bottom})")
            
            logger.info(f"✓ Identified {len(regions)} blur regions from {len(elements_found)} elements")
            
            # Get card region
            card_region_percent = data.get('card_region_percent', {})
            card_region = None
            if card_region_percent:
                top = int(card_region_percent.get('top', 0) * img_height / 100)
                left = int(card_region_percent.get('left', 0) * img_width / 100)
                width = int(card_region_percent.get('width', 0) * img_width / 100)
                height = int(card_region_percent.get('height', 0) * img_height / 100)
                card_region = (left, top, width, height)
                logger.info(f"Card region: ({left}, {top}, {width}x{height})")
            
            return {
                'has_credit_card': True,
                'confidence': confidence,
                'regions': regions,
                'found_elements': elements_found,
                'card_region': card_region,
                'details': f"Found {len(elements_found)} credit card elements, identified {len(regions)} blur regions"
            }
        
        except Exception as e:
            logger.error(f"❌ Gemini detection error: {e}", exc_info=True)
            return {'has_credit_card': False, 'error': str(e)}
    
    def blur_credit_card_regions(self, image_path: str, output_path: str) -> Dict:
        """
        Apply targeted blur to credit card sensitive regions
        
        Args:
            image_path: Path to original image
            output_path: Path to save blurred image
            
        Returns:
            Result dict with success status
        """
        try:
            logger.info(f"🔍 Starting blur for: {image_path}")
            
            # Detect regions
            detection = self.detect_credit_card_regions(image_path)
            
            if not detection.get('has_credit_card'):
                logger.warning(f"⚠️ No credit card detected: {detection.get('reason', 'Unknown')}")
                return {
                    'success': False,
                    'reason': detection.get('reason', 'No credit card detected')
                }
            
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                raise Exception("Could not load image for blurring")
            
            logger.info(f"✓ Image loaded. Found {len(detection.get('regions', []))} regions to blur")
            
            # Apply blur to each region
            regions = detection.get('regions', [])
            for i, region in enumerate(regions):
                coords = region['coords']
                blur_k = region.get('blur_strength', 31)
                
                # Ensure blur kernel is odd
                if blur_k % 2 == 0:
                    blur_k += 1
                
                x1, y1, x2, y2 = coords
                
                # Extract region
                roi = img[y1:y2, x1:x2]
                
                if roi.size > 0:
                    # Apply blur
                    blurred = cv2.GaussianBlur(roi, (blur_k, blur_k), 0)
                    
                    # Place back
                    img[y1:y2, x1:x2] = blurred
                    
                    logger.info(f"  ✓ Blurred {region['type']}: ({x1},{y1})-({x2},{y2}), kernel={blur_k}")
            
            # Save image
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            cv2.imwrite(output_path, img)
            logger.info(f"✓ Blurred image saved to: {output_path}")
            
            return {
                'success': True,
                'output_path': output_path,
                'regions_blurred': len(regions),
                'elements_blurred': [r['type'] for r in regions]
            }
        
        except Exception as e:
            logger.error(f"❌ Blur error: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}
    
    def blur_credit_card_full(self, image_path: str, output_path: str) -> Dict:
        """
        Apply full blur to entire credit card area
        
        Args:
            image_path: Path to original image
            output_path: Path to save blurred image
            
        Returns:
            Result dict with success status
        """
        try:
            logger.info(f"🔍 Starting full blur for: {image_path}")
            
            # Detect card
            detection = self.detect_credit_card_regions(image_path)
            
            if not detection.get('has_credit_card'):
                logger.warning("⚠️ No credit card detected")
                return {'success': False, 'reason': 'No credit card detected'}
            
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                raise Exception("Could not load image")
            
            # Get card region
            card_region = detection.get('card_region')
            if not card_region:
                logger.warning("⚠️ Card region not defined, using full image")
                x1, y1, w, h = 0, 0, img.shape[1], img.shape[0]
            else:
                x1, y1, w, h = card_region
                x2, y2 = x1 + w, y1 + h
            
            logger.info(f"Full blur region: ({x1}, {y1}, {x2}, {y2})")
            
            # Apply blur to card area
            roi = img[y1:y2, x1:x2]
            if roi.size > 0:
                blurred = cv2.GaussianBlur(roi, (51, 51), 0)
                img[y1:y2, x1:x2] = blurred
            
            # Save
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            cv2.imwrite(output_path, img)
            logger.info(f"✓ Full blur saved to: {output_path}")
            
            return {'success': True, 'output_path': output_path}
        
        except Exception as e:
            logger.error(f"❌ Full blur error: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}


# Standalone functions for backward compatibility
def detect_credit_card_regions(image_path: str, api_key: Optional[str] = None) -> Dict:
    """Standalone detection function"""
    detector = CreditCardDetector(gemini_api_key=api_key)
    return detector.detect_credit_card_regions(image_path)


def blur_credit_card_regions(image_path: str, output_path: str, api_key: Optional[str] = None) -> Dict:
    """Standalone blur function"""
    detector = CreditCardDetector(gemini_api_key=api_key)
    return detector.blur_credit_card_regions(image_path, output_path)


def blur_credit_card_full(image_path: str, output_path: str, api_key: Optional[str] = None) -> Dict:
    """Standalone full blur function"""
    detector = CreditCardDetector(gemini_api_key=api_key)
    return detector.blur_credit_card_full(image_path, output_path)
    
    def detect_credit_card_regions(self, image_path: str) -> Dict:
        """
        Detect credit card and identify sensitive regions
        
        Args:
            image_path: Path to image file
            
        Returns:
            Dict containing:
            - has_credit_card: bool - whether credit card is detected
            - regions: List of regions to blur
            - confidence: float - detection confidence (0-1)
            - card_region: Bounding box of entire card (x, y, w, h)
            - details: Additional detection details
        """
        try:
            logger.info(f"🔍 Starting credit card detection for: {image_path}")
            
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                logger.warning(f"❌ Could not load image: {image_path}")
                return {
                    'has_credit_card': False,
                    'error': 'Could not load image'
                }
            
            logger.info(f"✓ Image loaded. Size: {img.shape}")
            
            # Try Gemini-based detection first if API key available
            if self.gemini_api_key:
                logger.info("📡 Attempting Gemini Vision detection...")
                gemini_result = self._detect_with_gemini(image_path)
                logger.info(f"Gemini result: {gemini_result}")
                if gemini_result.get('success'):
                    logger.info(f"✓ Gemini detected card: {gemini_result.get('has_credit_card')}")
                    return gemini_result
                else:
                    logger.warning(f"⚠️ Gemini detection failed: {gemini_result.get('error')}")
            else:
                logger.warning("⚠️ No Gemini API key - using OpenCV only")
            
            # Fallback: CV2-based detection
            logger.info("🔍 Attempting OpenCV detection...")
            cv_result = self._detect_with_opencv(image_path, img)
            logger.info(f"OpenCV result: Card detected: {cv_result.get('has_credit_card')}, Confidence: {cv_result.get('confidence')}")
            return cv_result
        
        except Exception as e:
            logger.error(f"❌ Error detecting credit card: {e}", exc_info=True)
            return {
                'has_credit_card': False,
                'error': str(e)
            }
    
    def _detect_with_gemini(self, image_path: str) -> Dict:
        """
        Use Gemini Vision to detect credit cards and identify regions
        
        Args:
            image_path: Path to image
            
        Returns:
            Detection result dict
        """
        try:
            import base64
            
            logger.info(f"📡 Reading image from: {image_path}")
            with open(image_path, 'rb') as f:
                image_data = base64.standard_b64encode(f.read()).decode('utf-8')
            
            logger.info(f"✓ Image encoded. Size: {len(image_data)} bytes")
            
            try:
                # Try multiple models in order of preference
                models_to_try = [
                    'gemini-2.0-flash',
                    'gemini-1.5-pro',
                    'gemini-1.5-flash',
                    'gemini-pro-vision',
                    'gemini-pro'
                ]
                
                model = None
                for model_name in models_to_try:
                    try:
                        logger.info(f"Trying model: {model_name}")
                        model = genai.GenerativeModel(model_name)
                        logger.info(f"✓ Successfully initialized {model_name}")
                        break
                    except Exception as e:
                        logger.debug(f"Model {model_name} not available: {e}")
                        continue
                
                if model is None:
                    raise Exception("No suitable Gemini model available")
                    
            except Exception as model_err:
                logger.error(f"❌ Failed to initialize Gemini model: {model_err}")
                return {'success': False, 'error': f"Model init failed: {model_err}"}
            
            # Improved prompt that's easier to parse
            prompt = """TASK: Detect if there is a credit card in this image.

Answer these questions in EXACTLY this format:
1. Is there a credit card visible? YES or NO
2. Confidence level: 0 to 100
3. Card number visible? YES or NO
4. Expiration date visible? YES or NO
5. CVV/CVC visible? YES or NO

Example response:
1. YES
2. 95
3. YES
4. YES
5. NO

Now analyze the image:"""
            
            logger.info("📤 Sending request to Gemini API...")
            try:
                response = model.generate_content([
                    {"mime_type": "image/jpeg", "data": image_data},
                    prompt
                ])
                logger.info("✓ Received response from Gemini")
            except Exception as api_err:
                logger.error(f"❌ Gemini API error: {api_err}")
                return {'success': False, 'error': f"API error: {api_err}"}
            
            analysis_text = response.text
            logger.info(f"📝 Raw Gemini response:\n{repr(analysis_text)}\n")
            
            # Parse response with multiple strategies
            result = {
                'has_credit_card': False,
                'method': 'gemini',
                'regions': [],
                'confidence': 0,
                'raw_analysis': analysis_text,
                'success': True
            }
            
            # Strategy 1: Look for "YES" in first line
            lines = [line.strip() for line in analysis_text.split('\n') if line.strip()]
            logger.info(f"📊 Parsed {len(lines)} lines from response")
            
            # Try to find YES/NO answer
            card_detected = False
            for i, line in enumerate(lines):
                logger.info(f"  Line {i}: {repr(line[:100])}")
                
                # First non-empty line should contain the answer
                if i == 0 or '1.' in line or 'credit card' in line.lower():
                    if 'YES' in line.upper():
                        card_detected = True
                        logger.info(f"✓ Found YES in line: {repr(line)}")
                        break
                    elif 'NO' in line.upper():
                        logger.info(f"Found NO in line: {repr(line)}")
                        break
            
            # Also check full text for YES/NO as fallback
            if not card_detected and 'YES' in analysis_text.upper():
                # Count YES vs NO
                yes_count = analysis_text.upper().count('YES')
                no_count = analysis_text.upper().count('NO')
                logger.info(f"YES count: {yes_count}, NO count: {no_count}")
                if yes_count > no_count:
                    card_detected = True
                    logger.info("✓ More YES than NO - card detected")
            
            result['has_credit_card'] = card_detected
            
            # Extract confidence
            for line in lines:
                if '2.' in line or 'confidence' in line.lower():
                    try:
                        # Extract number from line
                        numbers = [int(s) for s in line.replace(':', '').split() if s.isdigit()]
                        if numbers:
                            result['confidence'] = numbers[0] / 100.0
                            logger.info(f"✓ Confidence: {result['confidence']}")
                    except Exception as conf_err:
                        logger.warning(f"⚠️ Could not parse confidence: {conf_err}")
            
            logger.info(f"🎯 Final decision - Card detected: {result['has_credit_card']}, Confidence: {result['confidence']}")
            
            if result['has_credit_card']:
                logger.info("🎯 Credit card detected! Generating default regions...")
                # Use default regions for detected cards
                result['regions'] = [
                    {
                        'type': 'card_number',
                        'relative_coords': (0.1, 0.35, 0.9, 0.55),
                        'blur_strength': 31,
                        'description': 'Credit card number region'
                    },
                    {
                        'type': 'expiry',
                        'relative_coords': (0.6, 0.65, 0.95, 0.8),
                        'blur_strength': 31,
                        'description': 'Expiration date region'
                    },
                    {
                        'type': 'cvv',
                        'relative_coords': (0.65, 0.3, 0.95, 0.5),
                        'blur_strength': 41,
                        'description': 'CVV/CVC code region'
                    }
                ]
                logger.info(f"✓ Generated {len(result['regions'])} blur regions")
            else:
                logger.info("ℹ️ No credit card detected by Gemini")
            
            return result
        
        except Exception as e:
            logger.error(f"❌ Gemini detection error: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}
    
    def _parse_gemini_regions(self, analysis_text: str) -> List[Dict]:
        """
        Parse Gemini response to extract blur regions
        
        Args:
            analysis_text: Gemini response text
            
        Returns:
            List of regions to blur
        """
        regions = []
        location_map = {
            'top-left': (0.05, 0.05, 0.35, 0.25),
            'top-center': (0.35, 0.05, 0.65, 0.25),
            'top-right': (0.65, 0.05, 0.95, 0.25),
            'middle-left': (0.05, 0.35, 0.35, 0.65),
            'middle-center': (0.35, 0.35, 0.65, 0.65),
            'middle-right': (0.65, 0.35, 0.95, 0.65),
            'bottom-left': (0.05, 0.65, 0.35, 0.95),
            'bottom-center': (0.35, 0.65, 0.65, 0.95),
            'bottom-right': (0.65, 0.65, 0.95, 0.95),
            'front-right': (0.60, 0.30, 0.95, 0.70),
            'back': (0.50, 0.40, 0.95, 0.80),
            'front-top': (0.10, 0.05, 0.90, 0.35),
        }
        
        for line in analysis_text.split('\n'):
            if 'NUMBER_LOCATION:' in line:
                location = line.split(':')[1].strip().lower()
                if location in location_map and location != 'not_visible':
                    x1, y1, x2, y2 = location_map[location]
                    regions.append({
                        'type': 'card_number',
                        'relative_coords': (x1, y1, x2, y2),
                        'blur_strength': 31,
                        'description': 'Credit card number region'
                    })
            
            elif 'CVV_LOCATION:' in line:
                location = line.split(':')[1].strip().lower()
                if location != 'not_visible':
                    if location == 'back':
                        coords = location_map.get(location, (0.50, 0.40, 0.95, 0.80))
                    elif location == 'front-right':
                        coords = location_map.get(location, (0.75, 0.50, 0.95, 0.70))
                    else:
                        coords = location_map.get(location, (0.70, 0.45, 0.95, 0.65))
                    
                    x1, y1, x2, y2 = coords
                    regions.append({
                        'type': 'cvv',
                        'relative_coords': (x1, y1, x2, y2),
                        'blur_strength': 41,
                        'description': 'CVV/CVC code region'
                    })
            
            elif 'EXPIRY_LOCATION:' in line:
                location = line.split(':')[1].strip().lower()
                if location != 'not_visible':
                    coords = location_map.get(location, (0.60, 0.60, 0.95, 0.80))
                    x1, y1, x2, y2 = coords
                    regions.append({
                        'type': 'expiry',
                        'relative_coords': (x1, y1, x2, y2),
                        'blur_strength': 31,
                        'description': 'Expiration date region'
                    })
        
        return regions
    
    def _detect_with_opencv(self, image_path: str, img_cv: np.ndarray) -> Dict:
        """
        Basic credit card detection using OpenCV
        Looks for rectangular shapes and regions with specific characteristics
        
        Args:
            image_path: Path to image
            img_cv: OpenCV image
            
        Returns:
            Detection result dict
        """
        try:
            logger.info("🔍 Starting OpenCV detection...")
            
            result = {
                'has_credit_card': False,
                'method': 'opencv',
                'regions': [],
                'confidence': 0,
                'success': True
            }
            
            gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
            logger.info(f"✓ Image converted to grayscale. Shape: {gray.shape}")
            
            img_height, img_width = img_cv.shape[:2]
            total_area = img_width * img_height
            
            logger.info(f"Image dimensions: {img_width}x{img_height}, total area: {total_area}")
            
            # Strategy 1: Look for large rectangular region (card usually fills significant area)
            logger.info("📊 Strategy 1: Looking for large rectangular regions...")
            
            # Edge detection with multiple parameters to catch more cards
            edges = cv2.Canny(gray, 50, 150)
            edges_aggressive = cv2.Canny(gray, 30, 100)
            edges_very_aggressive = cv2.Canny(gray, 10, 80)
            edges = cv2.bitwise_or(cv2.bitwise_or(edges, edges_aggressive), edges_very_aggressive)
            
            logger.info(f"✓ Edge detection complete")
            
            # Apply morphological operations to enhance edges
            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5, 5))
            edges = cv2.morphologyEx(edges, cv2.MORPH_CLOSE, kernel)
            
            # Find contours
            contours, _ = cv2.findContours(edges, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
            logger.info(f"🔍 Found {len(contours)} contours")
            
            card_candidates = []
            
            # Check all contours
            for i, contour in enumerate(contours):
                area = cv2.contourArea(contour)
                
                # Very lenient: card can be 2-95% of image
                min_area = total_area * 0.02  
                max_area = total_area * 0.95  
                
                if area < min_area or area > max_area:
                    continue
                
                # Approximate to polygon
                epsilon = 0.02 * cv2.arcLength(contour, True)
                approx = cv2.approxPolyDP(contour, epsilon, True)
                
                # Check if it's roughly rectangular (4 points, allow some tolerance)
                if len(approx) == 4 or len(approx) == 5:  # Allow pentagon for screenshots with shadows
                    x, y, w, h = cv2.boundingRect(approx)
                    
                    # Credit cards have aspect ratio around 1.5-2.1
                    # Be very lenient: 1.2-3.0
                    aspect_ratio = w / h if h > 0 else 0
                    
                    if 1.2 < aspect_ratio < 3.0:
                        logger.info(f"  ✓ Card candidate #{i}: area={area:.0f} ({area/total_area*100:.1f}%), aspect={aspect_ratio:.2f}, dims=({w}x{h})")
                        card_candidates.append({
                            'x': x, 'y': y, 'w': w, 'h': h,
                            'area': area,
                            'aspect_ratio': aspect_ratio,
                            'score': area  # Score for ranking
                        })
            
            logger.info(f"🎯 Strategy 1 found {len(card_candidates)} card candidates")
            
            # Strategy 2: Look for the largest rectangular region (even if not perfect aspect ratio)
            if not card_candidates:
                logger.info("📊 Strategy 2: Looking for any large rectangular region...")
                for i, contour in enumerate(contours):
                    area = cv2.contourArea(contour)
                    
                    # Very lenient: card can be 5-95% of image  
                    min_area = total_area * 0.05
                    max_area = total_area * 0.95
                    
                    if area < min_area or area > max_area:
                        continue
                    
                    epsilon = 0.02 * cv2.arcLength(contour, True)
                    approx = cv2.approxPolyDP(contour, epsilon, True)
                    
                    if len(approx) >= 4:  # At least 4 corners (rectangle-like)
                        x, y, w, h = cv2.boundingRect(approx)
                        aspect_ratio = w / h if h > 0 else 0
                        
                        # Even more lenient for strategy 2
                        if 1.0 < aspect_ratio < 4.0:
                            logger.info(f"  ✓ Candidate #{i}: area={area:.0f} ({area/total_area*100:.1f}%), aspect={aspect_ratio:.2f}")
                            card_candidates.append({
                                'x': x, 'y': y, 'w': w, 'h': h,
                                'area': area,
                                'aspect_ratio': aspect_ratio,
                                'score': area
                            })
                
                logger.info(f"🎯 Strategy 2 found {len(card_candidates)} candidates")
            
            # Strategy 3: Use color-based detection for credit cards (usually blue/dark colored)
            if not card_candidates:
                logger.info("📊 Strategy 3: Color-based detection...")
                
                # Convert to HSV
                hsv = cv2.cvtColor(img_cv, cv2.COLOR_BGR2HSV)
                
                # Look for dark colors (credit cards are usually dark blue, black, etc.)
                lower_dark = np.array([0, 0, 0])
                upper_dark = np.array([180, 255, 100])
                
                # Also look for blue (common credit card color)
                lower_blue = np.array([90, 50, 50])
                upper_blue = np.array([130, 255, 255])
                
                mask_dark = cv2.inRange(hsv, lower_dark, upper_dark)
                mask_blue = cv2.inRange(hsv, lower_blue, upper_blue)
                
                mask = cv2.bitwise_or(mask_dark, mask_blue)
                
                # Find contours in the mask
                contours_colored, _ = cv2.findContours(mask, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
                logger.info(f"🔍 Color detection found {len(contours_colored)} colored contours")
                
                for i, contour in enumerate(contours_colored):
                    area = cv2.contourArea(contour)
                    
                    if area < total_area * 0.05 or area > total_area * 0.95:
                        continue
                    
                    x, y, w, h = cv2.boundingRect(contour)
                    aspect_ratio = w / h if h > 0 else 0
                    
                    if 1.2 < aspect_ratio < 3.0:
                        logger.info(f"  ✓ Color-based candidate: area={area:.0f}, aspect={aspect_ratio:.2f}")
                        card_candidates.append({
                            'x': x, 'y': y, 'w': w, 'h': h,
                            'area': area,
                            'aspect_ratio': aspect_ratio,
                            'score': area * 1.5  # Boost score for color-based detection
                        })
            
            logger.info(f"🎯 Total candidates after all strategies: {len(card_candidates)}")
            
            if card_candidates:
                # Use the best candidate (highest score = largest area)
                best_card = max(card_candidates, key=lambda c: c['score'])
                logger.info(f"✓ Selected best card: area={best_card['area']:.0f}, ratio={best_card['aspect_ratio']:.2f}, size=({best_card['w']}x{best_card['h']})")
                
                result['has_credit_card'] = True
                result['confidence'] = 0.75  # Good confidence
                result['card_region'] = (best_card['x'], best_card['y'], best_card['w'], best_card['h'])
                
                # Define blur regions based on card location
                x, y, w, h = best_card['x'], best_card['y'], best_card['w'], best_card['h']
                
                # Card number - typically in upper-middle area
                result['regions'].append({
                    'type': 'card_number',
                    'coords': (int(x + w*0.05), int(y + h*0.25), int(x + w*0.95), int(y + h*0.45)),
                    'blur_strength': 31,
                    'description': 'Credit card number region'
                })
                
                # Expiration - typically bottom right
                result['regions'].append({
                    'type': 'expiry',
                    'coords': (int(x + w*0.60), int(y + h*0.65), int(x + w*0.95), int(y + h*0.85)),
                    'blur_strength': 31,
                    'description': 'Expiration date region'
                })
                
                # CVV - typically on back, but if visible on front, it's usually on the right
                result['regions'].append({
                    'type': 'cvv',
                    'coords': (int(x + w*0.70), int(y + h*0.40), int(x + w*0.95), int(y + h*0.60)),
                    'blur_strength': 41,
                    'description': 'CVV/CVC code region'
                })
                
                logger.info(f"✓ OpenCV detection successful: {len(result['regions'])} regions identified")
            else:
                logger.info(f"ℹ️ No card candidates found after all strategies")
            
            return result
        
        except Exception as e:
            logger.error(f"❌ OpenCV detection error: {e}", exc_info=True)
            return {
                'has_credit_card': False,
                'method': 'opencv',
                'error': str(e),
                'success': True
            }
    
    def blur_credit_card_regions(self, image_path: str, output_path: str, 
                                 regions: List[Dict], blur_strength: int = 31) -> str:
        """
        Apply blur to specific credit card regions
        
        Args:
            image_path: Path to original image
            output_path: Path to save blurred image
            regions: List of regions to blur (from detect_credit_card_regions)
            blur_strength: Blur kernel size
            
        Returns:
            Path to blurred image
        """
        try:
            # Load image
            img = Image.open(image_path).convert('RGB')
            img_array = np.array(img)
            img_cv = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
            
            img_height, img_width = img_cv.shape[:2]
            
            # Apply blur to each region
            for region in regions:
                if 'coords' in region:
                    # Absolute coordinates
                    x1, y1, x2, y2 = region['coords']
                elif 'relative_coords' in region:
                    # Relative coordinates (0-1)
                    rx1, ry1, rx2, ry2 = region['relative_coords']
                    x1 = int(rx1 * img_width)
                    y1 = int(ry1 * img_height)
                    x2 = int(rx2 * img_width)
                    y2 = int(ry2 * img_height)
                else:
                    continue
                
                # Ensure coordinates are within bounds
                x1, y1 = max(0, x1), max(0, y1)
                x2, y2 = min(img_width, x2), min(img_height, y2)
                
                if x2 <= x1 or y2 <= y1:
                    continue
                
                # Get the region to blur
                region_img = img_cv[y1:y2, x1:x2]
                
                # Apply blur
                blur_k = region.get('blur_strength', blur_strength)
                blur_k = blur_k if blur_k % 2 == 1 else blur_k + 1
                
                blurred_region = cv2.GaussianBlur(region_img, (blur_k, blur_k), 0)
                
                # Replace the region in the image
                img_cv[y1:y2, x1:x2] = blurred_region
                
                logger.info(f"Blurred {region.get('type', 'unknown')} at ({x1}, {y1}, {x2}, {y2})")
            
            # Save the result
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            img_rgb = cv2.cvtColor(img_cv, cv2.COLOR_BGR2RGB)
            result_img = Image.fromarray(img_rgb)
            result_img.save(output_path, quality=95)
            
            logger.info(f"Credit card blurred image saved to {output_path}")
            return output_path
        
        except Exception as e:
            logger.error(f"Error blurring credit card regions: {e}")
            raise
    
    def blur_credit_card_full(self, image_path: str, output_path: str,
                              card_region: Tuple[int, int, int, int],
                              blur_strength: int = 51) -> str:
        """
        Apply blur to entire credit card area
        
        Args:
            image_path: Path to original image
            output_path: Path to save blurred image
            card_region: Bounding box (x, y, w, h) of card
            blur_strength: Blur kernel size
            
        Returns:
            Path to blurred image
        """
        try:
            # Load image
            img = Image.open(image_path).convert('RGB')
            img_array = np.array(img)
            img_cv = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
            
            x, y, w, h = card_region
            
            # Get the card region
            card_img = img_cv[y:y+h, x:x+w]
            
            # Apply strong blur
            blur_k = blur_strength if blur_strength % 2 == 1 else blur_strength + 1
            blurred_card = cv2.GaussianBlur(card_img, (blur_k, blur_k), 0)
            
            # Replace the card in the image
            img_cv[y:y+h, x:x+w] = blurred_card
            
            # Save the result
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            img_rgb = cv2.cvtColor(img_cv, cv2.COLOR_BGR2RGB)
            result_img = Image.fromarray(img_rgb)
            result_img.save(output_path, quality=95)
            
            logger.info(f"Credit card fully blurred image saved to {output_path}")
            return output_path
        
        except Exception as e:
            logger.error(f"Error blurring entire credit card: {e}")
            raise
