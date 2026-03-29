"""
Encryption Engine for PII Protection
Supports Format-Preserving Encryption (FPE) and Full Field Encryption
"""

from cryptography.fernet import Fernet, InvalidToken
import pyffx
import os
import base64
import logging
from typing import Dict, Any, Tuple, Optional
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class EncryptionEngine:
    """
    Encryption and decryption engine supporting multiple strategies
    - Format-Preserving Encryption (FPE): Data stays in original format (e.g., XXXX-XXXX-XXXX)
    - Full Field Encryption: Data becomes encrypted blob
    """
    
    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize encryption engine
        
        Args:
            master_key: Optional master encryption key. If not provided, generates new one.
        """
        self.master_key = master_key or self._generate_master_key()
        self._setup_encryption()
    
    def _generate_master_key(self) -> str:
        """
        Generate a new master encryption key
        
        Returns:
            Base64-encoded 32-byte key suitable for Fernet
        """
        key = Fernet.generate_key()
        return key.decode('utf-8')
    
    def _setup_encryption(self):
        """Setup Fernet cipher and FPE engines"""
        try:
            # Setup Fernet for full encryption
            self.cipher = Fernet(self.master_key.encode())
            
            # Setup FPE engines for common formats
            # These use the master key to derive alphabet-specific keys
            self.fpe_engines = {
                'numeric': self._create_fpe_numeric(),
                'alphanumeric': self._create_fpe_alphanumeric(),
                'email': self._create_fpe_email(),
                'credit_card': self._create_fpe_credit_card()
            }
            
            logger.info("✓ Encryption engines initialized")
        except Exception as e:
            logger.error(f"Error setting up encryption: {e}")
            raise
    
    def _create_fpe_numeric(self) -> Any:
        """Create FPE engine for numeric-only data (SSN, phone, etc.)"""
        try:
            key = self.master_key[:16]  # Use first 16 chars of master key
            return pyffx.Integer(key, max_value=9999999999999999)
        except Exception as e:
            logger.warning(f"Could not create numeric FPE: {e}")
            return None
    
    def _create_fpe_alphanumeric(self) -> Any:
        """Create FPE engine for alphanumeric data"""
        try:
            key = self.master_key[:16]
            alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
            return pyffx.String(key, alphabet=alphabet)
        except Exception as e:
            logger.warning(f"Could not create alphanumeric FPE: {e}")
            return None
    
    def _create_fpe_email(self) -> Any:
        """Create FPE engine for email addresses"""
        try:
            key = self.master_key[:16]
            # Email-safe alphabet
            alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-'
            return pyffx.String(key, alphabet=alphabet)
        except Exception as e:
            logger.warning(f"Could not create email FPE: {e}")
            return None
    
    def _create_fpe_credit_card(self) -> Any:
        """Create FPE engine for credit card numbers"""
        try:
            key = self.master_key[:16]
            return pyffx.Integer(key, max_value=9999999999999999)
        except Exception as e:
            logger.warning(f"Could not create credit card FPE: {e}")
            return None
    
    # ========== FULL FIELD ENCRYPTION ==========
    
    def encrypt_full_field(self, data: str, entity_type: str = None) -> str:
        """
        Encrypt entire field - data becomes unreadable blob
        Best for: Highly sensitive data (SSN, Credit Card, Passport)
        
        Args:
            data: Data to encrypt
            entity_type: Type of entity (for reference)
            
        Returns:
            Encrypted string (base64-encoded)
        """
        try:
            encrypted = self.cipher.encrypt(data.encode('utf-8'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"Error encrypting full field: {e}")
            raise
    
    def decrypt_full_field(self, encrypted_data: str) -> str:
        """
        Decrypt full field encryption
        
        Args:
            encrypted_data: Base64-encoded encrypted data
            
        Returns:
            Decrypted string
        """
        try:
            encrypted = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.cipher.decrypt(encrypted)
            return decrypted.decode('utf-8')
        except InvalidToken:
            logger.error("Invalid encryption token - cannot decrypt")
            raise
        except Exception as e:
            logger.error(f"Error decrypting full field: {e}")
            raise
    
    # ========== FORMAT-PRESERVING ENCRYPTION ==========
    
    def encrypt_fpe(self, data: str, entity_type: str) -> str:
        """
        Format-Preserving Encryption - maintains data format/structure
        Best for: Email, Phone, SSN, Credit Card (stays recognizable format)
        
        Args:
            data: Data to encrypt
            entity_type: Type of entity (US_SSN, CREDIT_CARD, EMAIL_ADDRESS, PHONE_NUMBER, etc.)
            
        Returns:
            Encrypted string in same format
        """
        try:
            # Route to appropriate FPE engine based on entity type
            if entity_type in ['US_SSN', 'PHONE_NUMBER']:
                return self._encrypt_fpe_numeric(data)
            elif entity_type == 'CREDIT_CARD':
                return self._encrypt_fpe_credit_card_number(data)
            elif entity_type == 'EMAIL_ADDRESS':
                return self._encrypt_fpe_email(data)
            elif entity_type == 'US_PASSPORT':
                return self._encrypt_fpe_passport(data)
            else:
                # Default to alphanumeric FPE
                return self._encrypt_fpe_alphanumeric(data)
        
        except Exception as e:
            logger.error(f"Error encrypting with FPE ({entity_type}): {e}")
            # Fallback to full encryption if FPE fails
            return self.encrypt_full_field(data, entity_type)
    
    def decrypt_fpe(self, encrypted_data: str, entity_type: str) -> str:
        """
        Decrypt Format-Preserving Encrypted data
        
        Args:
            encrypted_data: FPE encrypted data
            entity_type: Type of entity
            
        Returns:
            Decrypted string
        """
        try:
            if entity_type in ['US_SSN', 'PHONE_NUMBER']:
                return self._decrypt_fpe_numeric(encrypted_data)
            elif entity_type == 'CREDIT_CARD':
                return self._decrypt_fpe_credit_card_number(encrypted_data)
            elif entity_type == 'EMAIL_ADDRESS':
                return self._decrypt_fpe_email(encrypted_data)
            elif entity_type == 'US_PASSPORT':
                return self._decrypt_fpe_passport(encrypted_data)
            else:
                return self._decrypt_fpe_alphanumeric(encrypted_data)
        
        except Exception as e:
            logger.error(f"Error decrypting FPE ({entity_type}): {e}")
            raise
    
    def _encrypt_fpe_numeric(self, data: str) -> str:
        """
        FPE for numeric data (SSN, Phone)
        
        Args:
            data: Numeric string
            
        Returns:
            Encrypted numeric string (same format)
        """
        if not self.fpe_engines['numeric']:
            return self.encrypt_full_field(data, 'NUMERIC')
        
        try:
            # Remove non-numeric characters
            numeric_only = ''.join(filter(str.isdigit, data))
            
            if not numeric_only:
                return data
            
            # Convert to integer and encrypt
            numeric_int = int(numeric_only)
            encrypted_int = self.fpe_engines['numeric'].encrypt(numeric_int)
            
            # Format back to original format (XXX-XX-XXXX for SSN, etc.)
            encrypted_str = str(encrypted_int).zfill(len(numeric_only))
            return self._reformat_numeric(encrypted_str, data)
        
        except Exception as e:
            logger.warning(f"FPE numeric encryption failed: {e}, using full encryption")
            return self.encrypt_full_field(data, 'NUMERIC')
    
    def _decrypt_fpe_numeric(self, encrypted_data: str) -> str:
        """Decrypt numeric FPE"""
        if not self.fpe_engines['numeric']:
            return self.decrypt_full_field(encrypted_data)
        
        try:
            numeric_only = ''.join(filter(str.isdigit, encrypted_data))
            numeric_int = int(numeric_only)
            decrypted_int = self.fpe_engines['numeric'].decrypt(numeric_int)
            decrypted_str = str(decrypted_int).zfill(len(numeric_only))
            return self._reformat_numeric(decrypted_str, encrypted_data)
        except Exception as e:
            logger.error(f"FPE numeric decryption failed: {e}")
            raise
    
    def _encrypt_fpe_credit_card_number(self, data: str) -> str:
        """FPE for credit card numbers"""
        numeric_only = ''.join(filter(str.isdigit, data))
        
        if len(numeric_only) < 4:
            return data
        
        try:
            # Keep first 4 and last 4 digits visible (common practice)
            # Encrypt the middle digits
            first_4 = numeric_only[:4]
            last_4 = numeric_only[-4:]
            middle = numeric_only[4:-4]
            
            if not middle:
                return data
            
            middle_int = int(middle)
            encrypted_middle_int = self.fpe_engines['credit_card'].encrypt(middle_int)
            encrypted_middle = str(encrypted_middle_int).zfill(len(middle))
            
            # Reconstruct with same formatting
            encrypted_cc = first_4 + encrypted_middle + last_4
            return self._reformat_credit_card(encrypted_cc, data)
        
        except Exception as e:
            logger.warning(f"FPE credit card encryption failed: {e}")
            return self.encrypt_full_field(data, 'CREDIT_CARD')
    
    def _decrypt_fpe_credit_card_number(self, encrypted_data: str) -> str:
        """Decrypt credit card FPE"""
        numeric_only = ''.join(filter(str.isdigit, encrypted_data))
        
        try:
            first_4 = numeric_only[:4]
            last_4 = numeric_only[-4:]
            middle = numeric_only[4:-4]
            
            if not middle:
                return encrypted_data
            
            middle_int = int(middle)
            decrypted_middle_int = self.fpe_engines['credit_card'].decrypt(middle_int)
            decrypted_middle = str(decrypted_middle_int).zfill(len(middle))
            
            decrypted_cc = first_4 + decrypted_middle + last_4
            return self._reformat_credit_card(decrypted_cc, encrypted_data)
        
        except Exception as e:
            logger.error(f"Credit card decryption failed: {e}")
            raise
    
    def _encrypt_fpe_email(self, email: str) -> str:
        """FPE for email addresses"""
        if '@' not in email:
            return email
        
        try:
            local, domain = email.split('@', 1)
            
            # Encrypt local part, keep domain
            if self.fpe_engines['email'] and len(local) > 2:
                # Keep first and last character of local part
                first_char = local[0]
                last_char = local[-1]
                middle = local[1:-1]
                
                # Encrypt middle part
                encrypted_middle = self.fpe_engines['email'].encrypt(middle)
                encrypted_local = first_char + encrypted_middle + last_char
            else:
                encrypted_local = local
            
            return f"{encrypted_local}@{domain}"
        
        except Exception as e:
            logger.warning(f"FPE email encryption failed: {e}")
            return self.encrypt_full_field(email, 'EMAIL_ADDRESS')
    
    def _decrypt_fpe_email(self, encrypted_email: str) -> str:
        """Decrypt email FPE"""
        if '@' not in encrypted_email:
            return encrypted_email
        
        try:
            local, domain = encrypted_email.split('@', 1)
            
            if self.fpe_engines['email'] and len(local) > 2:
                first_char = local[0]
                last_char = local[-1]
                middle = local[1:-1]
                
                decrypted_middle = self.fpe_engines['email'].decrypt(middle)
                decrypted_local = first_char + decrypted_middle + last_char
            else:
                decrypted_local = local
            
            return f"{decrypted_local}@{domain}"
        
        except Exception as e:
            logger.error(f"Email decryption failed: {e}")
            raise
    
    def _encrypt_fpe_passport(self, passport: str) -> str:
        """FPE for passport numbers"""
        try:
            # Keep first 1 and last 2 characters
            if len(passport) <= 3:
                return self.encrypt_full_field(passport, 'US_PASSPORT')
            
            first = passport[0]
            last_2 = passport[-2:]
            middle = passport[1:-2]
            
            if self.fpe_engines['alphanumeric']:
                encrypted_middle = self.fpe_engines['alphanumeric'].encrypt(middle)
            else:
                encrypted_middle = middle
            
            return first + encrypted_middle + last_2
        
        except Exception as e:
            logger.warning(f"FPE passport encryption failed: {e}")
            return self.encrypt_full_field(passport, 'US_PASSPORT')
    
    def _decrypt_fpe_passport(self, encrypted_passport: str) -> str:
        """Decrypt passport FPE"""
        try:
            if len(encrypted_passport) <= 3:
                return self.decrypt_full_field(encrypted_passport)
            
            first = encrypted_passport[0]
            last_2 = encrypted_passport[-2:]
            middle = encrypted_passport[1:-2]
            
            if self.fpe_engines['alphanumeric']:
                decrypted_middle = self.fpe_engines['alphanumeric'].decrypt(middle)
            else:
                decrypted_middle = middle
            
            return first + decrypted_middle + last_2
        
        except Exception as e:
            logger.error(f"Passport decryption failed: {e}")
            raise
    
    def _encrypt_fpe_alphanumeric(self, data: str) -> str:
        """FPE for alphanumeric data"""
        if not self.fpe_engines['alphanumeric']:
            return self.encrypt_full_field(data, 'ALPHANUMERIC')
        
        try:
            if len(data) <= 2:
                return data
            
            first = data[0]
            last = data[-1]
            middle = data[1:-1]
            
            encrypted_middle = self.fpe_engines['alphanumeric'].encrypt(middle)
            return first + encrypted_middle + last
        
        except Exception as e:
            logger.warning(f"FPE alphanumeric encryption failed: {e}")
            return self.encrypt_full_field(data, 'ALPHANUMERIC')
    
    def _decrypt_fpe_alphanumeric(self, encrypted_data: str) -> str:
        """Decrypt alphanumeric FPE"""
        if not self.fpe_engines['alphanumeric']:
            return self.decrypt_full_field(encrypted_data)
        
        try:
            if len(encrypted_data) <= 2:
                return encrypted_data
            
            first = encrypted_data[0]
            last = encrypted_data[-1]
            middle = encrypted_data[1:-1]
            
            decrypted_middle = self.fpe_engines['alphanumeric'].decrypt(middle)
            return first + decrypted_middle + last
        
        except Exception as e:
            logger.error(f"Alphanumeric decryption failed: {e}")
            raise
    
    @staticmethod
    def _reformat_numeric(encrypted: str, original: str) -> str:
        """
        Reformat encrypted numeric string to match original format
        E.g., XXX-XX-XXXX becomes XXX-XX-XXXX
        """
        # Extract format from original (positions of dashes, parentheses, etc.)
        format_pattern = ''.join(c if c not in '0123456789' else 'X' for c in original)
        
        encrypted_idx = 0
        result = []
        
        for char in format_pattern:
            if char == 'X':
                if encrypted_idx < len(encrypted):
                    result.append(encrypted[encrypted_idx])
                    encrypted_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def _reformat_credit_card(encrypted: str, original: str) -> str:
        """Reformat encrypted credit card to match original format"""
        format_pattern = ''.join(c if c not in '0123456789' else 'X' for c in original)
        
        encrypted_idx = 0
        result = []
        
        for char in format_pattern:
            if char == 'X':
                if encrypted_idx < len(encrypted):
                    result.append(encrypted[encrypted_idx])
                    encrypted_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def get_encryption_key_for_storage(self) -> str:
        """
        Get master key in format suitable for storage
        
        Returns:
            Master key string
        """
        return self.master_key
    
    @staticmethod
    def load_from_key(key: str) -> 'EncryptionEngine':
        """
        Load encryption engine from existing key
        
        Args:
            key: Master key string
            
        Returns:
            EncryptionEngine instance
        """
        return EncryptionEngine(master_key=key)
