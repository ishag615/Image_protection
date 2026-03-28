# auth.py
import secrets
import json
import hashlib
from datetime import datetime
from pathlib import Path

class KeyManager:
    """Manage admin authentication keys"""
    
    def __init__(self, vault_file='key_vault.json'):
        self.vault_file = vault_file
        self.keys = self.load_vault()
    
    def load_vault(self):
        """Load encrypted keys from vault"""
        if Path(self.vault_file).exists():
            with open(self.vault_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_vault(self):
        """Save keys to vault"""
        with open(self.vault_file, 'w') as f:
            json.dump(self.keys, f, indent=2)
    
    def generate_admin_key(self, admin_email):
        """Generate unique admin key"""
        # Create 32-character hex key
        admin_key = secrets.token_hex(16)  # 32 chars
        
        key_info = {
            'key': admin_key,
            'email': admin_email,
            'created': datetime.now().isoformat(),
            'active': True,
            'last_used': None,
            'documents_count': 0
        }
        
        self.keys[admin_email] = key_info
        self.save_vault()
        
        return admin_key
    
    def verify_admin_key(self, email, provided_key):
        """Verify admin key matches email"""
        if email not in self.keys:
            return False
        
        stored_key = self.keys[email]['key']
        
        # Update last used
        if provided_key == stored_key:
            self.keys[email]['last_used'] = datetime.now().isoformat()
            self.save_vault()
            return True
        
        return False
    
    def get_admin_info(self, email):
        """Get admin profile info"""
        return self.keys.get(email, None)
    
    def revoke_key(self, email):
        """Revoke admin key"""
        if email in self.keys:
            self.keys[email]['active'] = False
            self.save_vault()
            return True
        return False
    
    def update_document_count(self, email):
        """Update document count for admin"""
        if email in self.keys:
            self.keys[email]['documents_count'] += 1
            self.save_vault()

key_manager = KeyManager()