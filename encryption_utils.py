"""
Utility functions for encrypting and decrypting sensitive data.

This module provides secure encryption and decryption functionality using
Fernet symmetric encryption from the cryptography library. It ensures that
sensitive data like passwords and SSH keys are securely stored.
"""
import os
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load encryption key from environment or generate one
def get_encryption_key():
    """
    Get the encryption key from environment variables or generate a secure one.
    
    Priority order:
    1. ENCRYPTION_KEY environment variable
    2. Derived from FLASK_SECRET_KEY or SECRET_KEY
    3. Derived from a stored key file
    4. Generate a new key as a last resort (not persistent across restarts)
    
    Returns:
        bytes: The encryption key to use with Fernet
    """
    # Try to get from environment variable
    key = os.environ.get('ENCRYPTION_KEY')
    
    if not key:
        # Use app secret key for deriving encryption key if available
        app_secret = os.environ.get('FLASK_SECRET_KEY') or os.environ.get('SECRET_KEY')
        
        if app_secret:
            # Derive a key from the app secret
            # Use a unique salt for this application
            salt = b'subnet_whisperer_secure_salt_v2'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,  # Higher iteration count for better security
            )
            key_bytes = kdf.derive(app_secret.encode())
            key = base64.urlsafe_b64encode(key_bytes)
            logger.info("Derived encryption key from application secret")
        else:
            # Try to load the key from a key file
            key_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', '.encryption_key')
            try:
                if os.path.exists(key_file_path):
                    with open(key_file_path, 'rb') as key_file:
                        key = key_file.read().strip()
                        logger.info("Loaded encryption key from key file")
            except Exception as e:
                logger.warning(f"Could not load encryption key from file: {e}")
                
            # If we still don't have a key, generate one and try to save it
            if not key:
                key = Fernet.generate_key()
                logger.warning("Generated temporary encryption key. Set ENCRYPTION_KEY environment variable for persistent encryption.")
                
                # Try to save the key to a file for persistence
                try:
                    os.makedirs(os.path.dirname(key_file_path), exist_ok=True)
                    with open(key_file_path, 'wb') as key_file:
                        key_file.write(key)
                    os.chmod(key_file_path, 0o600)  # Secure permissions
                    logger.info("Saved generated encryption key to file for persistence")
                except Exception as e:
                    logger.error(f"Could not save encryption key to file: {e}")
                    logger.error("WARNING: Your encrypted data will be lost if the application restarts!")
    
    # If key is a string, convert to bytes
    if isinstance(key, str):
        key = key.encode()
        
    # Verify the key is in the correct format for Fernet
    try:
        # Test if the key is valid for Fernet
        Fernet(key)
    except Exception as e:
        logger.error(f"Invalid encryption key format: {e}")
        # If invalid, generate a new key as a last resort
        key = Fernet.generate_key()
        logger.warning("Generated new key due to format issues with existing key")
        
    return key

# Global encryption key
ENCRYPTION_KEY = get_encryption_key()
fernet = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    """
    Encrypt data using Fernet symmetric encryption
    
    Args:
        data: String data to encrypt
        
    Returns:
        Encrypted data as base64 string
    """
    if not data:
        return None
        
    # Convert string to bytes
    if isinstance(data, str):
        data = data.encode()
        
    # Encrypt the data
    encrypted_data = fernet.encrypt(data)
    
    # Return as string for storage in database
    return encrypted_data.decode()

def decrypt_data(encrypted_data):
    """
    Decrypt data that was encrypted with encrypt_data
    
    Args:
        encrypted_data: Encrypted data as base64 string
        
    Returns:
        Original string data
    """
    if not encrypted_data:
        return None
        
    # Convert string to bytes if necessary
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode()
        
    # Decrypt the data
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data.decode()
    except Exception as e:
        logger.error(f"Error decrypting data: {e}")
        return None