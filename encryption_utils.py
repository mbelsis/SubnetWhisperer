"""
Utility functions for encrypting and decrypting sensitive data
"""
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Load encryption key from environment or generate one
def get_encryption_key():
    # Try to get from environment variable
    key = os.environ.get('ENCRYPTION_KEY')
    
    if not key:
        # Use app secret key for deriving encryption key if available
        app_secret = os.environ.get('FLASK_SECRET_KEY') or os.environ.get('SECRET_KEY')
        
        if app_secret:
            # Derive a key from the app secret
            salt = b'subnet_whisperer_salt'  # Salt should be stored securely in production
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key_bytes = kdf.derive(app_secret.encode())
            key = base64.urlsafe_b64encode(key_bytes)
        else:
            # Generate a key if no environment variables are available
            # This will cause issues if the server restarts as the key will change
            key = Fernet.generate_key()
            print("WARNING: Generated temporary encryption key. Set ENCRYPTION_KEY environment variable for persistent encryption.")
    
    # If key is a string, convert to bytes
    if isinstance(key, str):
        key = key.encode()
        
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
        print(f"Error decrypting data: {e}")
        return None