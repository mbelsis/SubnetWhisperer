"""
Utility functions for encrypting and decrypting sensitive data.

Credentials are encrypted with Fernet (cryptography library). The key is
chosen in this order:

1. ``ENCRYPTION_KEY`` env var. It must be a valid Fernet key, otherwise the
   app refuses to start (RuntimeError).
2. An existing ``instance/.encryption_key`` file.
3. A key derived from ``FLASK_SECRET_KEY`` or ``SECRET_KEY`` (legacy, logs a
   warning).
4. A newly generated key, saved to ``instance/.encryption_key`` with 0600
   permissions.
"""
import os
import base64
import logging
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

KEY_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', '.encryption_key')

# Salt used by the legacy secret-derived key. Must not change, or existing
# ciphertexts encrypted with a derived key can no longer be decrypted.
_LEGACY_SALT = b'subnet_whisperer_secure_salt_v2'


class DecryptionError(Exception):
    """Raised when stored data cannot be decrypted with the current key."""


def _validate_key(key, source):
    if isinstance(key, str):
        key = key.strip().encode()
    else:
        key = key.strip()
    try:
        Fernet(key)
    except Exception as e:
        raise RuntimeError(
            f"Invalid encryption key from {source}: {e}. It must be a 32-byte "
            "url-safe base64 Fernet key (generate one with "
            "`python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"`)."
        ) from e
    return key


def _derive_key(secret):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_LEGACY_SALT,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))


def _write_new_key_file(path, key):
    """Create the key file with 0600 permissions. Returns the key actually stored."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process created it first; use its key.
        with open(path, 'rb') as f:
            return _validate_key(f.read(), path)
    with os.fdopen(fd, 'wb') as f:
        f.write(key)
    return key


def get_encryption_key(key_file_path=None):
    """Return the Fernet key to use, following the priority order above."""
    key_file_path = key_file_path or KEY_FILE_PATH

    env_key = os.environ.get('ENCRYPTION_KEY')
    if env_key:
        return _validate_key(env_key, 'ENCRYPTION_KEY')

    if os.path.exists(key_file_path):
        try:
            with open(key_file_path, 'rb') as f:
                data = f.read()
        except OSError as e:
            raise RuntimeError(f"Could not read encryption key file {key_file_path}: {e}") from e
        key = _validate_key(data, key_file_path)
        logger.info("Loaded encryption key from key file")
        return key

    app_secret = os.environ.get('FLASK_SECRET_KEY') or os.environ.get('SECRET_KEY')
    if app_secret:
        logger.warning(
            "Deriving the encryption key from FLASK_SECRET_KEY/SECRET_KEY (legacy). "
            "Set ENCRYPTION_KEY to a Fernet key instead; changing the secret key "
            "will make stored credentials unreadable.")
        return _derive_key(app_secret)

    key = Fernet.generate_key()
    try:
        key = _write_new_key_file(key_file_path, key)
        logger.warning("Generated a new encryption key and saved it to %s. Back this file up.",
                       key_file_path)
    except OSError as e:
        raise RuntimeError(
            f"Could not save a generated encryption key to {key_file_path}: {e}. "
            "Set ENCRYPTION_KEY or make the instance/ folder writable.") from e
    return key


# Global encryption key
ENCRYPTION_KEY = get_encryption_key()
fernet = Fernet(ENCRYPTION_KEY)


def encrypt_data(data):
    """Encrypt a string. Returns the Fernet token as a str, or None for empty input."""
    if not data:
        return None
    if isinstance(data, str):
        data = data.encode()
    return fernet.encrypt(data).decode()


def decrypt_data(encrypted_data):
    """
    Decrypt data produced by encrypt_data.

    Returns None only for empty input. Raises DecryptionError when the data
    cannot be decrypted (wrong key or corrupted data).
    """
    if not encrypted_data:
        return None
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode()
    try:
        return fernet.decrypt(encrypted_data).decode()
    except (InvalidToken, ValueError, TypeError) as e:
        logger.error("Error decrypting stored data: %s", type(e).__name__)
        raise DecryptionError(
            "Stored credential could not be decrypted (encryption key changed or data corrupted)") from e
