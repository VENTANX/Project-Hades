# Author: OUSSAMA ASLOUJ
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

def get_key():
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        # Generate a key if one doesn't exist (for dev convenience, ideally should be permanent)
        key = Fernet.generate_key().decode()
        print(f"WARNING: No ENCRYPTION_KEY found. Generated temporary key: {key}")
        # In a real app, you'd want to persist this or enforce it exists
    return key.encode() if isinstance(key, str) else key

_cipher_suite = None

def get_cipher_suite():
    global _cipher_suite
    if _cipher_suite is None:
        key = get_key()
        _cipher_suite = Fernet(key)
    return _cipher_suite

def encrypt(data: str) -> str:
    if not data:
        return ""
    cipher = get_cipher_suite()
    return cipher.encrypt(data.encode()).decode()

def decrypt(data: str) -> str:
    if not data:
        return ""
    cipher = get_cipher_suite()
    return cipher.decrypt(data.encode()).decode()
