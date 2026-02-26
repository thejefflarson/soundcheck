# Test case: cryptographic-failures (A04:2025)
import hashlib
import random
import string

def hash_password(password):
    # BUG: MD5 is cryptographically broken for passwords
    return hashlib.md5(password.encode()).hexdigest()

def generate_reset_token():
    # BUG: random is not cryptographically secure
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))

# BUG: hardcoded encryption key
ENCRYPTION_KEY = b"hardcoded-key-123"

def encrypt(data):
    from Crypto.Cipher import AES
    # BUG: ECB mode leaks patterns
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    return cipher.encrypt(data.ljust(16).encode())
