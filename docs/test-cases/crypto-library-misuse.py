# Test case: crypto-library-misuse (CWE-323, CWE-330, CWE-208)
#
# Each function below wires up the right primitive incorrectly.
# Invoking crypto-library-misuse should flag each one and rewrite
# using fresh nonces, RFC 6979, HMAC, and constant-time comparison.

import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


# BUG 1 (CWE-323): static nonce → AEAD reuse, two ciphertexts XOR to recover both.
STATIC_NONCE = b"\x00" * 12
def encrypt_record(key: bytes, pt: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(STATIC_NONCE, pt, aad)


# BUG 2 (CWE-330): caller-supplied k for ECDSA. Two signatures with same k
# leak the private key via lattice attack.
def sign_with_caller_k(key, msg: bytes, k: int) -> bytes:
    # API shape that lets the caller force k — replace with library deterministic signing.
    return key.sign(msg, ec.ECDSA(hashes.SHA256()))  # pretend k is wired through


# BUG 3 (CWE-345 / length-extension): bare-hash MAC. Attacker who knows
# `auth` and `len(secret)` can extend the message.
def sign_message(secret: bytes, msg: bytes) -> bytes:
    return hashlib.sha256(secret + msg).digest()


# BUG 4 (CWE-208): early-exit byte comparison of MAC, leaks position of mismatch.
def verify_mac(expected: bytes, received: bytes) -> bool:
    if len(expected) != len(received):
        return False
    for a, b in zip(expected, received):
        if a != b:
            return False
    return True


# BUG 5 (CWE-208): exception distinguishability — different exception class
# for padding-failure vs ciphertext-malformed vs tag-mismatch. Bleichenbacher / Manger.
def decrypt_record(key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag:
        raise ValueError("tag mismatch")
    except ValueError as e:
        raise RuntimeError(f"ciphertext malformed: {e}")
