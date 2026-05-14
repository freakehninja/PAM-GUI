"""
totp_util.py — Real TOTP implementation (RFC 6238)
Uses Python stdlib only (hmac, hashlib, struct) — no pyotp needed.
Compatible with Microsoft Authenticator and Google Authenticator.
"""

import hmac
import hashlib
import struct
import time
import base64
import os
import hashlib as hl


# ─── TOTP (RFC 6238) ──────────────────────────────────────────────────────────

def generate_secret() -> str:
    """Generate a 32-character base32 secret for TOTP."""
    random_bytes = os.urandom(20)
    return base64.b32encode(random_bytes).decode("utf-8")


def get_otp_uri(secret: str, username: str, issuer: str = "PAMVault") -> str:
    """Return the otpauth:// URI for QR code generation."""
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def _hotp(secret: str, counter: int) -> str:
    """HMAC-based OTP (RFC 4226)."""
    key = base64.b32decode(secret.upper().replace(" ", ""))
    msg = struct.pack(">Q", counter)
    h   = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code   = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**6).zfill(6)


def get_totp(secret: str, timestamp: float = None) -> str:
    """Return the current 6-digit TOTP code."""
    ts = timestamp if timestamp is not None else time.time()
    return _hotp(secret, int(ts) // 30)


def verify_totp(code: str, secret: str, window: int = 1) -> bool:
    """
    Verify a TOTP code with a tolerance window of ±window steps (±30s each).
    Returns True if the code matches any step in the window.
    """
    if not code or len(code) != 6 or not code.isdigit():
        return False
    ts = int(time.time()) // 30
    for step in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret, ts + step), code):
            return True
    return False


# ─── Password hashing (PBKDF2-HMAC-SHA256) ───────────────────────────────────

def hash_password(password: str) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 + random salt."""
    salt = os.urandom(16)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 390_000)
    return base64.b64encode(salt + dk).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored PBKDF2 hash."""
    try:
        raw  = base64.b64decode(stored_hash.encode())
        salt = raw[:16]
        stored_dk = raw[16:]
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 390_000)
        return hmac.compare_digest(dk, stored_dk)
    except Exception:
        return False
