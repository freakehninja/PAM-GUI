"""
vault.py — Encrypted Credential Vault
AES-128-CBC + HMAC-SHA256 via Fernet. Key derived via PBKDF2.
Master password read from VAULT_MASTER_PASSWORD env var.
"""

import os
import json
import base64
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_DIR  = Path("vault")
VAULT_FILE = VAULT_DIR / "credentials.enc"
SALT_FILE  = VAULT_DIR / "vault.salt"
_fernet    = None


def _ensure():
    VAULT_DIR.mkdir(exist_ok=True)


def _get_salt():
    _ensure()
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    return salt


def _get_fernet():
    global _fernet
    if _fernet:
        return _fernet
    master = os.environ.get("VAULT_MASTER_PASSWORD")
    if not master:
        raise RuntimeError("VAULT_MASTER_PASSWORD environment variable not set.")
    salt = _get_salt()
    kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390_000)
    key  = base64.urlsafe_b64encode(kdf.derive(master.encode()))
    _fernet = Fernet(key)
    return _fernet


def _load():
    if not VAULT_FILE.exists():
        return {}
    try:
        return json.loads(_get_fernet().decrypt(VAULT_FILE.read_bytes()).decode())
    except Exception:
        raise RuntimeError("Failed to decrypt vault. Wrong master password or corrupted file.")


def _save(d):
    _ensure()
    VAULT_FILE.write_bytes(_get_fernet().encrypt(json.dumps(d).encode()))


def _key(hostname, username):
    return f"{hostname}::{username}"


class CredentialVault:
    def store(self, hostname, username, password):
        d = _load()
        d[_key(hostname, username)] = password
        _save(d)

    def retrieve(self, hostname, username):
        return _load().get(_key(hostname, username))

    def delete(self, hostname, username):
        d = _load()
        k = _key(hostname, username)
        if k in d:
            del d[k]
            _save(d)

    def list_entries(self):
        return [tuple(k.split("::", 1)) for k in _load()]
