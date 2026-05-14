"""password_gen.py — Cryptographically secure password generator."""

import secrets
import string

UPPER   = string.ascii_uppercase
LOWER   = string.ascii_lowercase
DIGITS  = string.digits
SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?"
ALL     = UPPER + LOWER + DIGITS + SPECIAL


def generate_password(length: int = 15) -> str:
    if length < 8:
        raise ValueError("Minimum length is 8.")
    mandatory = [secrets.choice(UPPER), secrets.choice(LOWER), secrets.choice(DIGITS), secrets.choice(SPECIAL)]
    rest = [secrets.choice(ALL) for _ in range(length - 4)]
    arr  = mandatory + rest
    for i in range(len(arr) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    return "".join(arr)
