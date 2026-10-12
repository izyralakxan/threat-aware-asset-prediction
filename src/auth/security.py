"""
Authentication primitives, standard library only.

Passwords  scrypt (memory-hard key derivation) with a random 16-byte salt per
           user; comparisons in constant time.
MFA        TOTP, RFC 6238 (HMAC-SHA1, 6 digits, 30-second steps): the
           standard used by Google Authenticator, Microsoft Authenticator,
           Authy and others. One step of clock drift is accepted either way,
           and a code cannot be used twice.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}

TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_DRIFT_STEPS = 1
ISSUER = "ThreatAware Exposure"

MIN_PASSWORD_LENGTH = 12
COMMON_PASSWORDS = {
    "password1234", "123456789012", "qwertyuiop12", "letmein12345", "welcome12345",
    "administrator", "passw0rd1234", "iloveyou1234", "changeme1234", "admin1234567",
}


# ==============================
# Passwords
# ==============================

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
    except (AttributeError, ValueError):
        return False
    if scheme != "scrypt":
        return False
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), **SCRYPT)
    return hmac.compare_digest(digest.hex(), digest_hex)


def password_problems(password, username=""):
    """Reasons a new password is not acceptable (empty list = acceptable)."""
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"at least {MIN_PASSWORD_LENGTH} characters")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("too common")
    classes = sum([any(c.islower() for c in password), any(c.isupper() for c in password),
                   any(c.isdigit() for c in password), any(not c.isalnum() for c in password)])
    if classes < 3:
        problems.append("use at least three of: lowercase, uppercase, digits, symbols")
    return problems


def temporary_password():
    """Random one-time password for new accounts and resets."""
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(10)) + "-" + str(secrets.randbelow(90) + 10) + "!"


# ==============================
# TOTP (RFC 6238)
# ==============================

def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** TOTP_DIGITS).zfill(TOTP_DIGITS)


def current_code(secret, at=None):
    return _code(secret, int((at or time.time()) // TOTP_STEP))


def verify_totp(secret, code, last_counter=None, at=None):
    """
    Returns the matching time-step counter, or None if the code is wrong or
    was already used (replay protection: counter must be newer than the last
    accepted one).
    """
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    now = int((at or time.time()) // TOTP_STEP)
    for counter in range(now - TOTP_DRIFT_STEPS, now + TOTP_DRIFT_STEPS + 1):
        if hmac.compare_digest(_code(secret, counter), code):
            if last_counter is not None and counter <= last_counter:
                return None
            return counter
    return None


def provisioning_uri(secret, username):
    """otpauth:// link encoded in the enrolment QR code."""
    label = urllib.parse.quote(f"{ISSUER}:{username}")
    query = urllib.parse.urlencode({"secret": secret, "issuer": ISSUER,
                                    "digits": TOTP_DIGITS, "period": TOTP_STEP})
    return f"otpauth://totp/{label}?{query}"
