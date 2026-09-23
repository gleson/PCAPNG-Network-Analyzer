"""
Time-based one-time passwords (RFC 6238), stdlib only.

Used as a step-up second factor when an admin creates or enables a
suppression rule — an action that can hide alerts, so we want proof that a
live human with the enrolled device (not just a stolen session cookie or a
leaked password) authorised it.

No third-party dependency: HOTP/TOTP is a short HMAC-SHA1 construction, and
the provisioning URI consumed by Google Authenticator / Authy / 1Password is
just a formatted `otpauth://` string. Keeping it dependency-free avoids
pulling `pyotp`/`qrcode` into the image for ~40 lines of well-specified code.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse


DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30          # seconds per TOTP step (Authenticator default)
DEFAULT_VALID_WINDOW = 1     # accept the code from the adjacent steps too,
                             # tolerating up to ±30s of clock skew


def generate_secret(num_bytes=20):
    """Return a fresh base32 secret (no padding) for a new enrollment.

    20 random bytes = 160 bits, the RFC 4226 recommended key length and what
    Authenticator apps expect.
    """
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode('ascii').rstrip('=')


def _b32decode(secret_b32):
    """Decode a user/stored base32 secret, tolerating missing padding + case."""
    s = (secret_b32 or '').strip().replace(' ', '').upper()
    # base64.b32decode requires the length to be a multiple of 8; re-pad.
    pad = (-len(s)) % 8
    return base64.b32decode(s + ('=' * pad))


def _hotp(secret_b32, counter, digits=DEFAULT_DIGITS):
    key = _b32decode(secret_b32)
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    bincode = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(bincode % (10 ** digits)).zfill(digits)


def verify(secret_b32, code, valid_window=DEFAULT_VALID_WINDOW,
           digits=DEFAULT_DIGITS, period=DEFAULT_PERIOD, at=None):
    """Return True iff *code* is a valid TOTP for *secret_b32* right now.

    Constant-time compared against each candidate step in the window so a
    correct-prefix code can't be distinguished by timing.
    """
    if not secret_b32 or code is None:
        return False
    code = str(code).strip().replace(' ', '')
    if not code.isdigit() or len(code) != digits:
        return False
    now = int(at if at is not None else time.time())
    counter = now // period
    try:
        for drift in range(-valid_window, valid_window + 1):
            candidate = _hotp(secret_b32, counter + drift, digits)
            if hmac.compare_digest(candidate, code):
                return True
    except (ValueError, TypeError, base64.binascii.Error):
        # Malformed stored secret — treat as non-verifying rather than raising
        # into the request path.
        return False
    return False


def provisioning_uri(secret_b32, account_name, issuer='PCAP Analyzer'):
    """Build the otpauth:// URI encoded into the enrollment QR code."""
    label = urllib.parse.quote(f'{issuer}:{account_name}')
    params = urllib.parse.urlencode({
        'secret': secret_b32,
        'issuer': issuer,
        'algorithm': 'SHA1',
        'digits': DEFAULT_DIGITS,
        'period': DEFAULT_PERIOD,
    })
    return f'otpauth://totp/{label}?{params}'


__all__ = ['generate_secret', 'verify', 'provisioning_uri',
           'DEFAULT_DIGITS', 'DEFAULT_PERIOD']
