"""TOTP second factor (totp.py) — stdlib RFC 6238 implementation.

No database or Flask involved; these run in the pure-python suite.
"""
import base64
import hashlib
import hmac
import struct

import totp


def _reference_code(secret_b32, counter, digits=6):
    """Independent HOTP implementation to check totp._hotp against."""
    key = totp._b32decode(secret_b32)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def test_generate_secret_is_valid_base32():
    secret = totp.generate_secret()
    # Decodes without error and yields the requested 20 bytes of entropy.
    assert len(totp._b32decode(secret)) == 20
    # base32 alphabet only, no padding.
    assert set(secret) <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')


def test_verify_accepts_current_code():
    secret = totp.generate_secret()
    at = 1_700_000_000
    code = _reference_code(secret, at // totp.DEFAULT_PERIOD)
    assert totp.verify(secret, code, at=at) is True


def test_verify_accepts_adjacent_window():
    secret = totp.generate_secret()
    at = 1_700_000_000
    counter = at // totp.DEFAULT_PERIOD
    # Previous and next step must be accepted (±30s clock skew tolerance).
    assert totp.verify(secret, _reference_code(secret, counter - 1), at=at)
    assert totp.verify(secret, _reference_code(secret, counter + 1), at=at)


def test_verify_rejects_out_of_window_code():
    secret = totp.generate_secret()
    at = 1_700_000_000
    counter = at // totp.DEFAULT_PERIOD
    # Two steps away is outside the default ±1 window.
    assert totp.verify(secret, _reference_code(secret, counter + 2), at=at) is False


def test_verify_rejects_wrong_and_malformed_codes():
    secret = totp.generate_secret()
    at = 1_700_000_000
    assert totp.verify(secret, '000000', at=at) is False
    assert totp.verify(secret, None, at=at) is False
    assert totp.verify(secret, '', at=at) is False
    assert totp.verify(secret, 'abcdef', at=at) is False   # non-digit
    assert totp.verify(secret, '12345', at=at) is False    # wrong length
    assert totp.verify('', '123456', at=at) is False       # no secret


def test_verify_tolerates_spaces_in_code():
    secret = totp.generate_secret()
    at = 1_700_000_000
    code = _reference_code(secret, at // totp.DEFAULT_PERIOD)
    spaced = code[:3] + ' ' + code[3:]
    assert totp.verify(secret, spaced, at=at) is True


def test_verify_malformed_secret_returns_false_not_raises():
    # A corrupt stored secret must fail closed, never raise into the request.
    assert totp.verify('not!valid!base32!', '123456', at=1) is False


def test_provisioning_uri_shape():
    uri = totp.provisioning_uri('JBSWY3DPEHPK3PXP', 'alice', issuer='PCAP Analyzer')
    assert uri.startswith('otpauth://totp/')
    assert 'secret=JBSWY3DPEHPK3PXP' in uri
    assert 'issuer=PCAP+Analyzer' in uri
    assert 'PCAP%20Analyzer%3Aalice' in uri  # label is issuer:account, url-encoded
