"""
SSH KEXINIT parser + HASSH / HASSH-Server fingerprint generator.

The KEXINIT message (msg type 20, RFC 4253 §7.1) is sent by both peers
right after the version-string exchange and BEFORE encryption is enabled,
so it sits in plaintext on the wire. The HASSH fingerprint hashes the
algorithm-preference lists each side advertises, identifying the client
or server SSH stack the same way JA3 identifies a TLS stack.

    HASSH        = md5(kex;enc_c2s;mac_c2s;cmp_c2s)
    HASSH-Server = md5(kex;enc_s2c;mac_s2c;cmp_s2c)

Reference: https://github.com/salesforce/hassh
"""

from __future__ import annotations

import hashlib


SSH_MSG_KEXINIT = 20


def _read_string(buf, idx):
    """SSH 'string' type: uint32 length + bytes. Returns (value, new_idx) or
    raises ValueError on truncation/inconsistency."""
    if idx + 4 > len(buf):
        raise ValueError('truncated string length')
    length = (buf[idx] << 24) | (buf[idx + 1] << 16) | (buf[idx + 2] << 8) | buf[idx + 3]
    idx += 4
    if idx + length > len(buf):
        raise ValueError('truncated string body')
    value = buf[idx:idx + length].decode('ascii', errors='ignore')
    return value, idx + length


def parse_kexinit(payload):
    """Parse a KEXINIT *payload* (already stripped of the binary packet
    framing) and return a dict of the 10 name-lists, plus hassh and
    hassh_server md5s. Returns None on any parse error."""
    try:
        if len(payload) < 1 + 16 + 4:
            return None
        if payload[0] != SSH_MSG_KEXINIT:
            return None
        # Skip cookie (16 random bytes).
        idx = 1 + 16
        kex, idx = _read_string(payload, idx)
        host_keys, idx = _read_string(payload, idx)
        enc_c2s, idx = _read_string(payload, idx)
        enc_s2c, idx = _read_string(payload, idx)
        mac_c2s, idx = _read_string(payload, idx)
        mac_s2c, idx = _read_string(payload, idx)
        cmp_c2s, idx = _read_string(payload, idx)
        cmp_s2c, idx = _read_string(payload, idx)
        lang_c2s, idx = _read_string(payload, idx)
        lang_s2c, idx = _read_string(payload, idx)
    except (ValueError, IndexError):
        return None

    hassh_str = ';'.join([kex, enc_c2s, mac_c2s, cmp_c2s])
    hassh_server_str = ';'.join([kex, enc_s2c, mac_s2c, cmp_s2c])
    return {
        'kex_algorithms': kex,
        'server_host_key_algorithms': host_keys,
        'encryption_c2s': enc_c2s,
        'encryption_s2c': enc_s2c,
        'mac_c2s': mac_c2s,
        'mac_s2c': mac_s2c,
        'compression_c2s': cmp_c2s,
        'compression_s2c': cmp_s2c,
        'languages_c2s': lang_c2s,
        'languages_s2c': lang_s2c,
        'hassh': hashlib.md5(hassh_str.encode()).hexdigest(),
        'hassh_server': hashlib.md5(hassh_server_str.encode()).hexdigest(),
        'hassh_str': hassh_str,
        'hassh_server_str': hassh_server_str,
    }


def extract_kexinit_from_tcp_payload(payload):
    """SSH binary packet header sits at the start of a TCP payload IF this
    is the first message after the version banner. Tries to peel one binary
    packet, returns the inner payload bytes if it looks like a KEXINIT, else
    None. Conservative — leaves multi-segment reassembly to the aggregator.

    Wire format (RFC 4253 §6):
        uint32 packet_length
        byte   padding_length
        byte[] payload (packet_length - padding_length - 1 bytes)
        byte[] padding
    """
    if len(payload) < 6:
        return None
    pkt_len = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]
    # Sanity: KEXINIT is large (algorithm lists) but not huge. Anything below
    # ~64 bytes or above 32KB is almost certainly not an SSH KEXINIT.
    if pkt_len < 60 or pkt_len > 32768:
        return None
    pad_len = payload[4]
    if pad_len > pkt_len:
        return None
    body_len = pkt_len - pad_len - 1
    if 5 + body_len > len(payload):
        return None
    body = payload[5:5 + body_len]
    if not body or body[0] != SSH_MSG_KEXINIT:
        return None
    return body


def looks_like_ssh_banner(payload):
    """Plaintext SSH banner starts with 'SSH-' per RFC 4253 §4.2."""
    return len(payload) >= 4 and payload[:4] == b'SSH-'


__all__ = [
    'parse_kexinit',
    'extract_kexinit_from_tcp_payload',
    'looks_like_ssh_banner',
    'SSH_MSG_KEXINIT',
]
