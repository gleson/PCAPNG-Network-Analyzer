"""
TLS handshake parsers.

Self-contained helpers extracted from pcap_analyzer/_core.py. The module
purposely has no dependency on PCAPAnalyzer so it can be reused by aggregators
and post-detectors without circular imports.

Three parsers live here:

    parse_client_hello(record) -> dict | None
        Returns client_version, effective_version, sni, ja3, ja3_md5.

    parse_server_hello(record) -> dict | None
        Returns server_version, effective_version, cipher, ja3s, ja3s_md5.

    parse_certificate_message(record) -> list[dict]
        Returns a list of certs (leaf first). Each cert has cn, sans, issuer_cn,
        not_before (ISO 8601), not_after (ISO 8601), self_signed (bool),
        is_lets_encrypt (bool), fingerprint_sha256.

All three are tolerant: malformed records return None / empty list rather than
raising. record bytes are the TLS handshake message *after* the 5-byte record
header has been stripped.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from .constants import JA3_GREASE


# JA4 protocol+version slot: TLS record uses TCP in our capture path; QUIC
# would be 'q'. The version comes from supported_versions (TLS 1.3) when
# present, else the record version. Mapped to the 2-char codes per FoxIO
# spec (https://github.com/FoxIO-LLC/ja4).
_JA4_VER_MAP = {
    0x0304: '13',
    0x0303: '12',
    0x0302: '11',
    0x0301: '10',
    0x0300: 's3',
    0x0002: 's2',
}


def _ja4_version(v):
    return _JA4_VER_MAP.get(v, '00')


def _ja4_alpn_pair(alpn_list):
    """JA4 ALPN slot: first + last char of first ALPN proto, lowercase.

    Empty ALPN → '00'. Single-char ALPN → the char doubled. Non-printable
    bytes are rendered as '99' per FoxIO spec."""
    if not alpn_list:
        return '00'
    s = alpn_list[0] or ''
    if not s:
        return '00'
    first, last = s[0], s[-1]
    # FoxIO: if the first character isn't an ASCII printable char, use '99'.
    if not (32 <= ord(first) < 127 and 32 <= ord(last) < 127):
        return '99'
    return (first + last).lower()


def _ja4_hash12(parts):
    """sha256 first 12 hex chars of comma-joined parts. Empty → 12 zeros."""
    if not parts:
        return '000000000000'
    return hashlib.sha256(','.join(parts).encode()).hexdigest()[:12]


def _ja4_hash12_raw(s):
    if not s:
        return '000000000000'
    return hashlib.sha256(s.encode()).hexdigest()[:12]


# === ClientHello / ServerHello (JA3 / JA3S / SNI) ============================

def parse_client_hello(record):
    """Parse a TLS ClientHello handshake. record[0] must be 0x01."""
    try:
        if len(record) < 38 or record[0] != 0x01:
            return None
        hs_len = (record[1] << 16) | (record[2] << 8) | record[3]
        body = record[4:4 + hs_len]
        if len(body) < 38:
            return None

        client_version = (body[0] << 8) | body[1]
        sid_len = body[34]
        idx = 35 + sid_len
        if idx + 2 > len(body):
            return None

        cs_len = (body[idx] << 8) | body[idx + 1]
        idx += 2
        if idx + cs_len > len(body):
            return None
        ciphers = []
        for i in range(0, cs_len, 2):
            v = (body[idx + i] << 8) | body[idx + i + 1]
            if v not in JA3_GREASE:
                ciphers.append(v)
        idx += cs_len

        if idx + 1 > len(body):
            return None
        cm_len = body[idx]
        idx += 1 + cm_len

        extensions, curves, formats = [], [], []
        sni = None
        supported_versions = None
        alpn = []
        sig_algs = []  # signature_algorithms (ext 0x000d), order preserved
        has_ech = False  # encrypted_client_hello (ext 0xfe0d, draft-ietf-tls-esni)

        if idx + 2 <= len(body):
            ext_total = (body[idx] << 8) | body[idx + 1]
            idx += 2
            ext_end = min(idx + ext_total, len(body))
            while idx + 4 <= ext_end:
                ext_type = (body[idx] << 8) | body[idx + 1]
                ext_len = (body[idx + 2] << 8) | body[idx + 3]
                idx += 4
                if idx + ext_len > ext_end:
                    break
                ext_data = body[idx:idx + ext_len]
                idx += ext_len
                if ext_type not in JA3_GREASE:
                    extensions.append(ext_type)
                if ext_type == 0xfe0d:
                    has_ech = True
                # server_name (SNI)
                if ext_type == 0x0000 and len(ext_data) >= 5:
                    if ext_data[2] == 0x00:
                        name_len = (ext_data[3] << 8) | ext_data[4]
                        if 5 + name_len <= len(ext_data):
                            try:
                                sni = ext_data[5:5 + name_len].decode(
                                    'utf-8', errors='ignore',
                                )
                            except Exception:
                                sni = None
                # supported_groups (curves)
                elif ext_type == 0x000a and len(ext_data) >= 2:
                    grp_len = (ext_data[0] << 8) | ext_data[1]
                    for i in range(2, min(2 + grp_len, len(ext_data)), 2):
                        if i + 2 <= len(ext_data):
                            v = (ext_data[i] << 8) | ext_data[i + 1]
                            if v not in JA3_GREASE:
                                curves.append(v)
                # ec_point_formats
                elif ext_type == 0x000b and len(ext_data) >= 1:
                    fmt_len = ext_data[0]
                    for i in range(1, min(1 + fmt_len, len(ext_data))):
                        formats.append(ext_data[i])
                # signature_algorithms (ext 0x000d) — JA4_c hashes them in
                # the order seen on the wire, alongside the sorted ext list.
                elif ext_type == 0x000d and len(ext_data) >= 2:
                    sa_len = (ext_data[0] << 8) | ext_data[1]
                    for i in range(2, min(2 + sa_len, len(ext_data)), 2):
                        if i + 2 <= len(ext_data):
                            v = (ext_data[i] << 8) | ext_data[i + 1]
                            if v not in JA3_GREASE:
                                sig_algs.append(v)
                # supported_versions (TLS 1.3 real version)
                elif ext_type == 0x002b and len(ext_data) >= 1:
                    sv_len = ext_data[0]
                    versions = []
                    for i in range(1, min(1 + sv_len, len(ext_data)), 2):
                        if i + 2 <= len(ext_data):
                            v = (ext_data[i] << 8) | ext_data[i + 1]
                            if v not in JA3_GREASE:
                                versions.append(v)
                    if versions:
                        supported_versions = versions
                # application_layer_protocol_negotiation (ALPN)
                elif ext_type == 0x0010 and len(ext_data) >= 2:
                    list_len = (ext_data[0] << 8) | ext_data[1]
                    j = 2
                    end = min(2 + list_len, len(ext_data))
                    while j < end:
                        proto_len = ext_data[j]
                        j += 1
                        if j + proto_len > end:
                            break
                        try:
                            alpn.append(
                                ext_data[j:j + proto_len].decode(
                                    'ascii', errors='ignore',
                                )
                            )
                        except Exception:
                            pass
                        j += proto_len

        ja3_str = "{},{},{},{},{}".format(
            client_version,
            '-'.join(str(c) for c in ciphers),
            '-'.join(str(e) for e in extensions),
            '-'.join(str(c) for c in curves),
            '-'.join(str(f) for f in formats),
        )
        ja3_md5 = hashlib.md5(ja3_str.encode()).hexdigest()
        effective_version = (max(supported_versions)
                             if supported_versions
                             else client_version)

        # JA4 (FoxIO spec). a-part: proto/ver/sni/cipher_count/ext_count/alpn.
        # b-part: sha256[:12] of ciphers sorted ascending, comma-joined as
        # 4-char hex. c-part: sha256[:12] of (extensions excluding SNI/ALPN,
        # sorted ascending) + '_' + sig_algs in order, both as 4-char hex.
        ja4_ver = _ja4_version(effective_version)
        cipher_count = min(len(ciphers), 99)
        ext_count = min(len(extensions), 99)
        ja4_a = (
            't' + ja4_ver
            + ('d' if sni else 'i')
            + f'{cipher_count:02d}'
            + f'{ext_count:02d}'
            + _ja4_alpn_pair(alpn)
        )
        cipher_hex = [f'{c:04x}' for c in sorted(ciphers)]
        ja4_b = _ja4_hash12(cipher_hex)
        ja4_exts = sorted(e for e in extensions if e not in (0x0000, 0x0010))
        ext_hex = [f'{e:04x}' for e in ja4_exts]
        sa_hex = [f'{s:04x}' for s in sig_algs]
        ja4_c_input = ','.join(ext_hex)
        if sa_hex:
            ja4_c_input += '_' + ','.join(sa_hex)
        ja4_c = _ja4_hash12_raw(ja4_c_input) if ja4_c_input else '000000000000'
        ja4 = f'{ja4_a}_{ja4_b}_{ja4_c}'

        return {
            'client_version': client_version,
            'effective_version': effective_version,
            'sni': sni,
            'alpn': alpn,
            'ja3': ja3_str,
            'ja3_md5': ja3_md5,
            'ja4': ja4,
            'has_ech': has_ech,
        }
    except Exception:
        return None


def parse_server_hello(record):
    """Parse a TLS ServerHello -> JA3S. record[0] must be 0x02."""
    try:
        if len(record) < 38 or record[0] != 0x02:
            return None
        hs_len = (record[1] << 16) | (record[2] << 8) | record[3]
        body = record[4:4 + hs_len]
        if len(body) < 38:
            return None
        server_version = (body[0] << 8) | body[1]
        sid_len = body[34]
        idx = 35 + sid_len
        if idx + 2 > len(body):
            return None
        cipher = (body[idx] << 8) | body[idx + 1]
        idx += 2
        if idx + 1 > len(body):
            return None
        idx += 1  # compression_method (1 byte)

        extensions = []
        supported_version = None
        alpn = []
        if idx + 2 <= len(body):
            ext_total = (body[idx] << 8) | body[idx + 1]
            idx += 2
            ext_end = min(idx + ext_total, len(body))
            while idx + 4 <= ext_end:
                ext_type = (body[idx] << 8) | body[idx + 1]
                ext_len = (body[idx + 2] << 8) | body[idx + 3]
                idx += 4
                if idx + ext_len > ext_end:
                    break
                ext_data = body[idx:idx + ext_len]
                idx += ext_len
                if ext_type not in JA3_GREASE:
                    extensions.append(ext_type)
                if ext_type == 0x002b and len(ext_data) == 2:
                    supported_version = (ext_data[0] << 8) | ext_data[1]
                elif ext_type == 0x0010 and len(ext_data) >= 2:
                    list_len = (ext_data[0] << 8) | ext_data[1]
                    j = 2
                    end = min(2 + list_len, len(ext_data))
                    while j < end:
                        proto_len = ext_data[j]
                        j += 1
                        if j + proto_len > end:
                            break
                        try:
                            alpn.append(
                                ext_data[j:j + proto_len].decode(
                                    'ascii', errors='ignore',
                                )
                            )
                        except Exception:
                            pass
                        j += proto_len

        ja3s_str = "{},{},{}".format(
            server_version,
            cipher,
            '-'.join(str(e) for e in extensions),
        )
        ja3s_md5 = hashlib.md5(ja3s_str.encode()).hexdigest()
        effective_version = supported_version or server_version

        # JA4S (FoxIO spec): proto/ver/extcount/alpn '_' cipher_hex '_' sha12(exts_in_order).
        ja4s_ver = _ja4_version(effective_version)
        ja4s_ext_count = min(len(extensions), 99)
        ja4s_a = (
            't' + ja4s_ver
            + f'{ja4s_ext_count:02d}'
            + _ja4_alpn_pair(alpn)
        )
        ja4s_b = f'{cipher:04x}'
        ext_hex = [f'{e:04x}' for e in extensions]
        ja4s_c = _ja4_hash12(ext_hex)
        ja4s = f'{ja4s_a}_{ja4s_b}_{ja4s_c}'

        return {
            'server_version': server_version,
            'effective_version': effective_version,
            'cipher': cipher,
            'alpn': alpn,
            'ja3s': ja3s_str,
            'ja3s_md5': ja3s_md5,
            'ja4s': ja4s,
        }
    except Exception:
        return None


# === X.509 Certificate parsing ===============================================
#
# We deliberately avoid pulling in `cryptography` here — it adds a heavy
# native dependency for what is, in practice, a thin set of fields
# (CN, SANs, issuer, validity dates). The DER walker below extracts only
# what the cert-based detectors need; anything malformed yields a partial
# dict and the detector treats missing fields as "unknown" rather than
# false-positive material.

# OIDs we care about, encoded as already-resolved tuples for fast match.
_OID_CN = (2, 5, 4, 3)              # commonName
_OID_ORG = (2, 5, 4, 10)            # organizationName
_OID_SAN = (2, 5, 29, 17)           # subjectAltName extension


class _DERReadError(Exception):
    pass


def _read_len(buf, idx):
    if idx >= len(buf):
        raise _DERReadError('truncated length')
    first = buf[idx]
    idx += 1
    if first < 0x80:
        return first, idx
    n = first & 0x7F
    if n == 0 or idx + n > len(buf):
        raise _DERReadError('bad length')
    length = 0
    for _ in range(n):
        length = (length << 8) | buf[idx]
        idx += 1
    return length, idx


def _read_tlv(buf, idx):
    """Return (tag, contents, next_idx). Tag is the raw first byte."""
    if idx >= len(buf):
        raise _DERReadError('truncated tag')
    tag = buf[idx]
    idx += 1
    length, idx = _read_len(buf, idx)
    if idx + length > len(buf):
        raise _DERReadError('truncated value')
    return tag, buf[idx:idx + length], idx + length


def _decode_oid(buf):
    if not buf:
        return ()
    first = buf[0]
    parts = [first // 40, first % 40]
    val = 0
    for b in buf[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(val)
            val = 0
    return tuple(parts)


def _decode_string(tag, buf):
    # PrintableString, UTF8String, IA5String, T61String, BMPString — best effort.
    if tag == 0x1E:  # BMPString (UTF-16BE)
        try:
            return buf.decode('utf-16-be', errors='ignore')
        except Exception:
            return ''
    try:
        return buf.decode('utf-8', errors='ignore')
    except Exception:
        try:
            return buf.decode('latin-1', errors='ignore')
        except Exception:
            return ''


def _decode_time(tag, buf):
    """UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) -> ISO 8601 string."""
    s = buf.decode('latin-1', errors='ignore').rstrip('Z')
    fmt = None
    try:
        if tag == 0x17:
            # YYMMDDhhmmss; YY < 50 -> 20YY, else 19YY (RFC 5280).
            yy = int(s[:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            rest = s[2:]
            dt = datetime.strptime(f'{year:04d}{rest}', '%Y%m%d%H%M%S')
        else:
            dt = datetime.strptime(s, '%Y%m%d%H%M%S')
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        return s


def _walk_name(name_seq):
    """Subject/Issuer is a SEQUENCE of SETs of AttributeTypeAndValue. Returns
    dict OID -> value (first occurrence wins)."""
    out = {}
    idx = 0
    while idx < len(name_seq):
        try:
            tag, set_contents, idx = _read_tlv(name_seq, idx)
            if tag != 0x31:  # SET
                continue
            j = 0
            while j < len(set_contents):
                stag, attr, j = _read_tlv(set_contents, j)
                if stag != 0x30:  # SEQUENCE
                    continue
                k = 0
                otag, oid_buf, k = _read_tlv(attr, k)
                if otag != 0x06:
                    continue
                vtag, val_buf, k = _read_tlv(attr, k)
                oid = _decode_oid(oid_buf)
                if oid not in out:
                    out[oid] = _decode_string(vtag, val_buf)
        except _DERReadError:
            break
    return out


def _walk_sans(ext_value):
    """Subject Alternative Name extension. Returns (dns_names, ip_addresses).

    DNS SANs come from context tag [2] (0x82) as IA5String. IP SANs come from
    context tag [7] (0x87) as 4 raw bytes (IPv4) or 16 raw bytes (IPv6).
    """
    sans = []
    ip_sans = []
    try:
        tag, seq_contents, _ = _read_tlv(ext_value, 0)
        if tag != 0x30:
            return sans, ip_sans
        idx = 0
        while idx < len(seq_contents):
            try:
                gtag, gval, idx = _read_tlv(seq_contents, idx)
            except _DERReadError:
                break
            if gtag == 0x82:
                try:
                    sans.append(gval.decode('utf-8', errors='ignore'))
                except Exception:
                    pass
            elif gtag == 0x87:
                if len(gval) == 4:
                    ip_sans.append('.'.join(str(b) for b in gval))
                elif len(gval) == 16:
                    # IPv6 as 8 groups of 16-bit hex (uncompressed; readability
                    # over canonicalization — caller compares string-equal).
                    ip_sans.append(':'.join(
                        f'{(gval[i] << 8) | gval[i + 1]:x}'
                        for i in range(0, 16, 2)
                    ))
    except _DERReadError:
        pass
    return sans, ip_sans


def _parse_certificate(der):
    """Parse a DER-encoded X.509 certificate. Returns dict with cn, sans,
    issuer_cn, issuer_org, not_before, not_after, fingerprint_sha256."""
    info = {
        'cn': '',
        'sans': [],
        'ip_sans': [],
        'issuer_cn': '',
        'issuer_org': '',
        'not_before': '',
        'not_after': '',
        'fingerprint_sha256': hashlib.sha256(der).hexdigest(),
    }
    try:
        tag, cert_seq, _ = _read_tlv(der, 0)
        if tag != 0x30:
            return info
        # tbsCertificate
        ttag, tbs, _ = _read_tlv(cert_seq, 0)
        if ttag != 0x30:
            return info

        idx = 0
        # Optional [0] EXPLICIT Version
        if idx < len(tbs) and tbs[idx] == 0xA0:
            _, _, idx = _read_tlv(tbs, idx)
        # CertificateSerialNumber (INTEGER) — skip
        _, _, idx = _read_tlv(tbs, idx)
        # AlgorithmIdentifier — skip
        _, _, idx = _read_tlv(tbs, idx)
        # Issuer (Name)
        _, issuer_buf, idx = _read_tlv(tbs, idx)
        # Validity
        _, validity_buf, idx = _read_tlv(tbs, idx)
        # Subject (Name)
        _, subject_buf, idx = _read_tlv(tbs, idx)
        # subjectPublicKeyInfo — skip
        _, _, idx = _read_tlv(tbs, idx)

        # Walk extensions (optional [3] EXPLICIT)
        san_list = []
        ip_san_list = []
        while idx < len(tbs):
            try:
                etag, ext_outer, idx = _read_tlv(tbs, idx)
            except _DERReadError:
                break
            if etag != 0xA3:
                continue
            # ext_outer is SEQUENCE OF Extension
            try:
                _, ext_seq, _ = _read_tlv(ext_outer, 0)
            except _DERReadError:
                break
            j = 0
            while j < len(ext_seq):
                try:
                    _, ext_buf, j = _read_tlv(ext_seq, j)
                except _DERReadError:
                    break
                k = 0
                try:
                    _, oid_buf, k = _read_tlv(ext_buf, k)
                except _DERReadError:
                    continue
                oid = _decode_oid(oid_buf)
                # Optional BOOLEAN critical
                if k < len(ext_buf) and ext_buf[k] == 0x01:
                    _, _, k = _read_tlv(ext_buf, k)
                try:
                    _, octet_buf, _ = _read_tlv(ext_buf, k)
                except _DERReadError:
                    continue
                if oid == _OID_SAN:
                    san_list, ip_san_list = _walk_sans(octet_buf)
            break

        issuer = _walk_name(issuer_buf)
        subject = _walk_name(subject_buf)

        # Validity = SEQUENCE { notBefore Time, notAfter Time }
        try:
            vidx = 0
            ntag, nb, vidx = _read_tlv(validity_buf, vidx)
            info['not_before'] = _decode_time(ntag, nb)
            ntag, na, _ = _read_tlv(validity_buf, vidx)
            info['not_after'] = _decode_time(ntag, na)
        except _DERReadError:
            pass

        info['cn'] = subject.get(_OID_CN, '')
        info['issuer_cn'] = issuer.get(_OID_CN, '')
        info['issuer_org'] = issuer.get(_OID_ORG, '')
        info['sans'] = san_list
        info['ip_sans'] = ip_san_list
    except _DERReadError:
        pass
    except Exception:
        pass

    info['self_signed'] = bool(
        info['cn']
        and info['issuer_cn']
        and info['cn'] == info['issuer_cn']
    )
    issuer_blob = (info['issuer_cn'] + ' ' + info['issuer_org']).lower()
    info['is_lets_encrypt'] = 'let' in issuer_blob and 'encrypt' in issuer_blob
    return info


def parse_certificate_message(record):
    """Parse a TLS handshake Certificate message (record[0] == 0x0B).

    Returns a list of certificate dicts (leaf first), one per ASN1Cert. Each
    dict has the shape produced by _parse_certificate. Empty list on any error
    or if the message is not a Certificate.
    """
    try:
        if len(record) < 7 or record[0] != 0x0B:
            return []
        hs_len = (record[1] << 16) | (record[2] << 8) | record[3]
        body = record[4:4 + hs_len]
        if len(body) < 3:
            return []
        list_len = (body[0] << 16) | (body[1] << 8) | body[2]
        if list_len <= 0 or list_len > len(body) - 3:
            return []
        idx = 3
        end = 3 + list_len
        certs = []
        while idx + 3 <= end:
            cert_len = (body[idx] << 16) | (body[idx + 1] << 8) | body[idx + 2]
            idx += 3
            if cert_len <= 0 or idx + cert_len > end:
                break
            der = bytes(body[idx:idx + cert_len])
            idx += cert_len
            certs.append(_parse_certificate(der))
        return certs
    except Exception:
        return []
