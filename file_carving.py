"""
File carving from reassembled HTTP flows.

The analyzer's TcpFlowAggregator gives us per-direction reassembled TCP byte
streams keyed by 4-tuple. This module walks those streams, parses HTTP
request/response pairs, and extracts transferred files (downloads via response
bodies, uploads via multipart/form-data request bodies).

Each carved file is hashed (MD5/SHA-1/SHA-256), written to disk, and described
as a dict ready to persist in the carved_files table and look up against
VirusTotal / MalwareBazaar.

Carving is best-effort: malformed HTTP, chunked-encoded streams we can't
re-assemble, or oversized payloads are skipped silently. We err on the side of
"don't crash analyze()" — a parser exception on one flow must not poison the
rest of the run.

Public API:
    carve_http_files(tcp_flows, *, artifacts_dir, max_file_size,
                     min_file_size, allowed_extensions) -> list[dict]
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Iterable, Optional
from urllib.parse import unquote


# Files smaller than this are almost never interesting (favicons, tracking
# pixels) and dominate the volume on a busy capture.
DEFAULT_MIN_FILE_SIZE = 1024  # 1 KB

# Anything past this on a single response is dropped — both because reassembly
# of multi-MB streams from PCAP is unreliable and because submitting huge
# blobs to public hash services is wasteful when the sha256 won't be known.
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# Magic-number signatures by file family. Matching is preferred over
# Content-Type because servers lie / minimal-config installs use
# application/octet-stream for everything.
FILE_SIGNATURES = (
    # (offset, magic_bytes, family, common_ext)
    (0, b'MZ',                       'pe',     'exe'),
    (0, b'\x7fELF',                  'elf',    'bin'),
    (0, b'%PDF-',                    'pdf',    'pdf'),
    (0, b'PK\x03\x04',               'zip',    'zip'),   # also docx/xlsx/jar
    (0, b'\x1f\x8b\x08',             'gzip',   'gz'),
    (0, b'Rar!\x1a\x07',             'rar',    'rar'),
    (0, b'7z\xbc\xaf\x27\x1c',       '7z',     '7z'),
    (0, b'\xd0\xcf\x11\xe0',         'ole',    'doc'),   # legacy Office
    (0, b'#!/',                      'script', 'sh'),
    (0, b'<?php',                    'php',    'php'),
    (0, b'<!DOCTYPE',                'html',   'html'),
    (0, b'<html',                    'html',   'html'),
    (0, b'\xca\xfe\xba\xbe',         'macho',  'bin'),   # Mach-O fat
    (0, b'\xfe\xed\xfa\xce',         'macho',  'bin'),
    (0, b'\xfe\xed\xfa\xcf',         'macho',  'bin'),
    (0, b'\xcf\xfa\xed\xfe',         'macho',  'bin'),
)

# Extensions worth keeping even when no magic matches (e.g. text-based but
# script-y). Lowercased.
INTERESTING_EXTENSIONS = frozenset({
    'exe', 'dll', 'sys', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jse',
    'hta', 'lnk', 'scr', 'cpl',
    'jar', 'class', 'apk', 'ipa', 'dmg', 'iso',
    'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'xlsb', 'ppt', 'pptx', 'pptm',
    'pdf', 'rtf',
    'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'bz2',
    'sh', 'py', 'pl', 'rb', 'php',
    'elf', 'bin',
    'so', 'dylib',
})

# Content-Type prefixes that are noise (HTML pages, CSS, fonts, tracking).
NOISE_CONTENT_TYPES = (
    'text/html', 'text/css', 'image/gif', 'image/png', 'image/jpeg',
    'image/svg', 'image/x-icon', 'font/', 'application/font-',
    'application/javascript', 'text/javascript',
)

# Methods that may carry an uploaded body worth carving.
UPLOAD_METHODS = (b'POST', b'PUT', b'PATCH')

# Header lookup regex (case-insensitive, multi-line). HTTP/1.x header values
# may be quoted; we keep the whole value and post-process per-field.
_HDR_RE = re.compile(rb'^([!-9;-~]+):[ \t]*(.*?)\r?$', re.MULTILINE)


def _parse_headers(header_block: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _HDR_RE.finditer(header_block):
        name = m.group(1).decode('latin-1', errors='ignore').lower()
        value = m.group(2).decode('latin-1', errors='ignore').strip()
        # Don't overwrite — first value wins for repeated headers.
        out.setdefault(name, value)
    return out


def _filename_from_disposition(value: str) -> Optional[str]:
    """Pull a filename out of a Content-Disposition header value."""
    if not value:
        return None
    # RFC 6266: filename*=UTF-8''something  OR  filename="something"
    m = re.search(r'filename\*\s*=\s*[^\'"]*\'\'([^;]+)', value, re.IGNORECASE)
    if m:
        try:
            return unquote(m.group(1).strip().strip('"'))
        except Exception:
            pass
    m = re.search(r'filename\s*=\s*"?([^";]+)"?', value, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def _filename_from_url(path: str) -> Optional[str]:
    if not path:
        return None
    # Drop query string.
    p = path.split('?', 1)[0].split('#', 1)[0]
    if '/' in p:
        p = p.rsplit('/', 1)[-1]
    if not p or p == '/':
        return None
    try:
        p = unquote(p)
    except Exception:
        pass
    # Strip control chars / path separators that could escape the artifacts dir.
    p = re.sub(r'[\x00-\x1f/\\]', '_', p)
    return p[:255] or None


def _identify_by_magic(body: bytes) -> tuple[Optional[str], Optional[str]]:
    """Return (family, suggested_ext) from magic bytes, or (None, None)."""
    for offset, magic, family, ext in FILE_SIGNATURES:
        end = offset + len(magic)
        if len(body) >= end and body[offset:end] == magic:
            return family, ext
    return None, None


def _ext_of(filename: Optional[str]) -> Optional[str]:
    if not filename or '.' not in filename:
        return None
    return filename.rsplit('.', 1)[-1].lower()


def _is_noise_content_type(ct: str) -> bool:
    if not ct:
        return False
    ct = ct.lower().split(';', 1)[0].strip()
    return any(ct.startswith(p) for p in NOISE_CONTENT_TYPES)


def _should_keep(body: bytes,
                 filename: Optional[str],
                 content_type: Optional[str]) -> bool:
    """Filter heuristic: keep if magic matches a known file family, OR the
    filename extension is in INTERESTING_EXTENSIONS. Skip obvious noise.
    """
    if not body:
        return False
    family, _ = _identify_by_magic(body)
    if family:
        return True
    ext = _ext_of(filename)
    if ext and ext in INTERESTING_EXTENSIONS:
        return True
    # Content-Type fallback: only accept executable/document MIME types and
    # reject the obvious noise.
    if content_type:
        ct = content_type.lower().split(';', 1)[0].strip()
        if _is_noise_content_type(ct):
            return False
        if (ct.startswith('application/') and
                ct not in ('application/javascript',
                           'application/x-javascript')):
            return True
    return False


def _iter_http_responses(payload: bytes) -> Iterable[tuple[str, dict, bytes]]:
    """Yield (status_line, headers_dict, body_bytes) for every HTTP response
    framed in *payload*. Skips chunked-transfer responses (would need
    re-assembly we don't implement here).
    """
    idx = 0
    n = len(payload)
    while idx < n:
        start = payload.find(b'HTTP/', idx)
        if start < 0:
            return
        eol = payload.find(b'\r\n', start)
        if eol < 0:
            return
        status_line = payload[start:eol].decode('latin-1', errors='ignore')
        hdr_end = payload.find(b'\r\n\r\n', eol)
        if hdr_end < 0:
            return
        header_block = payload[eol + 2:hdr_end]
        headers = _parse_headers(header_block)
        body_start = hdr_end + 4

        encoding = headers.get('transfer-encoding', '').lower()
        if 'chunked' in encoding:
            # Skip chunked bodies — proper re-assembly is non-trivial and
            # the reassembled flow rarely preserves chunk boundaries.
            idx = body_start
            continue

        clen_s = headers.get('content-length')
        if clen_s and clen_s.isdigit():
            clen = int(clen_s)
            body_end = min(body_start + clen, n)
        else:
            # No Content-Length: best-effort — consume until the next
            # HTTP/ marker or end-of-stream.
            next_resp = payload.find(b'HTTP/', body_start)
            body_end = next_resp if next_resp > 0 else n

        body = payload[body_start:body_end]
        yield status_line, headers, body
        idx = body_end


def _iter_http_uploads(payload: bytes) -> Iterable[tuple[bytes, dict, bytes]]:
    """Yield (method, headers_dict, body_bytes) for POST/PUT/PATCH requests in
    *payload* that carry a non-empty body.
    """
    idx = 0
    n = len(payload)
    while idx < n:
        # Find a candidate request line by scanning for known methods at line start.
        candidate = -1
        for m in UPLOAD_METHODS:
            pos = payload.find(m + b' ', idx)
            if pos == -1:
                continue
            if candidate < 0 or pos < candidate:
                candidate = pos
        if candidate < 0:
            return
        eol = payload.find(b'\r\n', candidate)
        if eol < 0:
            return
        request_line = payload[candidate:eol]
        method = request_line.split(b' ', 1)[0]
        hdr_end = payload.find(b'\r\n\r\n', eol)
        if hdr_end < 0:
            return
        headers = _parse_headers(payload[eol + 2:hdr_end])
        body_start = hdr_end + 4

        clen_s = headers.get('content-length')
        if clen_s and clen_s.isdigit():
            clen = int(clen_s)
            body_end = min(body_start + clen, n)
        else:
            next_idx = payload.find(b'\r\n\r\n', body_start)
            body_end = next_idx if next_idx > 0 else n

        body = payload[body_start:body_end]
        if body:
            yield method, headers, body
        idx = body_end


def _split_multipart(body: bytes, boundary: str) -> Iterable[tuple[dict, bytes]]:
    """Yield (part_headers, part_body) tuples from a multipart/form-data body."""
    sep = ('--' + boundary).encode('latin-1', errors='ignore')
    parts = body.split(sep)
    for raw in parts:
        if not raw or raw in (b'--', b'--\r\n'):
            continue
        raw = raw.lstrip(b'\r\n')
        hdr_end = raw.find(b'\r\n\r\n')
        if hdr_end < 0:
            continue
        headers = _parse_headers(raw[:hdr_end])
        part_body = raw[hdr_end + 4:]
        # Drop the trailing CRLF that lives before the next boundary marker.
        if part_body.endswith(b'\r\n'):
            part_body = part_body[:-2]
        yield headers, part_body


def _multipart_boundary(content_type: str) -> Optional[str]:
    if not content_type:
        return None
    m = re.search(r'boundary\s*=\s*"?([^";]+)"?', content_type, re.IGNORECASE)
    return m.group(1).strip() if m else None


def _hash_bytes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def _safe_filename_for_disk(sha256: str) -> str:
    """sha256 is hex from hashlib — safe by construction, but be defensive."""
    return re.sub(r'[^0-9a-f]', '', sha256.lower())[:64] or 'unknown'


def carve_http_files(
    tcp_flows: dict[tuple, bytes],
    *,
    artifacts_dir: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    min_file_size: int = DEFAULT_MIN_FILE_SIZE,
) -> list[dict]:
    """
    Walk reassembled TCP flows and return metadata for every interesting file
    carved out of HTTP responses and uploads.

    Args:
        tcp_flows: dict keyed by (src_ip, sport, dst_ip, dport) → reassembled
                   payload bytes (provided by TcpFlowAggregator).
        artifacts_dir: directory under which carved file bytes are written as
                       <sha256>. Created if missing. One file per unique sha256.
        max_file_size, min_file_size: size envelope; bodies outside it are
                                       skipped.

    Returns:
        A list of dicts, one per unique sha256, with keys:
          sha256, sha1, md5, filename, content_type, size_bytes, source_url,
          src_ip, dst_ip, protocol, family, on_disk_path, direction
        `direction` is 'download' for server→client or 'upload' for
        client→server (multipart part).
    """
    if not tcp_flows:
        return []

    try:
        os.makedirs(artifacts_dir, exist_ok=True)
    except OSError as e:
        print(f"[file_carving] cannot create artifacts dir {artifacts_dir}: {e}")
        return []

    seen: dict[str, dict] = {}

    def _accept(meta: dict, body: bytes) -> None:
        size = len(body)
        if size < min_file_size or size > max_file_size:
            return
        filename = meta.get('filename')
        content_type = meta.get('content_type')
        if not _should_keep(body, filename, content_type):
            return
        md5, sha1, sha256 = _hash_bytes(body)
        if sha256 in seen:
            # Already carved — keep the earliest sighting's metadata.
            return
        family, suggested_ext = _identify_by_magic(body)
        if not filename:
            filename = f"{sha256[:12]}.{suggested_ext or 'bin'}"
        on_disk = os.path.join(artifacts_dir, _safe_filename_for_disk(sha256))
        try:
            with open(on_disk, 'wb') as f:
                f.write(body)
        except OSError as e:
            print(f"[file_carving] write failed for {sha256[:12]}: {e}")
            return
        seen[sha256] = {
            'sha256': sha256,
            'sha1': sha1,
            'md5': md5,
            'filename': filename[:255],
            'content_type': (content_type or '')[:128],
            'size_bytes': size,
            'source_url': meta.get('source_url'),
            'src_ip': meta.get('src_ip'),
            'dst_ip': meta.get('dst_ip'),
            'protocol': meta.get('protocol', 'http'),
            'family': family,
            'on_disk_path': on_disk,
            'direction': meta.get('direction', 'download'),
        }

    # Track the latest pending request per (client_ip, sport, server_ip, dport)
    # so we can tag downloaded files with the URL that triggered them.
    pending_requests: dict[tuple, str] = {}

    for (src, sport, dst, dport), payload in tcp_flows.items():
        if not payload:
            continue
        # === downloads: server → client ===
        # On a typical capture the response flow is keyed (server_ip, 80, client_ip, X)
        # but TcpFlowAggregator doesn't know HTTP semantics — we just try both
        # directions and let the response framer find HTTP/ markers.
        try:
            for _status, headers, body in _iter_http_responses(payload):
                ct = headers.get('content-type', '')
                if _is_noise_content_type(ct):
                    continue
                filename = _filename_from_disposition(
                    headers.get('content-disposition', '')
                )
                url_key = (dst, dport, src, sport)
                source_url = pending_requests.get(url_key, '')
                if not filename and source_url:
                    filename = _filename_from_url(source_url)
                _accept({
                    'filename': filename,
                    'content_type': ct,
                    'source_url': source_url,
                    'src_ip': src,
                    'dst_ip': dst,
                    'protocol': 'http',
                    'direction': 'download',
                }, body)
        except Exception as e:
            print(f"[file_carving] response parse error on {src}:{sport}→{dst}:{dport}: {e}")

        # === uploads: client → server, multipart bodies ===
        try:
            for method, headers, body in _iter_http_uploads(payload):
                ct = headers.get('content-type', '')
                host = headers.get('host', '')
                # Track the request line URL even on non-upload requests so a
                # response framed in the reverse flow can attribute itself.
                # _iter_http_uploads only yields POST/PUT/PATCH, so we only see
                # bodies — that's fine.
                request_line_match = re.match(rb'(\S+)\s+(\S+)', payload)
                source_url = ''
                if request_line_match:
                    path = request_line_match.group(2).decode('latin-1', errors='ignore')
                    source_url = f'http://{host}{path}' if host else path
                if 'multipart/form-data' in ct.lower():
                    boundary = _multipart_boundary(ct)
                    if not boundary:
                        continue
                    for part_headers, part_body in _split_multipart(body, boundary):
                        cd = part_headers.get('content-disposition', '')
                        if 'filename' not in cd.lower():
                            continue
                        part_filename = _filename_from_disposition(cd)
                        part_ct = part_headers.get('content-type', '')
                        _accept({
                            'filename': part_filename,
                            'content_type': part_ct,
                            'source_url': source_url,
                            'src_ip': src,
                            'dst_ip': dst,
                            'protocol': 'http',
                            'direction': 'upload',
                        }, part_body)
                # Raw body upload (PUT of a single file). Only if small enough
                # and looks like a known file family — otherwise we'd carve
                # every API call.
                else:
                    _accept({
                        'filename': _filename_from_url(host) if not host else None,
                        'content_type': ct,
                        'source_url': source_url,
                        'src_ip': src,
                        'dst_ip': dst,
                        'protocol': 'http',
                        'direction': 'upload',
                    }, body)
        except Exception as e:
            print(f"[file_carving] upload parse error on {src}:{sport}→{dst}:{dport}: {e}")

    return list(seen.values())


__all__ = ['carve_http_files', 'DEFAULT_MAX_FILE_SIZE', 'DEFAULT_MIN_FILE_SIZE']
