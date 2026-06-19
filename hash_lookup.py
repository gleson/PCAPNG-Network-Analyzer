"""
File hash reputation lookups.

Given an SHA-256 (and optionally MD5/SHA-1) of a file carved out of a PCAP,
query public threat-intel services and return a structured verdict.

Sources:
    MalwareBazaar (abuse.ch) — free, no API key required for `get_info`.
        POST https://mb-api.abuse.ch/api/v1/  query=get_info&hash=<sha256>

    VirusTotal v3 — requires API key (settings.api_keys.virustotal).
        GET https://www.virustotal.com/api/v3/files/<sha256>
        Header: x-apikey: <key>

Both calls have short timeouts and are wrapped in try/except — a failed lookup
must never crash the enrichment task. Negative results (the hash is unknown
to both services) are still returned so the UI can show "unknown" instead of
re-querying on every page load. Caching/persistence is the caller's job
(carved_files DB table).

Public API:
    lookup_file_hash(sha256, *, md5=None, sha1=None, settings=None) -> dict
    is_malicious(verdict) -> bool
"""
from __future__ import annotations

import os
import requests
from typing import Optional

VT_TIMEOUT = 10
MB_TIMEOUT = 10

VT_URL = 'https://www.virustotal.com/api/v3/files/{hash}'
MB_URL = 'https://mb-api.abuse.ch/api/v1/'

VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
MALWAREBAZAAR_AUTH_KEY = os.environ.get('MALWAREBAZAAR_AUTH_KEY', '')

# Mapping kept aligned with threat_intel._ENV_MAP so the same /api/admin/api-keys
# endpoint can manage these too.
_ENV_MAP = {
    'virustotal': 'VIRUSTOTAL_API_KEY',
    'malwarebazaar': 'MALWAREBAZAAR_AUTH_KEY',
}


def _get_key(service: str, settings: Optional[dict] = None) -> str:
    if settings:
        key = (settings.get('api_keys') or {}).get(service, '')
        if key:
            return key
    env_var = _ENV_MAP.get(service)
    if env_var:
        val = os.environ.get(env_var, '')
        if val:
            return val
    return ''


# ---------------------------------------------------------------------------
#  MalwareBazaar
# ---------------------------------------------------------------------------

def check_malwarebazaar(sha256: str,
                       settings: Optional[dict] = None) -> Optional[dict]:
    """Look up *sha256* in MalwareBazaar. Returns a dict with selected fields
    on a hit, an explicit {'found': False} on a clean miss, or None on
    transport error.
    """
    if not sha256:
        return None
    auth_key = _get_key('malwarebazaar', settings)
    headers = {'User-Agent': 'pcap-analyzer/1.0'}
    # MB introduced API-Key requirement for some endpoints in 2023 — pass it
    # if the operator configured one, but the lookup still works without.
    if auth_key:
        headers['Auth-Key'] = auth_key
    try:
        resp = requests.post(
            MB_URL,
            data={'query': 'get_info', 'hash': sha256},
            headers=headers,
            timeout=MB_TIMEOUT,
        )
    except requests.RequestException as e:
        print(f"[hash_lookup] MalwareBazaar transport error for {sha256[:12]}: {e}")
        return None
    if resp.status_code != 200:
        print(f"[hash_lookup] MalwareBazaar HTTP {resp.status_code} for {sha256[:12]}")
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    status = (payload.get('query_status') or '').lower()
    if status == 'hash_not_found':
        return {'found': False}
    if status != 'ok':
        # 'no_results', 'illegal_hash', 'illegal_auth_key', etc.
        return {'found': False, 'status': status}
    data = (payload.get('data') or [{}])[0]
    return {
        'found': True,
        'signature': data.get('signature'),
        'file_name': data.get('file_name'),
        'file_type': data.get('file_type'),
        'tags': data.get('tags') or [],
        'first_seen': data.get('first_seen'),
        'last_seen': data.get('last_seen'),
        'reporter': data.get('reporter'),
        'sha256': data.get('sha256_hash'),
    }


# ---------------------------------------------------------------------------
#  VirusTotal
# ---------------------------------------------------------------------------

def check_virustotal(sha256: str,
                    settings: Optional[dict] = None) -> Optional[dict]:
    """Look up *sha256* in VirusTotal v3. Returns dict with counts on hit,
    {'found': False} on a clean miss, or None on transport error / missing key.
    """
    if not sha256:
        return None
    key = _get_key('virustotal', settings)
    if not key:
        return None
    try:
        resp = requests.get(
            VT_URL.format(hash=sha256),
            headers={'x-apikey': key, 'User-Agent': 'pcap-analyzer/1.0'},
            timeout=VT_TIMEOUT,
        )
    except requests.RequestException as e:
        print(f"[hash_lookup] VirusTotal transport error for {sha256[:12]}: {e}")
        return None
    if resp.status_code == 404:
        return {'found': False}
    if resp.status_code != 200:
        print(f"[hash_lookup] VirusTotal HTTP {resp.status_code} for {sha256[:12]}")
        return None
    try:
        body = resp.json()
    except ValueError:
        return None
    attrs = ((body.get('data') or {}).get('attributes') or {})
    stats = attrs.get('last_analysis_stats') or {}
    return {
        'found': True,
        'malicious': int(stats.get('malicious') or 0),
        'suspicious': int(stats.get('suspicious') or 0),
        'harmless': int(stats.get('harmless') or 0),
        'undetected': int(stats.get('undetected') or 0),
        'total': sum(int(v or 0) for v in stats.values()),
        'meaningful_name': attrs.get('meaningful_name'),
        'type_description': attrs.get('type_description'),
        'reputation': attrs.get('reputation'),
        'first_submission_date': attrs.get('first_submission_date'),
        'last_analysis_date': attrs.get('last_analysis_date'),
        'popular_threat_label': (
            ((attrs.get('popular_threat_classification') or {})
             .get('suggested_threat_label'))
        ),
    }


# ---------------------------------------------------------------------------
#  Combined verdict
# ---------------------------------------------------------------------------

def lookup_file_hash(sha256: str,
                     *,
                     md5: Optional[str] = None,
                     sha1: Optional[str] = None,
                     settings: Optional[dict] = None) -> dict:
    """Query all configured services for *sha256* and build a unified verdict.

    Returns a dict shaped:
        {
            'sha256': '<hex>',
            'malicious': bool,
            'sources': ['malwarebazaar', 'virustotal', ...],
            'labels': ['cobalt-strike', ...],
            'malwarebazaar': {...} | None,
            'virustotal': {...} | None,
        }

    Never raises — services that error out simply leave their key as None.
    """
    out = {
        'sha256': sha256,
        'md5': md5,
        'sha1': sha1,
        'malicious': False,
        'sources': [],
        'labels': [],
        'malwarebazaar': None,
        'virustotal': None,
    }

    mb = check_malwarebazaar(sha256, settings)
    if mb is not None:
        out['malwarebazaar'] = mb
        if mb.get('found'):
            out['malicious'] = True
            out['sources'].append('malwarebazaar')
            if mb.get('signature'):
                out['labels'].append(mb['signature'])
            out['labels'].extend(mb.get('tags') or [])

    vt = check_virustotal(sha256, settings)
    if vt is not None:
        out['virustotal'] = vt
        if vt.get('found') and vt.get('malicious', 0) >= 2:
            # ≥2 engines flagging is the conventional malicious threshold —
            # single-engine hits are usually FPs from less-reliable scanners.
            out['malicious'] = True
            out['sources'].append('virustotal')
            if vt.get('popular_threat_label'):
                out['labels'].append(vt['popular_threat_label'])

    # De-dupe labels while preserving order.
    seen = set()
    out['labels'] = [x for x in out['labels'] if x and not (x in seen or seen.add(x))]
    return out


def is_malicious(verdict: dict) -> bool:
    return bool(verdict and verdict.get('malicious'))


__all__ = [
    'lookup_file_hash',
    'check_malwarebazaar',
    'check_virustotal',
    'is_malicious',
]
