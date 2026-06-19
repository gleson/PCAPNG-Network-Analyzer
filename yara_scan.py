"""
YARA scanning of carved-file payloads.

Carved files (HTTP downloads / multipart uploads) land on disk via
file_carving.carve_http_files and are then enriched on the slow Celery queue.
This module is one of those enrichment steps: compile a directory of YARA
rules once per worker, scan each carved artifact, and return structured match
metadata so the caller can write to the DB and raise alerts.

Design choices:
  - yara-python is an OPTIONAL dependency. If the import fails (operator chose
    not to install libyara or the python binding) the public helpers degrade
    to "no matches" and log once. Same fallback pattern as defusedxml.
  - The compiled ruleset is cached on the module so we only pay the compile
    cost once per worker process. The cache key is (rules_dir, sorted file
    mtimes) so editing a .yar on disk transparently invalidates the cache
    next time scan_files() is called.
  - Per-file scan is wrapped in try/except. A malformed rule or a corrupt
    artifact must never crash the enrichment task.
  - severity is derived from rule `meta` (`severity` field) when present,
    otherwise from tags ('critical', 'high', 'malware' → high; 'suspicious'
    → medium; otherwise low). This lets dropped-in third-party rules (Florian
    Roth, Neo23x0) integrate without manual tagging.

Public API:
    scan_files(carved_files, rules_dir) -> dict[sha256, list[match_dict]]
    scan_file(path, rules_dir) -> list[match_dict]
    yara_available() -> bool
"""
from __future__ import annotations

import os
import threading
from typing import Iterable, Optional

try:
    import yara  # type: ignore
    _YARA_AVAILABLE = True
except Exception:
    yara = None  # type: ignore
    _YARA_AVAILABLE = False


_RULES_EXTENSIONS = ('.yar', '.yara')
_DEFAULT_TIMEOUT_SECONDS = 30

_SEVERITY_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

_HIGH_SEV_TAGS = frozenset({
    'critical', 'high', 'malware', 'ransomware', 'trojan', 'backdoor',
    'apt', 'exploit', 'webshell', 'rat', 'stealer',
})
_MEDIUM_SEV_TAGS = frozenset({
    'suspicious', 'packed', 'obfuscated', 'pua', 'crypto',
})

_lock = threading.Lock()
_cache: dict | None = None  # {'key': (dir, frozenset((path, mtime))), 'rules': yara.Rules}
_warned_no_yara = False


def yara_available() -> bool:
    """True if yara-python imported successfully."""
    return _YARA_AVAILABLE


def _list_rule_files(rules_dir: str) -> list[str]:
    out: list[str] = []
    try:
        for entry in sorted(os.listdir(rules_dir)):
            if entry.startswith('.'):
                continue
            if not entry.lower().endswith(_RULES_EXTENSIONS):
                continue
            full = os.path.join(rules_dir, entry)
            if os.path.isfile(full):
                out.append(full)
    except OSError as e:
        print(f"[yara_scan] cannot list rules dir {rules_dir}: {e}")
    return out


def _cache_key(rules_dir: str, files: Iterable[str]) -> tuple:
    pairs = []
    for f in files:
        try:
            pairs.append((f, os.path.getmtime(f)))
        except OSError:
            continue
    return (os.path.abspath(rules_dir), frozenset(pairs))


def _compile_rules(rules_dir: str):
    """Return a compiled yara.Rules object for *rules_dir* (cached). None if no
    rules are usable or yara isn't installed.
    """
    global _cache, _warned_no_yara

    if not _YARA_AVAILABLE:
        if not _warned_no_yara:
            print("[yara_scan] yara-python not installed — YARA scanning disabled")
            _warned_no_yara = True
        return None

    if not rules_dir or not os.path.isdir(rules_dir):
        return None

    files = _list_rule_files(rules_dir)
    if not files:
        return None

    key = _cache_key(rules_dir, files)
    with _lock:
        if _cache is not None and _cache.get('key') == key:
            return _cache['rules']
        filepaths = {os.path.basename(p).rsplit('.', 1)[0]: p for p in files}
        try:
            rules = yara.compile(filepaths=filepaths)
        except Exception as e:
            print(f"[yara_scan] compile failed for {rules_dir}: {e}")
            _cache = {'key': key, 'rules': None}
            return None
        _cache = {'key': key, 'rules': rules}
        return rules


def _classify_severity(rule_meta: dict, tags: Iterable[str]) -> str:
    """Pick a severity for a YARA match. Rule meta `severity` wins; otherwise
    derive from tags; otherwise 'medium'.
    """
    explicit = (rule_meta.get('severity') or '').lower().strip()
    if explicit in _SEVERITY_RANK:
        return explicit

    tag_set = {t.lower() for t in tags}
    if tag_set & _HIGH_SEV_TAGS:
        return 'high'
    if tag_set & _MEDIUM_SEV_TAGS:
        return 'medium'
    return 'medium'


def _worst_severity(matches: Iterable[dict]) -> str:
    worst = 'info'
    worst_rank = -1
    for m in matches:
        sev = m.get('severity', 'medium')
        rank = _SEVERITY_RANK.get(sev, 1)
        if rank > worst_rank:
            worst = sev
            worst_rank = rank
    return worst


def _normalize_match(match) -> dict:
    """Convert a yara.Match object into a JSON-serialisable dict."""
    meta = dict(match.meta or {})
    tags = list(match.tags or [])
    # Strings: (offset, identifier, data_bytes). Truncate the byte content so
    # we don't dump multi-KB into the DB row.
    string_hits = []
    try:
        for s in (match.strings or [])[:32]:
            offset, ident, data = s
            try:
                preview = data[:64].decode('latin-1', errors='replace')
            except Exception:
                preview = ''
            string_hits.append({
                'offset': offset,
                'identifier': ident,
                'preview': preview,
            })
    except Exception:
        pass

    return {
        'rule': match.rule,
        'namespace': getattr(match, 'namespace', 'default'),
        'tags': tags,
        'meta': meta,
        'severity': _classify_severity(meta, tags),
        'strings': string_hits,
    }


def scan_file(path: str,
              rules_dir: str,
              *,
              timeout: int = _DEFAULT_TIMEOUT_SECONDS) -> list[dict]:
    """Scan a single file on disk. Returns a list of normalised match dicts.
    Empty list on no match, no rules, or any error.
    """
    rules = _compile_rules(rules_dir)
    if rules is None:
        return []
    if not path or not os.path.isfile(path):
        return []
    try:
        raw_matches = rules.match(filepath=path, timeout=timeout)
    except Exception as e:
        print(f"[yara_scan] match error on {path}: {e}")
        return []
    return [_normalize_match(m) for m in raw_matches]


def scan_files(carved_files: list[dict],
               rules_dir: str,
               *,
               timeout: int = _DEFAULT_TIMEOUT_SECONDS) -> dict[str, dict]:
    """Scan every carved file in *carved_files* and return a mapping
        sha256 -> {
            'matches': [match_dict, ...],
            'severity': worst severity across matches,
        }
    Files with no matches are omitted from the result. Files missing
    on_disk_path or sha256 are silently skipped.
    """
    if not carved_files:
        return {}
    rules = _compile_rules(rules_dir)
    if rules is None:
        return {}

    out: dict[str, dict] = {}
    for f in carved_files:
        sha256 = f.get('sha256')
        path = f.get('on_disk_path')
        if not sha256 or not path or not os.path.isfile(path):
            continue
        try:
            raw_matches = rules.match(filepath=path, timeout=timeout)
        except Exception as e:
            print(f"[yara_scan] match error on {sha256[:12]}: {e}")
            continue
        if not raw_matches:
            continue
        normalized = [_normalize_match(m) for m in raw_matches]
        out[sha256] = {
            'matches': normalized,
            'severity': _worst_severity(normalized),
        }
    return out


def default_rules_dir(settings: Optional[dict] = None) -> str:
    """Resolve the YARA rules directory from settings/env, with a sensible default."""
    if settings:
        from_settings = settings.get('yara_rules_dir')
        if from_settings:
            return from_settings
    return os.environ.get('YARA_RULES_DIR', 'data/yara_rules')


def yara_enabled(settings: Optional[dict] = None) -> bool:
    """True when YARA scanning should run: dependency present AND not disabled
    via settings. Defaults to enabled when the dep is available.
    """
    if not _YARA_AVAILABLE:
        return False
    if settings is None:
        return True
    flag = settings.get('yara_enabled')
    if flag is None:
        return True
    return bool(flag)


_YARA_SEVERITY_TO_ALERT = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
    'info': 'low',
}


def scan_and_alert(scan_id, results, settings) -> int:
    """End-to-end YARA enrichment for a scan: scan every carved artifact on
    disk, persist matches into carved_files.yara_matches, and append one
    alert per file matched.

    Safe to invoke from both the slow Celery queue and the threading fallback.
    Returns the number of files that produced matches (0 means "nothing
    found", including when YARA is disabled or no rules are present).
    """
    carved = (results or {}).get('carved_files') or []
    if not carved or not yara_enabled(settings):
        return 0

    try:
        import database as db
    except Exception as e:
        print(f"[yara_scan] database import failed: {e}")
        return 0

    rules_dir = default_rules_dir(settings)
    try:
        per_file = scan_files(carved, rules_dir)
    except Exception as e:
        print(f"[yara_scan] scan failed: {e}")
        return 0

    if not per_file:
        return 0

    carved_by_sha = {f.get('sha256'): f for f in carved if f.get('sha256')}
    alerts = []

    for sha256, payload in per_file.items():
        try:
            db.update_carved_file_yara_matches(sha256, payload)
        except Exception as e:
            print(f"[yara_scan] DB update failed for {sha256[:12]}: {e}")
            continue

        meta = carved_by_sha.get(sha256) or {}
        matches = payload.get('matches') or []
        severity = _YARA_SEVERITY_TO_ALERT.get(payload.get('severity'), 'medium')
        rule_names = [m.get('rule') for m in matches if m.get('rule')]
        primary_meta = (matches[0].get('meta') if matches else {}) or {}

        alerts.append({
            'severity': severity,
            'category': 'yara-match',
            'title': (
                f"YARA match on carved file: "
                f"{', '.join(rule_names[:3]) or 'unknown rule'}"
            ),
            'description': (
                f"File {meta.get('filename') or sha256[:12]} "
                f"({meta.get('size_bytes', 0)} bytes) carved from "
                f"{meta.get('protocol', 'http')} flow matched "
                f"{len(rule_names)} YARA rule(s): "
                f"{', '.join(rule_names)}. "
                f"{(primary_meta.get('description') or '').strip()}"
            ).strip(),
            'ip': meta.get('dst_ip') or meta.get('src_ip'),
            'details': {
                'sha256': sha256,
                'filename': meta.get('filename'),
                'source_url': meta.get('source_url'),
                'rules': rule_names,
                'matches': matches,
                'severity': payload.get('severity'),
            },
            'recommendation': (
                "Pull the artifact from data/artifacts/, validate the YARA "
                "rule's intent, and pivot on source_url to identify other "
                "affected hosts."
            ),
            'mitre_attack': {
                'technique_id': 'T1105',
                'technique_name': 'Ingress Tool Transfer',
                'tactic_id': 'TA0011',
                'tactic_name': 'Command and Control',
                'url': 'https://attack.mitre.org/techniques/T1105/',
            },
        })

    if alerts:
        try:
            db.append_alerts_to_scan(scan_id, alerts)
            # Mirror into the in-memory blob so blob/DB alert counts stay equal
            # and the scan view's count-based merge keeps blob-only fields.
            if isinstance(results, dict):
                results.setdefault('alerts', []).extend(alerts)
        except Exception as e:
            print(f"[yara_scan] alert append failed: {e}")

    return len(per_file)


__all__ = [
    'scan_file',
    'scan_files',
    'scan_and_alert',
    'yara_available',
    'yara_enabled',
    'default_rules_dir',
]
