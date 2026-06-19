"""
Unified post-analysis enrichment pipeline.

These are the network-bound steps that must NOT block the initial save_scan():
geolocation, IP reputation, alert domain reputation, carved-file hash lookups
and YARA scanning. Both execution paths call run_enrichment() so they cannot
drift apart:
  - Celery slow queue          -> celery_app.enrich_scan_task
  - threading fallback (no Celery) -> routes.common.analyze_pcap_background

Enrichment mutates the in-memory ``results`` blob (IP reputation/geolocation are
re-attached from their own DB tables on read, but alert ``domain_reputation`` and
appended carved/YARA alerts live only in the blob). When ``persist`` is set the
enriched blob is written back to scans.results_json so the scan view shows it on
reload. Appended carved/YARA alerts are also pushed into ``results['alerts']`` so
the blob and the alerts table keep the same count — otherwise the scan view's
count-based merge (see routes.common.merge_alert_triage_state) discards
blob-only fields (domain_reputation, mitre_attack).
"""
import time

import requests as http_requests

import database as db


def geolocate_ips(results):
    """Geolocate external IPs via ip-api.com (free, ~45 req/min) and cache them."""
    external_ips = [
        ip_data['ip'] for ip_data in results.get('ips', [])
        if not ip_data.get('is_local', True)
    ]

    for ip_addr in external_ips:
        if db.get_ip_geolocation(ip_addr):
            continue
        try:
            resp = http_requests.get(
                f'http://ip-api.com/json/{ip_addr}', timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    db.save_ip_geolocation(ip_addr, data)
            time.sleep(1.5)
        except Exception as e:
            print(f"[enrichment] geolocation error for {ip_addr}: {e}")


def lookup_carved_file_hashes(scan_id, results, settings):
    """Query VT + MalwareBazaar for every carved file's SHA-256, update the
    carved_files rows, and append a critical alert per malicious hit.

    Runs in the slow path so a hash service hanging never blocks the UI.
    """
    carved = results.get('carved_files') or []
    if not carved:
        return
    try:
        from hash_lookup import lookup_file_hash
    except Exception as e:
        print(f"[enrichment] hash_lookup import failed: {e}")
        return

    api_settings = settings or {}
    malicious_alerts = []
    for f in carved:
        sha256 = f.get('sha256')
        if not sha256:
            continue
        try:
            verdict = lookup_file_hash(
                sha256,
                md5=f.get('md5'), sha1=f.get('sha1'),
                settings=api_settings,
            )
        except Exception as e:
            print(f"[enrichment] lookup error for {sha256[:12]}: {e}")
            continue

        try:
            db.update_carved_file_reputation(sha256, verdict)
        except Exception as e:
            print(f"[enrichment] DB update failed for {sha256[:12]}: {e}")

        if verdict.get('malicious'):
            labels = ', '.join(verdict.get('labels') or []) or 'unknown family'
            sources = ', '.join(verdict.get('sources') or [])
            malicious_alerts.append({
                'severity': 'critical',
                'category': 'malware-download',
                'title': f"Malicious file downloaded ({labels})",
                'description': (
                    f"File {f.get('filename') or sha256[:12]} "
                    f"({f.get('size_bytes', 0)} bytes) carved from HTTP flow "
                    f"matches known-malicious hash on {sources}."
                ),
                'ip': f.get('dst_ip') or f.get('src_ip'),
                'details': {
                    'sha256': sha256,
                    'sha1': f.get('sha1'),
                    'md5': f.get('md5'),
                    'filename': f.get('filename'),
                    'source_url': f.get('source_url'),
                    'labels': verdict.get('labels'),
                    'sources': verdict.get('sources'),
                },
                'recommendation': (
                    "Isolate the recipient host, collect the file from "
                    "data/artifacts/, and pivot on the source URL/host."
                ),
                'mitre_attack': {
                    'technique_id': 'T1105',
                    'technique_name': 'Ingress Tool Transfer',
                    'tactic_id': 'TA0011',
                    'tactic_name': 'Command and Control',
                    'url': 'https://attack.mitre.org/techniques/T1105/',
                },
            })

    if malicious_alerts:
        try:
            db.append_alerts_to_scan(scan_id, malicious_alerts)
            # Mirror into the blob so blob/DB alert counts stay equal.
            results.setdefault('alerts', []).extend(malicious_alerts)
        except Exception as e:
            print(f"[enrichment] alert append failed: {e}")


def run_enrichment(scan_id, results, settings, persist=True):
    """Run the full enrichment pipeline against an already-saved scan.

    Each step is isolated so one failing service never aborts the rest. When
    ``persist`` is true the enriched blob is written back to scans.results_json
    (skipped if ``scan_id`` is falsy).
    """
    settings = settings or {}

    try:
        geolocate_ips(results)
    except Exception as e:
        print(f"[enrichment] geolocation step failed for scan {scan_id}: {e}")

    try:
        from threat_intel import enrich_ips_with_reputation
        enrich_ips_with_reputation(results)
    except Exception as e:
        print(f"[enrichment] IP reputation step failed for scan {scan_id}: {e}")

    try:
        from threat_intel import enrich_domains_in_alerts
        enrich_domains_in_alerts(results)
    except Exception as e:
        print(f"[enrichment] domain reputation step failed for scan {scan_id}: {e}")

    try:
        lookup_carved_file_hashes(scan_id, results, settings)
    except Exception as e:
        print(f"[enrichment] carved-file hash step failed for scan {scan_id}: {e}")

    try:
        from yara_scan import scan_and_alert
        scan_and_alert(scan_id, results, settings)
    except Exception as e:
        print(f"[enrichment] YARA step failed for scan {scan_id}: {e}")

    if persist and scan_id:
        try:
            db.update_scan_results(scan_id, results)
        except Exception as e:
            print(f"[enrichment] results persist failed for scan {scan_id}: {e}")


__all__ = ['run_enrichment', 'geolocate_ips', 'lookup_carved_file_hashes']
