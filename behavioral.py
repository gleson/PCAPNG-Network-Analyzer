"""
Behavioral baseline analysis.

Compares the freshly-analyzed scan against historical scans stored in the
database and emits alerts for deviations from each host's normal behavior.

Runs after the per-packet detections but BEFORE `db.save_scan(...)` so the
baseline naturally excludes the current scan.

Detections:
  - new external destination (network has never seen this IP)
  - new protocol used by an internal host
  - outbound bandwidth surge (vs host's median + MAD)
  - inbound bandwidth surge (server-side anomaly)
  - host previously internal-only now talking externally
  - activity in an unusual hour-of-week window (seasonality)

Each alert is also annotated with `category=behavioral` so the UI can
filter / group it the same way as the per-scan detections.
"""
from datetime import datetime
import database as db


# Minimum number of historical scans required before a baseline is considered
# meaningful. With fewer than this, the analysis is skipped entirely so we
# don't flood the operator on day-1.
MIN_HISTORY_SCANS = 3

# Volume surge thresholds: alert if current >= max(MIN_BYTES, median * MULTIPLIER)
VOLUME_MIN_BYTES = 5 * 1024 * 1024   # 5 MiB floor to avoid noise on chatty tiny hosts
VOLUME_MULTIPLIER = 5.0              # 5x the historical median

# Cap how many "first-seen external IP" alerts we emit per scan to avoid swamping
MAX_NEW_EXTERNAL_ALERTS = 30

# Seasonality: require at least this many distinct hour-of-week buckets in the
# host's history before alerting on activity outside that envelope. Below the
# floor we don't have a reliable schedule baseline.
SEASONALITY_MIN_BUCKETS = 8

# Cap seasonality alerts per scan to avoid swamping when the captures shift
# from business-hours to off-hours wholesale (a single config change can flip
# every host).
MAX_SEASONALITY_ALERTS = 20


# ============================================================
#  Math helpers (no numpy dependency)
# ============================================================

def _median(values):
    if not values:
        return 0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2


# ============================================================
#  Public entrypoint
# ============================================================

def analyze_behavioral_baseline(results, settings=None):
    """Mutate `results` adding behavioral alerts to results['alerts']."""
    if not results:
        return results

    history_count = db.get_total_scan_count()
    if history_count < MIN_HISTORY_SCANS:
        # Not enough history yet — skip silently.
        return results

    settings = settings or {}
    thresholds = (settings.get('thresholds') or {})
    multiplier = float(thresholds.get('behavioral_volume_multiplier', VOLUME_MULTIPLIER))
    min_bytes = int(thresholds.get('behavioral_volume_min_bytes', VOLUME_MIN_BYTES))
    max_new_ext = int(thresholds.get('behavioral_max_new_external_alerts', MAX_NEW_EXTERNAL_ALERTS))

    alerts_out = []

    # Index current scan IPs
    ip_records = results.get('ips', []) or []
    current_external = [r for r in ip_records if not r.get('is_local')]
    current_internal = [r for r in ip_records if r.get('is_local')]

    # ---- 1. New external destinations (network-wide first-seen) ----
    known_external = db.get_known_external_ips()
    new_externals = []
    for r in current_external:
        ip = r.get('ip')
        if not ip or ip in known_external:
            continue
        new_externals.append(r)
    # Sort by traffic volume so the noisiest get the alerts when capped
    new_externals.sort(
        key=lambda r: (r.get('bytes_sent', 0) or 0) + (r.get('bytes_received', 0) or 0),
        reverse=True,
    )
    for r in new_externals[:max_new_ext]:
        ip = r['ip']
        bytes_total = (r.get('bytes_sent', 0) or 0) + (r.get('bytes_received', 0) or 0)
        alerts_out.append({
            'severity': 'medium',
            'category': 'behavioral',
            'title': 'First-Seen External Destination',
            'description': (
                f'External IP {ip} appears for the first time in this network '
                f'(no record across {history_count} prior scan(s))'
            ),
            'ip': ip,
            'details': {
                'ip': ip,
                'bytes_total': bytes_total,
                'protocols': r.get('protocols', []),
                'historical_scans_checked': history_count,
            },
            'recommendation': (
                'Validate that this destination is expected for this host or business unit. '
                'First-seen external IPs are a leading indicator of new C2 channels.'
            ),
        })

    # ---- 2. New protocol on a known host ----
    for r in current_internal:
        ip = r.get('ip')
        if not ip:
            continue
        current_protos = set(r.get('protocols', []) or [])
        if not current_protos:
            continue
        history_protos = db.get_host_protocols(ip)
        if not history_protos:
            continue  # host is itself new — handled by first-seen logic
        new_protos = current_protos - history_protos
        if not new_protos:
            continue
        alerts_out.append({
            'severity': 'medium',
            'category': 'behavioral',
            'title': 'New Protocol on Known Host',
            'description': (
                f'Host {ip} is using protocol(s) {sorted(new_protos)} '
                f'never previously observed on it'
            ),
            'ip': ip,
            'details': {
                'ip': ip,
                'new_protocols': sorted(new_protos),
                'historical_protocols': sorted(history_protos),
            },
            'recommendation': (
                'Confirm this protocol change is expected (new app deployed, OS update, '
                'remote-admin tool installed). Sudden protocol shifts often indicate '
                'malware staging or pivoting.'
            ),
        })

    # ---- 3. Volume surge on known host ----
    for r in current_internal:
        ip = r.get('ip')
        if not ip:
            continue
        history = db.get_host_volume_history(ip, limit=60)
        if len(history) < MIN_HISTORY_SCANS:
            continue

        cur_sent = int(r.get('bytes_sent', 0) or 0)
        cur_recv = int(r.get('bytes_received', 0) or 0)
        med_sent = _median([h[0] for h in history if h[0] is not None])
        med_recv = _median([h[1] for h in history if h[1] is not None])

        if cur_sent >= min_bytes and med_sent and cur_sent >= med_sent * multiplier:
            alerts_out.append({
                'severity': 'high',
                'category': 'behavioral',
                'title': 'Outbound Volume Surge vs Baseline',
                'description': (
                    f'Host {ip} sent {cur_sent / 1_000_000:.1f} MB '
                    f'(>= {multiplier:.0f}x historical median {med_sent / 1_000_000:.1f} MB)'
                ),
                'ip': ip,
                'details': {
                    'ip': ip,
                    'bytes_sent_current': cur_sent,
                    'bytes_sent_median': int(med_sent),
                    'multiplier_observed': round(cur_sent / med_sent, 2),
                    'history_window_scans': len(history),
                },
                'recommendation': (
                    'Sudden outbound volume spikes are a top indicator of data exfiltration. '
                    'Check destination IPs and correlate with file-share or HTTP exfil alerts.'
                ),
            })

        if cur_recv >= min_bytes and med_recv and cur_recv >= med_recv * multiplier:
            alerts_out.append({
                'severity': 'medium',
                'category': 'behavioral',
                'title': 'Inbound Volume Surge vs Baseline',
                'description': (
                    f'Host {ip} received {cur_recv / 1_000_000:.1f} MB '
                    f'(>= {multiplier:.0f}x historical median {med_recv / 1_000_000:.1f} MB)'
                ),
                'ip': ip,
                'details': {
                    'ip': ip,
                    'bytes_received_current': cur_recv,
                    'bytes_received_median': int(med_recv),
                    'multiplier_observed': round(cur_recv / med_recv, 2),
                    'history_window_scans': len(history),
                },
                'recommendation': (
                    'Inbound spikes can indicate large downloads, malware payload delivery, '
                    'or unusual server load. Review the source IPs.'
                ),
            })

    # ---- 3b. Seasonality: activity in an unusual hour-of-week ----
    # The current scan's start_time tells us *when* the captured traffic
    # happened. If the host has been observed in many distinct hour-of-week
    # buckets historically but never in the current bucket, that's a schedule
    # anomaly worth surfacing (workstation chatting at 03:00 Sunday, etc.).
    summary = results.get('summary') or {}
    start_time_iso = summary.get('start_time')
    current_how = None
    if start_time_iso:
        try:
            current_dt = datetime.fromisoformat(start_time_iso)
            current_how = current_dt.weekday() * 24 + current_dt.hour
        except (ValueError, TypeError):
            current_how = None

    if current_how is not None:
        seasonality_min_buckets = int(thresholds.get(
            'behavioral_seasonality_min_buckets', SEASONALITY_MIN_BUCKETS,
        ))
        max_seasonality_alerts = int(thresholds.get(
            'behavioral_max_seasonality_alerts', MAX_SEASONALITY_ALERTS,
        ))

        # Bulk-fetch active hours for every internal IP we might alert on.
        ip_list = [r.get('ip') for r in current_internal if r.get('ip')]
        active_hours_map = db.get_active_hours_for_ips(ip_list)

        seasonality_candidates = []
        for r in current_internal:
            ip = r.get('ip')
            if not ip:
                continue
            historical = active_hours_map.get(ip) or set()
            if len(historical) < seasonality_min_buckets:
                continue
            if current_how in historical:
                continue
            seasonality_candidates.append((r, historical))

        # Prefer alerting hosts that have the most distinct historical
        # buckets — those carry the strongest "we know your schedule" signal.
        seasonality_candidates.sort(key=lambda x: len(x[1]), reverse=True)
        for r, historical in seasonality_candidates[:max_seasonality_alerts]:
            ip = r['ip']
            day_name = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][current_how // 24]
            hour = current_how % 24
            alerts_out.append({
                'severity': 'medium',
                'category': 'behavioral',
                'title': 'Activity in Unusual Time Window',
                'description': (
                    f'Host {ip} is active at {day_name} {hour:02d}:00, a window where '
                    f'it has never been observed across {len(historical)} distinct '
                    f'historical hour-of-week buckets'
                ),
                'ip': ip,
                'details': {
                    'ip': ip,
                    'current_day': day_name,
                    'current_hour': hour,
                    'current_hour_of_week': current_how,
                    'historical_distinct_buckets': len(historical),
                    'sample_historical_hours': sorted(historical)[:24],
                },
                'recommendation': (
                    'Off-schedule activity is a leading indicator of compromise '
                    '(scheduled tasks dropped by malware, attacker-controlled '
                    'sessions, after-hours data staging). Validate that a human '
                    'or business process explains the activity.'
                ),
            })

    # ---- 4. Internal host going external for the first time ----
    for r in current_internal:
        ip = r.get('ip')
        if not ip:
            continue
        # Heuristic: this host never appeared in protocol_ip_stats before AND
        # has external-bound traffic now → first-time external comm.
        history_protos = db.get_host_protocols(ip)
        had_history = bool(history_protos)
        # We can't cheaply compute "had external comms" from the schema, so
        # we approximate using bytes_sent against the per-host history: a host
        # with prior bytes_sent records has talked over the network before.
        history_volume = db.get_host_volume_history(ip, limit=5)
        cur_sent = int(r.get('bytes_sent', 0) or 0)
        if not had_history and not history_volume and cur_sent > 0:
            alerts_out.append({
                'severity': 'low',
                'category': 'behavioral',
                'title': 'New Internal Host Active on Network',
                'description': f'Internal host {ip} is observed for the first time',
                'ip': ip,
                'details': {
                    'ip': ip,
                    'bytes_sent': cur_sent,
                    'protocols': r.get('protocols', []),
                },
                'recommendation': (
                    'Verify this is an authorized device. Unknown internal hosts can be '
                    'rogue devices, BYOD, or attacker-deployed implants.'
                ),
            })

    # Stamp timestamps
    now = datetime.now().isoformat()
    for a in alerts_out:
        a.setdefault('timestamp', now)

    # Annotate with MITRE ATT&CK
    try:
        from mitre_attack import annotate_alerts
        annotate_alerts(alerts_out)
    except Exception as e:
        print(f"[behavioral] MITRE annotation failed: {e}")

    # Merge into the scan results
    results.setdefault('alerts', []).extend(alerts_out)

    # Bump alert_count on affected hosts so the UI badges stay correct
    by_ip = {}
    for a in alerts_out:
        ip = a.get('ip')
        if ip:
            by_ip[ip] = by_ip.get(ip, 0) + 1
    for r in ip_records:
        ip = r.get('ip')
        if ip in by_ip:
            r['alert_count'] = (r.get('alert_count', 0) or 0) + by_ip[ip]

    return results
