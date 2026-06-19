"""Host Risk Score (0-100).

Aggregates four signals per IP and produces a single score consumed by the
IPs tab in the UI:

  * severity            — sum of weighted alert severities
  * persistence         — distinct alert categories + log of alert volume
  * reputation          — threat-intel score (filled in by the slow queue)
  * baseline_deviation  — count of behavioral / anomaly-flavour alerts

Score is recomputed every time the scan is served (via
``enrich_results_with_names_and_groups``) so it always reflects the freshest
reputation data, even if the slow-queue enrichment lands after the fast task.
"""

from __future__ import annotations

import math
from collections import defaultdict


_SEVERITY_WEIGHTS = {
    'critical': 20,
    'high': 8,
    'medium': 3,
    'low': 1,
    'info': 0,
}

_BASELINE_CATEGORIES = frozenset({
    'beaconing',
    'behavioral',
    'anomaly',
    'exfil',
    'scan',
    'c2',
    'quic_high_volume_new_dest',
})

_SEVERITY_CAP = 55
_PERSISTENCE_CAP = 15
_REPUTATION_CAP = 20
_BASELINE_CAP = 10


def _alerts_by_ip(alerts):
    grouped = defaultdict(list)
    for alert in alerts or []:
        ip = alert.get('ip')
        if ip:
            grouped[ip].append(alert)
    return grouped


def _score_severity(alerts):
    raw = sum(
        _SEVERITY_WEIGHTS.get(a.get('severity', 'low'), 1)
        for a in alerts
    )
    return min(raw, _SEVERITY_CAP)


def _score_persistence(alerts):
    if not alerts:
        return 0
    distinct = len({a.get('category', '') for a in alerts if a.get('category')})
    diversity = min(distinct * 3, 12)
    volume_bonus = min(int(math.log2(len(alerts) + 1)), 3)
    return min(diversity + volume_bonus, _PERSISTENCE_CAP)


def _score_reputation(ip_data):
    rep = ip_data.get('reputation') or {}
    if rep.get('is_malicious'):
        return _REPUTATION_CAP
    raw = rep.get('reputation_score') or 0
    try:
        raw = int(raw)
    except (TypeError, ValueError):
        return 0
    if raw <= 0:
        return 0
    return min(round(raw * _REPUTATION_CAP / 100), _REPUTATION_CAP)


def _score_baseline_deviation(alerts):
    count = sum(
        1 for a in alerts
        if a.get('category') in _BASELINE_CATEGORIES
    )
    return min(count * 2, _BASELINE_CAP)


def compute_host_risk_scores(results):
    """Mutates ``results['ips']`` in place, adding ``risk_score`` and
    ``risk_breakdown`` to every entry. Returns the same dict for chaining.
    """
    if not isinstance(results, dict):
        return results
    ips = results.get('ips') or []
    if not ips:
        return results

    alerts_by_ip = _alerts_by_ip(results.get('alerts'))

    for ip_data in ips:
        ip_alerts = alerts_by_ip.get(ip_data.get('ip'), [])
        sev = _score_severity(ip_alerts)
        persistence = _score_persistence(ip_alerts)
        reputation = _score_reputation(ip_data)
        baseline = _score_baseline_deviation(ip_alerts)
        total = min(sev + persistence + reputation + baseline, 100)
        ip_data['risk_score'] = total
        ip_data['risk_breakdown'] = {
            'severity': sev,
            'persistence': persistence,
            'reputation': reputation,
            'baseline_deviation': baseline,
        }
    return results
