"""
SOC IP tagging.

Lets the operator register IPs/CIDRs operated by their own security team
(pentesters, vulnerability scanners, blue-team probes). Each alert whose
source or destination falls inside a registered range gets a `soc_match`
annotation. The badge is informational only — it does NOT change the alert's
severity or triage status, so the analyst's manual decisions still feed the
FP classifier with clean labels.

Match modes per registered range:
  - 'either'   : badge when SOC IP appears as src OR dst (default, recommended)
  - 'src_only' : badge only when SOC IP is the source
  - 'dst_only' : badge only when SOC IP is the destination

`either` is recommended because a scan generates two-sided traffic (scan
packet src=SOC dst=target, response src=target dst=SOC). Restricting to
`src_only` would let the response leg generate a fake "target is hosting
Back Orifice" alert.
"""
import ipaddress


VALID_MATCH_MODES = ('either', 'src_only', 'dst_only')
DEFAULT_MATCH_MODE = 'either'


def _parse_cidr_rules(settings):
    """Return [(network, rule_dict)] from settings['soc_ips']. Bad entries skipped."""
    rules = []
    for raw in (settings or {}).get('soc_ips') or []:
        cidr = (raw.get('cidr') or '').strip()
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            continue
        mode = raw.get('match_mode') or settings.get('soc_default_match_mode') \
               or DEFAULT_MATCH_MODE
        if mode not in VALID_MATCH_MODES:
            mode = DEFAULT_MATCH_MODE
        rules.append((net, {
            'cidr': cidr,
            'description': raw.get('description') or '',
            'match_mode': mode,
        }))
    return rules


def _ip_in_net(ip_str, net):
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str) in net
    except (ValueError, TypeError):
        return False


def _collect_alert_ips(alert):
    """Return (src_ips, dst_ips) sets gathered from the alert's known fields.

    Detectors are inconsistent about where they put endpoints — some use
    src_ip/dst_ip, some put a single IP at alert['ip'], some use targets/peer_ips.
    We err on the side of collecting too much so the operator can spot scans
    even when the detector didn't model a clean pair.
    """
    d = alert.get('details') or {}
    src = set()
    dst = set()

    if isinstance(d.get('src_ip'), str):
        src.add(d['src_ip'])
    if isinstance(d.get('source_ip'), str):
        src.add(d['source_ip'])
    if isinstance(d.get('dst_ip'), str):
        dst.add(d['dst_ip'])

    targets = d.get('targets')
    if isinstance(targets, list):
        for t in targets:
            if isinstance(t, str):
                dst.add(t)
            elif isinstance(t, dict) and isinstance(t.get('ip'), str):
                dst.add(t['ip'])

    peers = d.get('peer_ips')
    if isinstance(peers, list):
        # `peer_role` lets a detector tell us which side the peers belong to:
        #   'client' -> peers are sources (e.g. suspicious-port clients/scanners)
        #   'target' -> peers are destinations (e.g. port-scan targets)
        # Default (incident kill-chains, legacy) treats peers as the destination
        # side: src is the compromised/attacker host and peers are the C2/exfil
        # endpoints on the other end.
        peer_role = d.get('peer_role')
        if peer_role == 'client':
            bucket = src
        elif peer_role == 'target':
            bucket = dst
        else:
            bucket = dst
        for p in peers:
            if isinstance(p, str):
                bucket.add(p)

    # Generic single-IP fallback: if neither side has anything, treat alert.ip
    # as the source. Otherwise add it to whichever side is empty so a SOC IP
    # at alert.ip still matches.
    fallback_ip = alert.get('ip')
    if isinstance(fallback_ip, str) and fallback_ip:
        if not src and not dst:
            src.add(fallback_ip)
        elif not src:
            src.add(fallback_ip)
        elif not dst:
            dst.add(fallback_ip)

    return src, dst


def _match_alert(alert, rules):
    """Return the first matching SOC rule dict + side ('src'|'dst'|'both'), or None."""
    if not rules:
        return None
    src_ips, dst_ips = _collect_alert_ips(alert)
    for net, rule in rules:
        src_hit = any(_ip_in_net(ip, net) for ip in src_ips)
        dst_hit = any(_ip_in_net(ip, net) for ip in dst_ips)
        mode = rule['match_mode']
        if mode == 'src_only' and not src_hit:
            continue
        if mode == 'dst_only' and not dst_hit:
            continue
        if mode == 'either' and not (src_hit or dst_hit):
            continue
        side = 'both' if src_hit and dst_hit else ('src' if src_hit else 'dst')
        return {
            'cidr': rule['cidr'],
            'description': rule['description'],
            'side': side,
            'match_mode': mode,
        }
    return None


def tag_soc_alerts(results, settings):
    """Annotate every matching alert in `results` with `soc_match`. Mutates in place.

    Returns the count of tagged alerts so the caller can log it.
    """
    rules = _parse_cidr_rules(settings or {})
    if not rules:
        return 0
    count = 0
    for alert in results.get('alerts') or []:
        match = _match_alert(alert, rules)
        if match:
            alert['soc_match'] = match
            count += 1
    return count


def is_soc_ip(ip_str, settings, side='either'):
    """Public helper: is this IP under a SOC rule whose match_mode allows `side`?"""
    rules = _parse_cidr_rules(settings or {})
    for net, rule in rules:
        if not _ip_in_net(ip_str, net):
            continue
        mode = rule['match_mode']
        if mode == 'either' or side == 'either' or mode == f'{side}_only':
            return rule
    return None
