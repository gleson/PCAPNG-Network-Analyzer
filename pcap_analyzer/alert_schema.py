"""
Canonical alert schema — endpoint/port/protocol/CVE normalization.

Detectors grew organically and disagree on where an alert's endpoints live:
some write ``details.src_ip``/``dst_ip``, others ``src``/``dst``,
``source_ip``/``destination_ip``, ``server_ip``/``client_ip``, ``kdc_ip``,
``targets``/``peer_ips`` lists, or only the top-level ``alert['ip']``.
Downstream consumers (dedup, SOC matching, UI filters) each hard-coded a
subset of those names and silently missed the rest.

``normalize_alerts`` runs once per analysis, after every detector emitted its
alerts and before dedup/SOC/persistence. It derives five canonical top-level
fields on EVERY alert without touching detector-specific ``details``:

    src_ips     list[str]  — origin endpoint(s), sorted
    dst_ips     list[str]  — destination endpoint(s), sorted
    ports       list[int]  — service ports involved, sorted
    protocols   list[str]  — protocol labels involved, sorted
    cves        list[str]  — CVE-YYYY-NNNN tokens referenced anywhere

Legacy detail keys stay untouched so old detectors, stored blobs and the UI
keep working; consumers should prefer the canonical fields going forward.
Only values that parse as real IP addresses enter src_ips/dst_ips — this
keeps hostnames/labels that some detectors store in ``src``-like keys out of
IP-matching logic.
"""

import ipaddress
import json
import re

# Matches "CVE-YYYY-NNNN+" tokens (case/sep tolerant). Shared with the KEV
# enricher so both extract the exact same token set.
CVE_RE = re.compile(r'CVE[-\s]?(\d{4})[-\s]?(\d{4,7})', re.IGNORECASE)

# details keys holding a single source-side IP. client_ip is source because
# the client is the connection initiator in every detector that sets it.
_SRC_SCALAR_KEYS = ('src_ip', 'source_ip', 'src', 'client_ip')
# details keys holding a single destination-side IP.
_DST_SCALAR_KEYS = (
    'dst_ip', 'destination_ip', 'dst', 'target_ip', 'server_ip',
    'kdc_ip', 'destination',
)
# details keys holding a LIST of source-side IPs.
_SRC_LIST_KEYS = ('sources',)
# details keys holding a LIST of destination-side IPs (scan targets etc.).
_DST_LIST_KEYS = ('targets', 'targets_sample', 'target_sample', 'hosts_sample')
# details keys holding a service port. Client-side ephemeral ports ('sport')
# are only used as a last resort (see _collect_ports) because a few detectors
# (JA3S) store the *server* port there while others store the ephemeral one.
_PORT_SCALAR_KEYS = ('port', 'dport', 'destination_port', 'server_port')
_PORT_LIST_KEYS = ('ports',)
_PROTO_KEYS = ('protocol', 'proto')

# Caps to keep alert blobs bounded on pathological captures.
_MAX_IPS = 32
_MAX_PORTS = 32
_MAX_CVE_BLOB = 20000


def _as_ip(value):
    """Return the stripped string when it parses as an IP address, else None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return None
    return v


def _as_port(value):
    try:
        p = int(value)
    except (TypeError, ValueError):
        return None
    return p if 0 < p < 65536 else None


def _add_ips_from_list(bucket, value):
    if not isinstance(value, (list, tuple, set)):
        return
    for item in value:
        if isinstance(item, dict):
            item = item.get('ip')
        ip = _as_ip(item)
        if ip:
            bucket.add(ip)


def _collect_endpoints(alert, details):
    src, dst = set(), set()

    for key in _SRC_SCALAR_KEYS:
        ip = _as_ip(details.get(key))
        if ip:
            src.add(ip)
    for key in _DST_SCALAR_KEYS:
        ip = _as_ip(details.get(key))
        if ip:
            dst.add(ip)
    for key in _SRC_LIST_KEYS:
        _add_ips_from_list(src, details.get(key))
    for key in _DST_LIST_KEYS:
        _add_ips_from_list(dst, details.get(key))

    # peer_ips side depends on peer_role: 'client' → sources (e.g. clients
    # hitting a suspicious port), 'target' or absent → destinations (legacy
    # SOC semantics).
    peers = details.get('peer_ips')
    if isinstance(peers, (list, tuple, set)):
        bucket = src if details.get('peer_role') == 'client' else dst
        _add_ips_from_list(bucket, peers)

    # A few detectors put endpoints at the alert top level (port_scans sets
    # dst_ip there). Pre-existing canonical lists are merged, not clobbered.
    ip = _as_ip(alert.get('dst_ip'))
    if ip:
        dst.add(ip)
    _add_ips_from_list(src, alert.get('src_ips'))
    _add_ips_from_list(dst, alert.get('dst_ips'))

    # Fallback: alert['ip'] is the source when we found none; when sources
    # exist but destinations don't, a *different* alert['ip'] is the dest.
    ip0 = _as_ip(alert.get('ip'))
    if ip0:
        if not src:
            src.add(ip0)
        elif not dst and ip0 not in src:
            dst.add(ip0)

    return src, dst


def _collect_ports(alert, details):
    ports = set()
    for key in _PORT_SCALAR_KEYS:
        p = _as_port(details.get(key))
        if p:
            ports.add(p)
    for key in _PORT_LIST_KEYS:
        value = details.get(key)
        if isinstance(value, (list, tuple, set)):
            for item in value:
                p = _as_port(item)
                if p:
                    ports.add(p)
    for item in alert.get('ports') or []:
        p = _as_port(item)
        if p:
            ports.add(p)
    # Last resort: 'sport' (JA3S stores the server port there; detectors with
    # a real service port always set one of the keys above, which wins).
    if not ports:
        p = _as_port(details.get('sport'))
        if p:
            ports.add(p)
    return ports


def _collect_protocols(alert, details):
    protos = set()
    for key in _PROTO_KEYS:
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            protos.add(value.strip())
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                if isinstance(item, str) and item.strip():
                    protos.add(item.strip())
    for item in alert.get('protocols') or []:
        if isinstance(item, str) and item.strip():
            protos.add(item.strip())
    return protos


def _collect_cves(alert, details):
    cves = set()
    for item in alert.get('cves') or []:
        if isinstance(item, str) and item.strip():
            cves.add(item.strip().upper())
    parts = [alert.get('title') or '', alert.get('description') or '']
    try:
        parts.append(json.dumps(details, default=str)[:_MAX_CVE_BLOB])
    except (TypeError, ValueError):
        parts.append(str(details)[:_MAX_CVE_BLOB])
    blob = '\n'.join(parts)
    for m in CVE_RE.finditer(blob):
        cves.add(f'CVE-{m.group(1)}-{m.group(2)}')
    return cves


def normalize_alert(alert):
    """Populate the canonical fields on one alert dict, in place."""
    details = alert.get('details') or {}
    if not isinstance(details, dict):
        details = {}

    src, dst = _collect_endpoints(alert, details)
    alert['src_ips'] = sorted(src)[:_MAX_IPS]
    alert['dst_ips'] = sorted(dst)[:_MAX_IPS]
    alert['ports'] = sorted(_collect_ports(alert, details))[:_MAX_PORTS]
    alert['protocols'] = sorted(_collect_protocols(alert, details))
    alert['cves'] = sorted(_collect_cves(alert, details))

    # Backfill alert['ip'] for detectors that emit '' (ICS presence,
    # fast-flux with no client) so per-IP counters don't drop the alert.
    if not alert.get('ip'):
        if alert['src_ips']:
            alert['ip'] = alert['src_ips'][0]
        elif alert['dst_ips']:
            alert['ip'] = alert['dst_ips'][0]

    return alert


def normalize_alerts(alerts):
    """Normalize every alert in the list, in place. Returns the list."""
    for alert in alerts or []:
        try:
            normalize_alert(alert)
        except Exception as e:  # one bad alert must not break the pipeline
            print(f'[alert_schema] normalization failed for '
                  f'{alert.get("title")!r}: {e}')
    return alerts
