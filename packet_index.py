"""
Cached lightweight packet-summary index for the packet viewer.

Parsing a PCAP with scapy is expensive and the viewer paginates. Re-reading and
re-parsing the whole file on every page request is O(N) CPU *and* O(N) memory
per request (the old get_packets materialised every matching scapy packet just
to slice out 50). Instead we parse each PCAP exactly once into a compact
per-packet summary — the few fields the viewer shows plus a handful of filter
helpers — and cache that list, keyed by file identity (path + mtime + size) so a
replaced file is re-indexed automatically.

The web container runs a single Gunicorn worker (see analysis_status in
routes.common), so a process-global cache is shared across all request threads.
The cache is a small LRU; raise PKT_INDEX_CACHE_SIZE if you serve many distinct
scans concurrently (each entry holds up to MAX_VIEWER_PKTS compact dicts).
"""
import os
import threading
from collections import OrderedDict

MAX_VIEWER_PKTS = 100_000
_CACHE_SIZE = max(1, int(os.environ.get('PKT_INDEX_CACHE_SIZE', '3')))

# Fields returned to the client (the rest are underscore-prefixed filter helpers).
_PUBLIC_FIELDS = ('number', 'time', 'length', 'protocol', 'src', 'dst', 'info')

_cache = OrderedDict()          # key -> list[dict]
_cache_lock = threading.Lock()


def _classify(pkt, number, time_offset, scapy):
    """Build one compact summary entry for *pkt*.

    Display fields ('protocol', 'src', 'dst', 'info') reproduce exactly what the
    old inline get_packets logic produced. Underscore-prefixed fields are filter
    helpers and are stripped before the entry reaches the client. Filter helpers
    are derived from raw layer presence (independent of the displayed L3) so that
    e.g. a TCP-over-IPv6 packet still matches the TCP/HTTP filters, matching the
    original _matches() semantics.
    """
    IP, IPv6, TCP, UDP, ICMP, ARP, DNS = scapy

    # --- filter helpers (layer presence, independent of display) ---
    has_ipaddr = (IP in pkt) or (IPv6 in pkt)
    l4 = ''
    sport = dport = None
    if TCP in pkt:
        l4 = 'TCP'
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        l4 = 'UDP'
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    elif ICMP in pkt:
        l4 = 'ICMP'
    has_dns = DNS in pkt
    has_arp = ARP in pkt

    info = {
        'number': number,
        'time': time_offset,
        'length': len(pkt),
        'protocol': 'Other',
        'src': '',
        'dst': '',
        'info': '',
        '_ipaddr': has_ipaddr,
        '_l4': l4,
        '_sport': sport,
        '_dport': dport,
        '_dns': has_dns,
        '_arp': has_arp,
    }

    if IP in pkt:
        info['src'] = pkt[IP].src
        info['dst'] = pkt[IP].dst
        if TCP in pkt:
            flags = str(pkt[TCP].flags)
            info['protocol'] = 'TCP'
            info['info'] = f"{sport} → {dport} [{flags}] Len={len(pkt[TCP].payload)}"
            if dport == 80 or sport == 80:
                info['protocol'] = 'HTTP'
            elif dport == 443 or sport == 443:
                info['protocol'] = 'TLS'
            elif dport == 22 or sport == 22:
                info['protocol'] = 'SSH'
            elif dport == 21 or sport == 21:
                info['protocol'] = 'FTP'
            elif dport == 23 or sport == 23:
                info['protocol'] = 'Telnet'
            elif dport == 53 or sport == 53:
                info['protocol'] = 'DNS'
        elif UDP in pkt:
            info['protocol'] = 'UDP'
            info['info'] = f"{sport} → {dport} Len={len(pkt[UDP].payload)}"
            if dport == 53 or sport == 53:
                info['protocol'] = 'DNS'
                if DNS in pkt and pkt[DNS].qr == 0:
                    try:
                        qname = pkt[DNS].qd.qname
                        if isinstance(qname, bytes):
                            qname = qname.decode('utf-8', errors='ignore')
                        info['info'] = f"Query: {qname.rstrip('.')}"
                    except Exception:
                        pass
        elif ICMP in pkt:
            info['protocol'] = 'ICMP'
            info['info'] = f"Type={pkt[ICMP].type} Code={pkt[ICMP].code}"
    elif IPv6 in pkt:
        info['src'] = pkt[IPv6].src
        info['dst'] = pkt[IPv6].dst
        info['protocol'] = 'IPv6'
    elif ARP in pkt:
        info['protocol'] = 'ARP'
        info['src'] = pkt[ARP].psrc
        info['dst'] = pkt[ARP].pdst
        op = "Request" if pkt[ARP].op == 1 else "Reply"
        info['info'] = f"{op}: {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"

    return info


def _build_index(filepath, max_pkts):
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, DNS
    scapy = (IP, IPv6, TCP, UDP, ICMP, ARP, DNS)

    entries = []
    first_time = 0.0
    first_seen = False
    with PcapReader(filepath) as reader:
        for i, p in enumerate(reader):
            if i >= max_pkts:
                break
            if not first_seen:
                try:
                    first_time = float(p.time)
                except Exception:
                    first_time = 0.0
                first_seen = True
            try:
                t = round(float(p.time) - first_time, 6)
            except Exception:
                t = 0.0
            entries.append(_classify(p, i + 1, t, scapy))
    return entries


def _cache_key(filepath):
    try:
        st = os.stat(filepath)
        return (os.path.abspath(filepath), int(st.st_mtime), st.st_size)
    except OSError:
        return (os.path.abspath(filepath), 0, 0)


def get_packet_index(filepath, max_pkts=MAX_VIEWER_PKTS):
    """Return the cached compact summary list for *filepath*, building it once.

    Cache hits are pure in-memory dict lists (no scapy). The actual parse runs
    *outside* the lock; two threads racing to index the same uncached file just
    do duplicate, idempotent work rather than serialising the whole viewer.
    """
    key = _cache_key(filepath)
    with _cache_lock:
        entry = _cache.get(key)
        if entry is not None:
            _cache.move_to_end(key)
            return entry

    entries = _build_index(filepath, max_pkts)

    with _cache_lock:
        _cache[key] = entries
        _cache.move_to_end(key)
        while len(_cache) > _CACHE_SIZE:
            _cache.popitem(last=False)
    return entries


def matches(entry, filter_ip, filter_protocol):
    """Evaluate the viewer filters against a compact entry (same semantics as
    the original per-packet _matches)."""
    if filter_ip:
        if not entry['_ipaddr']:
            return False
        if entry['src'] != filter_ip and entry['dst'] != filter_ip:
            return False
    if filter_protocol:
        l4 = entry['_l4']
        if filter_protocol == 'TCP' and l4 != 'TCP':
            return False
        if filter_protocol == 'UDP' and l4 != 'UDP':
            return False
        if filter_protocol == 'ICMP' and l4 != 'ICMP':
            return False
        if filter_protocol == 'ARP' and not entry['_arp']:
            return False
        if filter_protocol == 'DNS' and not entry['_dns']:
            return False
        if filter_protocol == 'HTTP' and not (
                l4 == 'TCP' and (entry['_sport'] == 80 or entry['_dport'] == 80)):
            return False
        if filter_protocol == 'HTTPS' and not (
                l4 == 'TCP' and (entry['_sport'] == 443 or entry['_dport'] == 443)):
            return False
    return True


def public_view(entry):
    """Strip filter-helper fields, leaving only what the client expects."""
    return {k: entry[k] for k in _PUBLIC_FIELDS}


__all__ = [
    'MAX_VIEWER_PKTS', 'get_packet_index', 'matches', 'public_view',
]
