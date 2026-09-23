"""
Host identity: tie a machine's IPv4 and IPv6 addresses together by MAC.

A dual-stack host shows up in a capture as several unrelated IPs (one IPv4,
a link-local fe80::, maybe global / privacy IPv6 addresses). This module
turns per-packet observations into one "host" per MAC so the app can total a
machine's traffic across address families and flag hosts holding more
addresses than they should.

Pure logic, no scapy: the streaming aggregator feeds observations in; the
build step decides which bindings to trust.

Trust model
-----------
A MAC only identifies machines on the capture's own L2 segment. Everything
routed (other subnets, the internet) arrives with the ROUTER's MAC, so a
naive "Ethernet source MAC of an IP packet" binding would turn the gateway
into one giant machine owning every remote address. Therefore:

* **Authoritative** bindings come from protocols where a host states its own
  address: ARP sender, IPv6 Neighbor Discovery (NA target / NS source with
  a link-layer option) and DHCP (client address / ACK).
* **Observed** bindings (``l2``: Ethernet source + IP source) are kept only
  for MACs that do not behave like a router. A MAC is router-like when it
  carries public-IPv4-sourced traffic, or is the source of many distinct
  IPv4 / non-link-local IPv6 addresses.

Manual bindings (user decisions stored in the DB) are applied last: they win
over automatic ones, except when the capture shows the IP on a DIFFERENT
machine's MAC — then the IP is left where the capture puts it and a conflict
is reported instead of silently merging two machines.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict

# Router heuristics (distinct source addresses behind one MAC, l2 only).
GATEWAY_MIN_V4_SOURCES = 4
# IPv6 privacy addresses rotate daily and a long capture legitimately shows
# several per host, so the IPv6 bar is much higher.
GATEWAY_MIN_V6_SOURCES = 16

AUTH_SOURCES = frozenset({'arp', 'ndp', 'dhcp'})
MAX_BINDINGS = 200_000

# Name sources, most trustworthy first.
NAME_PRIORITY = ('dhcp', 'nbns', 'llmnr', 'mdns')

_CGNAT = ipaddress.ip_network('100.64.0.0/10')
_ULA = ipaddress.ip_network('fc00::/7')
_ZERO_MACS = frozenset({'00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'})


# --------------------------------------------------------------- helpers

def classify_ip(ip_str):
    """Return (family, scope) for a unicast address a host can own, else
    (None, None). Scopes: v4_private, v4_link_local, v4_public,
    v6_link_local, v6_ula, v6_global."""
    try:
        ip = ipaddress.ip_address(str(ip_str).split('%', 1)[0])
    except (ValueError, TypeError):
        return None, None
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        return None, None
    if ip.version == 4:
        if str(ip) == '255.255.255.255' or ip.is_reserved:
            return None, None
        if ip.is_link_local:
            return 4, 'v4_link_local'
        if ip.is_private or ip in _CGNAT:
            return 4, 'v4_private'
        return 4, 'v4_public'
    if ip.ipv4_mapped is not None:
        return None, None
    if ip.is_link_local:
        return 6, 'v6_link_local'
    if ip in _ULA:
        return 6, 'v6_ula'
    return 6, 'v6_global'


def normalize_mac(mac):
    if not mac:
        return None
    m = str(mac).strip().lower().replace('-', ':')
    parts = m.split(':')
    if len(parts) != 6 or any(len(p) != 2 for p in parts):
        return None
    try:
        first = int(parts[0], 16)
    except ValueError:
        return None
    if m in _ZERO_MACS or first & 0x01:  # broadcast / multicast
        return None
    return m


def is_randomized_mac(mac):
    """Locally-administered bit set: phones/laptops using a private
    (per-network random) MAC. Such a host may reappear under a new MAC."""
    try:
        return bool(int(mac.split(':', 1)[0], 16) & 0x02)
    except (ValueError, AttributeError):
        return False


def ipv6_is_eui64_of(ip_str, mac):
    """True when the IPv6 interface identifier is the modified EUI-64 of
    `mac` (a stable, MAC-derived address rather than a privacy one)."""
    try:
        ip = ipaddress.IPv6Address(ip_str)
        b = [int(x, 16) for x in mac.split(':')]
    except (ValueError, AttributeError):
        return False
    iid = bytes([b[0] ^ 0x02, b[1], b[2], 0xff, 0xfe, b[3], b[4], b[5]])
    return ip.packed[8:] == iid


def clean_host_name(name):
    """Normalise a discovered machine name, or None when unusable."""
    if name is None:
        return None
    if isinstance(name, (bytes, bytearray)):
        name = name.decode('utf-8', errors='ignore')
    n = str(name).replace('\x00', '').strip().rstrip('.')
    if n.lower().endswith('.local'):
        n = n[:-6]
    # NetBIOS names arrive space-padded to 15 chars.
    n = n.strip()
    if not n or len(n) > 63:
        return None
    if not all(ch.isprintable() for ch in n):
        return None
    if n.lower() in ('wpad', 'isatap', 'localhost', 'workgroup'):
        return None
    return n


# ---------------------------------------------------------- observations

class HostObservations:
    """Accumulates (MAC, IP) bindings and self-announced names."""

    def __init__(self):
        # (mac, ip) -> {first_ts, last_ts, sources:set, family, scope}
        self.bindings = {}
        # mac -> {source: name} (first name seen per source wins)
        self.names = defaultdict(dict)

    def observe(self, mac, ip, source, ts):
        key_mac = normalize_mac(mac)
        if key_mac is None or not ip:
            return
        ip = str(ip)
        key = (key_mac, ip)
        rec = self.bindings.get(key)
        if rec is None:
            if len(self.bindings) >= MAX_BINDINGS:
                return
            family, scope = classify_ip(ip)
            rec = {'first_ts': ts, 'last_ts': ts, 'sources': set(),
                   'family': family, 'scope': scope}
            self.bindings[key] = rec
        if rec['family'] is None:
            return
        rec['sources'].add(source)
        if ts is not None:
            if rec['first_ts'] is None or ts < rec['first_ts']:
                rec['first_ts'] = ts
            if rec['last_ts'] is None or ts > rec['last_ts']:
                rec['last_ts'] = ts

    def observe_name(self, mac, name, source):
        key_mac = normalize_mac(mac)
        clean = clean_host_name(name)
        if key_mac is None or clean is None:
            return
        self.names[key_mac].setdefault(source, clean)

    def discovered_name(self, mac):
        by_src = self.names.get(mac) or {}
        for src in NAME_PRIORITY:
            if by_src.get(src):
                return by_src[src], src
        return None, None

    def router_like_macs(self, min_v4=GATEWAY_MIN_V4_SOURCES,
                         min_v6=GATEWAY_MIN_V6_SOURCES):
        routed = set()
        v4 = defaultdict(set)
        v6 = defaultdict(set)
        for (mac, ip), rec in self.bindings.items():
            if 'l2' not in rec['sources']:
                continue
            scope = rec['scope']
            if scope == 'v4_public':
                routed.add(mac)
            elif rec['family'] == 4:
                v4[mac].add(ip)
            elif scope in ('v6_global', 'v6_ula'):
                v6[mac].add(ip)
        routed |= {m for m, s in v4.items() if len(s) >= min_v4}
        routed |= {m for m, s in v6.items() if len(s) >= min_v6}
        return routed


# ------------------------------------------------------------------ build

def _address_entry(ip, rec, mac, binding):
    entry = {
        'ip': ip,
        'family': rec.get('family') if rec else classify_ip(ip)[0],
        'scope': rec.get('scope') if rec else classify_ip(ip)[1],
        'first_ts': rec.get('first_ts') if rec else None,
        'last_ts': rec.get('last_ts') if rec else None,
        'sources': sorted(rec['sources']) if rec else [],
        'binding': binding,
    }
    entry['eui64'] = bool(mac and entry['family'] == 6
                          and ipv6_is_eui64_of(ip, mac))
    return entry


def build_hosts(obs, manual=None, excluded=None,
                min_v4=GATEWAY_MIN_V4_SOURCES, min_v6=GATEWAY_MIN_V6_SOURCES):
    """Resolve observations (+ user bindings) into hosts.

    manual:   [{'host_key', 'ip', 'mac'?}] user-made IP -> host bindings;
              host_key is the MAC for a discovered machine or 'manual:<id>'
              for a machine that exists only by user action
    excluded: [{'host_key', 'ip'}] automatic bindings the user removed

    Returns (hosts, ip_host, conflicts):
      hosts     list of host dicts (see _new_host)
      ip_host   {ip: host_key}
      conflicts [{'ip', 'host_key', 'expected_mac', 'observed_mac'}]
    """
    manual = manual or []
    excluded_pairs = {(e.get('host_key'), e.get('ip'))
                      for e in (excluded or []) if e.get('ip')}
    router_like = obs.router_like_macs(min_v4=min_v4, min_v6=min_v6)

    # One owner per IP: authoritative beats observed, then most recent.
    owner = {}
    for (mac, ip), rec in obs.bindings.items():
        if rec['family'] is None or rec['scope'] == 'v4_public':
            continue
        authoritative = bool(rec['sources'] & AUTH_SOURCES)
        if mac in router_like and not authoritative:
            continue
        if (mac, ip) in excluded_pairs:
            continue
        rank = (authoritative, rec['last_ts'] or 0)
        cur = owner.get(ip)
        if cur is None or rank > cur[0]:
            owner[ip] = (rank, mac, rec)

    hosts = {}

    def _new_host(key, mac, is_manual):
        h = {
            'host_key': key,
            'mac': mac,
            'manual': is_manual,
            'gateway_like': bool(mac and mac in router_like),
            'mac_randomized': bool(mac and is_randomized_mac(mac)),
            'discovered_name': None,
            'name_source': None,
            'addresses': {},
        }
        if mac:
            h['discovered_name'], h['name_source'] = obs.discovered_name(mac)
        hosts[key] = h
        return h

    for ip, (_rank, mac, rec) in owner.items():
        h = hosts.get(mac) or _new_host(mac, mac, False)
        h['addresses'][ip] = _address_entry(ip, rec, mac, 'auto')

    conflicts = []
    for m in manual:
        ip = m.get('ip')
        key = m.get('host_key')
        if not ip or not key:
            continue
        is_manual_host = key.startswith('manual:')
        expected_mac = normalize_mac(m.get('mac')) or (
            None if is_manual_host else normalize_mac(key))
        cur = owner.get(ip)
        observed_mac = cur[1] if cur else None
        if observed_mac and expected_mac and observed_mac != expected_mac:
            conflicts.append({'ip': ip, 'host_key': key,
                              'expected_mac': expected_mac,
                              'observed_mac': observed_mac})
            continue
        # Move the IP off its automatic owner onto the chosen host.
        if observed_mac and observed_mac in hosts and observed_mac != key:
            hosts[observed_mac]['addresses'].pop(ip, None)
        target = hosts.get(key)
        if target is None:
            target = _new_host(key, expected_mac, is_manual_host)
        target['addresses'][ip] = _address_entry(
            ip, cur[2] if cur else None, target['mac'], 'manual')

    out = []
    ip_host = {}
    for key, h in hosts.items():
        if not h['addresses']:
            continue
        addrs = sorted(h['addresses'].values(),
                       key=lambda a: (a['family'] or 9, a['ip']))
        h['addresses'] = addrs
        for a in addrs:
            ip_host[a['ip']] = key
        out.append(h)
    out.sort(key=lambda h: (h['manual'], h['host_key']))
    return out, ip_host, conflicts


def annotate_with_hosts(results, alerts, ip_host, hosts_by_key):
    """Stamp host_key on per-IP rows and on every alert's details."""
    if not ip_host:
        return
    for row in results.get('ips') or []:
        hk = ip_host.get(row.get('ip'))
        if hk:
            row['host_key'] = hk
    for alert in alerts or []:
        hk = ip_host.get(alert.get('ip'))
        if not hk:
            continue
        details = alert.get('details')
        if not isinstance(details, dict):
            details = {}
            alert['details'] = details
        details.setdefault('host_key', hk)
        mac = (hosts_by_key.get(hk) or {}).get('mac')
        if mac:
            details.setdefault('host_mac', mac)
