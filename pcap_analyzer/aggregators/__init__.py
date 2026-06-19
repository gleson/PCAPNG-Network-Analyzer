"""
Streaming aggregators.

Aggregators populate the analyzer's results dict in a single pass over packets,
replacing the legacy _extract_* batch methods. Each aggregator implements
update(pkt) (called per PktView) and finalize(results) (writes the results
dict). Order in STREAMING_AGGREGATORS matters: HttpInfoAggregator depends on
TcpFlowAggregator having finalized first.

Extracted from pcap_analyzer/_core.py.
"""

import math
import hashlib
import ipaddress
import time
from collections import defaultdict, Counter
from datetime import datetime

from scapy.all import IP, IPv6, TCP, UDP, ARP, DNS, DNSQR, DNSRR, ICMP, Raw, Ether
from scapy.layers.http import HTTP, HTTPRequest  # noqa: F401  (referenced by some aggregators)

try:
    from scapy.layers.dhcp import DHCP as _ScapyDHCP
except Exception:
    _ScapyDHCP = None  # type: ignore

# Safe XML parsing (used by aggregators that decode SOAP/SMB-XML payloads).
try:
    import defusedxml.ElementTree as _ET
    _xml_fromstring = _ET.fromstring
except ImportError:
    import xml.etree.ElementTree as _ET_std  # noqa: F401
    _xml_fromstring = _ET_std.fromstring


_JA4H_VER_MAP = {
    'HTTP/1.1': '11',
    'HTTP/1.0': '10',
    'HTTP/2.0': '20',
    'HTTP/2':   '20',
    'HTTP/3.0': '30',
    'HTTP/3':   '30',
    'HTTP/0.9': '09',
}


def _ja4h_sha12(s):
    if not s:
        return '000000000000'
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _compute_ja4h(method, http_version, header_names_order,
                  cookie_value, referer, accept_lang):
    """JA4H per FoxIO spec (https://github.com/FoxIO-LLC/ja4).

    Layout: a_b_c_d
        a = method2 + ver2 + cookie(c|n) + referer(r|n) + headercount2 + lang4
        b = sha256[:12] of header names (in wire order, excluding Cookie+Referer)
        c = sha256[:12] of cookie keys (sorted)
        d = sha256[:12] of cookie key=value pairs (sorted by key)
    """
    m2 = (method or '').lower()[:2].ljust(2, '0')
    ver = _JA4H_VER_MAP.get((http_version or '').upper().strip(), '00')
    cookie_flag = 'c' if cookie_value else 'n'
    referer_flag = 'r' if referer else 'n'
    # Header count excludes Cookie and Referer (per spec).
    countable = [
        n for n in header_names_order
        if n.lower() not in ('cookie', 'referer')
    ]
    hcount = min(len(countable), 99)
    # Accept-Language: first primary tag, lowercased, padded/truncated to 4
    # chars. '0000' when absent. Hyphens kept (e.g., 'en-u' from 'en-US').
    lang_slot = '0000'
    if accept_lang:
        first = accept_lang.split(',', 1)[0].split(';', 1)[0].strip().lower()
        first = first.replace('-', '')
        if first:
            lang_slot = (first + '0000')[:4]
    a = f'{m2}{ver}{cookie_flag}{referer_flag}{hcount:02d}{lang_slot}'
    b_input = ','.join(countable)
    b = _ja4h_sha12(b_input)
    # Cookies: split on ';' into name[=value] pairs.
    cookie_keys = []
    cookie_pairs = []
    if cookie_value:
        for raw in cookie_value.split(';'):
            raw = raw.strip()
            if not raw:
                continue
            if '=' in raw:
                k, _, v = raw.partition('=')
                k = k.strip()
                v = v.strip()
            else:
                k, v = raw, ''
            if k:
                cookie_keys.append(k)
                cookie_pairs.append(f'{k}={v}')
    cookie_keys.sort()
    cookie_pairs.sort()
    c = _ja4h_sha12(','.join(cookie_keys)) if cookie_keys else '000000000000'
    d = _ja4h_sha12(','.join(cookie_pairs)) if cookie_pairs else '000000000000'
    return f'{a}_{b}_{c}_{d}'


# === Streaming aggregator framework (Fase 3 lote 4) ============================
# Agregadores incrementais que substituem os métodos _extract_xxx() legados.
# Cada um acumula estado durante update(pkt) na passada de load e, em
# finalize(results), escreve no dicionário de resultados final.


class StreamingAggregator:
    """Base para agregadores incrementais. Update por pacote, finalize escreve
    em results dict.
    """
    name = 'base'

    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.settings = analyzer.settings

    def update(self, pkt):  # noqa: ARG002
        pass

    def finalize(self, results):  # noqa: ARG002
        pass


class SummaryAggregator(StreamingAggregator):
    """Substitui _extract_summary. Acumula contagem, bytes, primeiro/último ts."""
    name = 'summary'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.count = 0
        self.total_bytes = 0
        self.first_ts = None
        self.last_ts = None

    def update(self, pkt):
        self.count += 1
        self.total_bytes += len(pkt)
        ts = pkt.time
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts = ts
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts

    def finalize(self, results):
        if self.count == 0:
            return
        first = self.first_ts or 0
        last = self.last_ts or 0
        results['summary'] = {
            'filename': self.analyzer.filepath.split('/')[-1],
            'analyzed_at': datetime.now().isoformat(),
            'packet_count': self.count,
            'duration': float(last - first),
            'start_time': datetime.fromtimestamp(float(first)).isoformat(),
            'end_time': datetime.fromtimestamp(float(last)).isoformat(),
            'total_bytes': self.total_bytes,
            'truncated': bool(getattr(self.analyzer, '_truncated', False)),
        }


class MacIpAggregator(StreamingAggregator):
    """Substitui _extract_mac_ip_mapping. Acumula mac->ips e ip->macs."""
    name = 'mac_ip'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.mac_to_ips = defaultdict(set)
        self.ip_to_macs = defaultdict(set)

    def update(self, pkt):
        if Ether in pkt:
            e = pkt[Ether]
            src_mac, dst_mac = e.src, e.dst
            if IP in pkt:
                ip = pkt[IP]
                if src_mac and ip.src:
                    self.mac_to_ips[src_mac].add(ip.src)
                    self.ip_to_macs[ip.src].add(src_mac)
                if dst_mac and ip.dst:
                    self.mac_to_ips[dst_mac].add(ip.dst)
                    self.ip_to_macs[ip.dst].add(dst_mac)
            if IPv6 in pkt:
                v6 = pkt[IPv6]
                if src_mac and v6.src:
                    self.mac_to_ips[src_mac].add(v6.src)
                    self.ip_to_macs[v6.src].add(src_mac)
                if dst_mac and v6.dst:
                    self.mac_to_ips[dst_mac].add(v6.dst)
                    self.ip_to_macs[v6.dst].add(dst_mac)
        if ARP in pkt:
            a = pkt[ARP]
            if a.hwsrc and a.psrc:
                self.mac_to_ips[a.hwsrc].add(a.psrc)
                self.ip_to_macs[a.psrc].add(a.hwsrc)

    def finalize(self, results):
        results['mac_ip_mapping'] = {
            mac: list(ips) for mac, ips in self.mac_to_ips.items()
        }
        results['ip_mac_mapping'] = {
            ip: list(macs) for ip, macs in self.ip_to_macs.items()
        }


class IpStatsAggregator(StreamingAggregator):
    """Substitui _extract_ips. Estatísticas por IP."""
    name = 'ips'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.ip_stats = defaultdict(lambda: {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'protocols': set(),
            'ports': set(),
            'is_local': False,
            'macs': set(),
        })

    def update(self, pkt):
        pkt_size = len(pkt)
        if IP in pkt:
            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
            s = self.ip_stats[src_ip]
            s['packets_sent'] += 1
            s['bytes_sent'] += pkt_size
            s['is_local'] = self.analyzer._is_local_ip(src_ip)
            d = self.ip_stats[dst_ip]
            d['packets_received'] += 1
            d['bytes_received'] += pkt_size
            d['is_local'] = self.analyzer._is_local_ip(dst_ip)
            if TCP in pkt:
                s['protocols'].add('TCP')
                s['ports'].add(pkt[TCP].dport)
            elif UDP in pkt:
                s['protocols'].add('UDP')
                s['ports'].add(pkt[UDP].dport)
            elif ICMP in pkt:
                s['protocols'].add('ICMP')
            if Ether in pkt:
                s['macs'].add(pkt[Ether].src)
                d['macs'].add(pkt[Ether].dst)
        if IPv6 in pkt:
            v6 = pkt[IPv6]
            src_ip, dst_ip = v6.src, v6.dst
            s = self.ip_stats[src_ip]
            s['packets_sent'] += 1
            s['bytes_sent'] += pkt_size
            s['is_local'] = self.analyzer._is_local_ip(src_ip)
            s['protocols'].add('IPv6')
            d = self.ip_stats[dst_ip]
            d['packets_received'] += 1
            d['bytes_received'] += pkt_size
            d['is_local'] = self.analyzer._is_local_ip(dst_ip)
            if Ether in pkt:
                s['macs'].add(pkt[Ether].src)
                d['macs'].add(pkt[Ether].dst)

    def finalize(self, results):
        ips_list = [
            {
                'ip': ip,
                'is_local': data['is_local'],
                'packets_sent': data['packets_sent'],
                'packets_received': data['packets_received'],
                'bytes_sent': data['bytes_sent'],
                'bytes_received': data['bytes_received'],
                'protocols': list(data['protocols']),
                'ports': sorted(list(data['ports']))[:50],
                'alert_count': 0,
                'macs': list(data['macs']),
            }
            for ip, data in self.ip_stats.items()
        ]
        ips_list.sort(
            key=lambda x: x['bytes_sent'] + x['bytes_received'], reverse=True,
        )
        results['ips'] = ips_list


class ProtocolStatsAggregator(StreamingAggregator):
    """Substitui _extract_protocols. Stats por protocolo + por IP/protocolo."""
    name = 'protocols'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.smb_ports = analyzer.SMB_PORTS
        self.protocol_stats = defaultdict(lambda: {
            'packets': 0, 'bytes': 0, 'ips': set(),
        })
        self.protocol_ip_stats = defaultdict(
            lambda: defaultdict(lambda: {'packets': 0, 'bytes': 0}),
        )
        # ip -> proto -> {packets, bytes, peers: peer_ip -> {packets, bytes}}
        self.ip_protocol_stats = defaultdict(
            lambda: defaultdict(lambda: {
                'packets': 0, 'bytes': 0,
                'peers': defaultdict(lambda: {'packets': 0, 'bytes': 0}),
            }),
        )
        self.total_bytes = 0

    def _add(self, proto, pkt_size, src_ip, dst_ip):
        ps = self.protocol_stats[proto]
        ps['packets'] += 1
        ps['bytes'] += pkt_size
        if src_ip:
            ps['ips'].add(src_ip)
            self.protocol_ip_stats[proto][src_ip]['packets'] += 1
            self.protocol_ip_stats[proto][src_ip]['bytes'] += pkt_size
            sp = self.ip_protocol_stats[src_ip][proto]
            sp['packets'] += 1
            sp['bytes'] += pkt_size
            if dst_ip:
                peer = sp['peers'][dst_ip]
                peer['packets'] += 1
                peer['bytes'] += pkt_size
        if dst_ip:
            ps['ips'].add(dst_ip)
            self.protocol_ip_stats[proto][dst_ip]['packets'] += 1
            self.protocol_ip_stats[proto][dst_ip]['bytes'] += pkt_size
            dp = self.ip_protocol_stats[dst_ip][proto]
            dp['packets'] += 1
            dp['bytes'] += pkt_size
            if src_ip:
                peer = dp['peers'][src_ip]
                peer['packets'] += 1
                peer['bytes'] += pkt_size

    def update(self, pkt):
        pkt_size = len(pkt)
        self.total_bytes += pkt_size
        src_ip = dst_ip = None
        if IP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        if TCP in pkt:
            self._add('TCP', pkt_size, src_ip, dst_ip)
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if dport == 80 or sport == 80:
                self._add('HTTP', pkt_size, src_ip, dst_ip)
            elif dport == 443 or sport == 443:
                self._add('HTTPS', pkt_size, src_ip, dst_ip)
            elif dport == 22 or sport == 22:
                self._add('SSH', pkt_size, src_ip, dst_ip)
            elif dport == 21 or sport == 21:
                self._add('FTP', pkt_size, src_ip, dst_ip)
            elif dport == 23 or sport == 23:
                self._add('Telnet', pkt_size, src_ip, dst_ip)
            elif dport == 25 or sport == 25:
                self._add('SMTP', pkt_size, src_ip, dst_ip)
            elif dport in self.smb_ports or sport in self.smb_ports:
                self._add('SMB', pkt_size, src_ip, dst_ip)
            # Cleartext HTTP/2 preface (h2c): "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            # Surfacing it counts h2c traffic in the protocol breakdown and
            # also flags the (otherwise rare) cleartext-HTTP/2 case.
            if Raw in pkt:
                try:
                    head = bytes(pkt[Raw].load)[:24]
                    if head.startswith(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'):
                        self._add('HTTP/2', pkt_size, src_ip, dst_ip)
                except Exception:
                    pass
        elif UDP in pkt:
            self._add('UDP', pkt_size, src_ip, dst_ip)
            u = pkt[UDP]
            if u.dport == 53 or u.sport == 53:
                self._add('DNS', pkt_size, src_ip, dst_ip)
            elif (u.dport in (443, 80) or u.sport in (443, 80)) and Raw in pkt:
                # QUIC long-header detection. RFC 9000 §17.2: a long header has
                # the high bit (0x80) set in byte 0; the next 4 bytes are the
                # QUIC version. Zero version means Version Negotiation, which
                # we still count as QUIC. The check is intentionally cheap so
                # we don't pay a parsing tax on every UDP packet.
                try:
                    payload = bytes(u.payload) if not hasattr(u, 'load') else bytes(u.payload)
                    if len(payload) >= 5 and (payload[0] & 0x80):
                        self._add('QUIC', pkt_size, src_ip, dst_ip)
                except Exception:
                    pass
        elif ICMP in pkt:
            self._add('ICMP', pkt_size, src_ip, dst_ip)
        elif ARP in pkt:
            arp_src = pkt[ARP].psrc
            arp_dst = pkt[ARP].pdst
            self._add('ARP', pkt_size, arp_src, arp_dst)

    def finalize(self, results):
        is_local = self.analyzer._is_local_ip
        protocols = []
        protocol_ips_out = {}
        for proto, data in self.protocol_stats.items():
            percentage = (data['bytes'] / self.total_bytes * 100
                          if self.total_bytes > 0 else 0)
            ip_entries = self.protocol_ip_stats[proto]
            ip_list = [
                {
                    'ip': ip,
                    'is_local': is_local(ip),
                    'packets': s['packets'],
                    'bytes': s['bytes'],
                }
                for ip, s in ip_entries.items()
            ]
            ip_list.sort(key=lambda x: x['bytes'], reverse=True)
            protocol_ips_out[proto] = ip_list
            protocols.append({
                'name': proto,
                'packets': data['packets'],
                'bytes': data['bytes'],
                'percentage': round(percentage, 2),
                'ip_count': len(data['ips']),
            })
        protocols.sort(key=lambda x: x['bytes'], reverse=True)
        results['protocols'] = protocols
        results['protocol_ips'] = protocol_ips_out

        ip_protocols_out = []
        for ip, proto_map in self.ip_protocol_stats.items():
            total_packets = 0
            total_bytes = 0
            proto_list = []
            for proto, pdata in proto_map.items():
                total_packets += pdata['packets']
                total_bytes += pdata['bytes']
                peers_list = [
                    {
                        'ip': peer_ip,
                        'is_local': is_local(peer_ip),
                        'packets': pv['packets'],
                        'bytes': pv['bytes'],
                    }
                    for peer_ip, pv in pdata['peers'].items()
                ]
                peers_list.sort(key=lambda x: x['bytes'], reverse=True)
                proto_list.append({
                    'name': proto,
                    'packets': pdata['packets'],
                    'bytes': pdata['bytes'],
                    'peers': peers_list,
                })
            proto_list.sort(key=lambda x: x['bytes'], reverse=True)
            ip_protocols_out.append({
                'ip': ip,
                'is_local': is_local(ip),
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'protocol_count': len(proto_list),
                'protocols': proto_list,
            })
        ip_protocols_out.sort(key=lambda x: x['total_bytes'], reverse=True)
        results['ip_protocols'] = ip_protocols_out


class TimelineAggregator(StreamingAggregator):
    """Substitui _generate_traffic_timeline. Bins de 10s."""
    name = 'timeline'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.interval = 10
        self.first_ts = None
        self.timeline = defaultdict(lambda: {'bytes': 0, 'packets': 0})

    def update(self, pkt):
        ts = float(pkt.time)
        if self.first_ts is None:
            self.first_ts = ts
        bucket = int((ts - self.first_ts) / self.interval) * self.interval
        rec = self.timeline[bucket]
        rec['bytes'] += len(pkt)
        rec['packets'] += 1

    def finalize(self, results):
        first = self.first_ts or 0
        results['traffic_timeline'] = [
            {
                'timestamp': first + bucket,
                'bytes': data['bytes'],
                'packets': data['packets'],
            }
            for bucket, data in sorted(self.timeline.items())
        ]


class TcpFlowAggregator(StreamingAggregator):
    """Substitui _build_tcp_flows. Acumula bytes por (src,sport,dst,dport)
    em pacotes TCP+Raw. No finalize, congela em dict de bytes e atribui a
    analyzer._tcp_flows para uso pelos detectores TLS/HTTP.

    Limite de memória: os detectores que consomem _tcp_flows (TLS/HTTP) só
    inspecionam o INÍCIO do stream (ClientHello, request line + headers).
    Acumular o fluxo inteiro de captures grandes (8 GB+) estoura a RAM e o
    worker é morto pelo OOM-killer. Por isso cada fluxo é limitado a
    `tcp_flow_max_bytes` (default 64 KiB) — suficiente para o handshake TLS
    e cabeçalhos HTTP, e descartamos o resto."""
    name = 'tcp_flows'

    DEFAULT_MAX_FLOW_BYTES = 65536

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.flows = defaultdict(bytearray)
        self.max_flow_bytes = int(
            (self.settings.get('thresholds') or {}).get(
                'tcp_flow_max_bytes', self.DEFAULT_MAX_FLOW_BYTES)
        )

    def update(self, pkt):
        if TCP not in pkt or Raw not in pkt:
            return
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = str(pkt[IPv6].src), str(pkt[IPv6].dst)
        else:
            return
        try:
            key = (src, pkt[TCP].sport, dst, pkt[TCP].dport)
            buf = self.flows[key]
            remaining = self.max_flow_bytes - len(buf)
            if remaining <= 0:
                return
            payload = bytes(pkt[Raw])
            buf += payload[:remaining] if len(payload) > remaining else payload
        except Exception:
            pass

    def finalize(self, results):
        self.analyzer._tcp_flows = {
            k: bytes(v) for k, v in self.flows.items() if v
        }


class FileCarvingFlowAggregator(StreamingAggregator):
    """Per-flow byte accumulator dedicated to file carving from HTTP traffic.

    TcpFlowAggregator caps each flow at 64 KiB — enough for TLS handshakes
    and HTTP headers, but bodies are truncated, which makes file extraction
    impossible. This aggregator keeps a separate, deeper buffer scoped to
    likely-HTTP ports so the carver gets full payloads without changing the
    memory profile of the detectors that already rely on TcpFlowAggregator.

    Opt-in: when settings.carving.enabled is False the aggregator is a no-op.
    Two caps guard memory:
        per_flow_max  — bytes per (src,sport,dst,dport)   default 50 MB + 16 KB
        total_max     — sum across all tracked flows      default 256 MB
    When the total cap is hit, new flows are ignored (already-tracked flows
    keep filling until their own per-flow cap).
    """
    name = 'carving_flows'

    LIKELY_HTTP_PORTS = (80, 8080, 8000, 8008, 3000, 5000)
    DEFAULT_PER_FLOW_MAX = 50 * 1024 * 1024 + 16 * 1024
    DEFAULT_TOTAL_MAX = 256 * 1024 * 1024

    def __init__(self, analyzer):
        super().__init__(analyzer)
        carving = analyzer.settings.get('carving') or {}
        self.enabled = bool(carving.get('enabled', True))
        max_file = int(
            carving.get('max_file_size') or self.DEFAULT_PER_FLOW_MAX - 16 * 1024
        )
        self.per_flow_max = max_file + 16 * 1024  # headers headroom
        self.total_max = int(
            carving.get('total_max_bytes') or self.DEFAULT_TOTAL_MAX
        )
        self.flows = defaultdict(bytearray)
        self.total_bytes = 0
        self.dropped_new_flows = 0

    def update(self, pkt):
        if not self.enabled:
            return
        if TCP not in pkt or Raw not in pkt:
            return
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = str(pkt[IPv6].src), str(pkt[IPv6].dst)
        else:
            return
        try:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        except Exception:
            return
        if (sport not in self.LIKELY_HTTP_PORTS
                and dport not in self.LIKELY_HTTP_PORTS):
            return
        key = (src, sport, dst, dport)
        existing = key in self.flows
        if not existing and self.total_bytes >= self.total_max:
            # Memory ceiling reached — stop accepting new flows. Pre-existing
            # flows keep filling because the in-flight HTTP response we want
            # to carve has probably already started.
            self.dropped_new_flows += 1
            return
        buf = self.flows[key]
        remaining_flow = self.per_flow_max - len(buf)
        remaining_total = self.total_max - self.total_bytes
        room = min(remaining_flow, remaining_total)
        if room <= 0:
            return
        try:
            payload = bytes(pkt[Raw])
        except Exception:
            return
        take = payload[:room] if len(payload) > room else payload
        buf += take
        self.total_bytes += len(take)

    def finalize(self, results):
        if not self.enabled:
            self.analyzer._carving_flows = {}
            return
        self.analyzer._carving_flows = {
            k: bytes(v) for k, v in self.flows.items() if v
        }
        if self.dropped_new_flows:
            print(f"[carving_flows] hit {self.total_max} bytes ceiling, "
                  f"dropped {self.dropped_new_flows} new flows")


class TlsInfoAggregator(StreamingAggregator):
    """Streaming TLS handshake collector. In one load pass we extract
    ClientHello (JA3 + SNI), ServerHello (JA3S), and Certificate (X.509:
    CN/SAN/issuer/validity). Certificate chains that span multiple TCP
    segments are parsed best-effort — large chains may be missed because the
    current per-packet walker does not reassemble at the TLS-record layer."""
    name = 'tls_info'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.info = {
            'client_hellos': [],
            'server_hellos': [],
            'certificates': [],
        }

    def update(self, pkt):
        if TCP not in pkt or IP not in pkt or Raw not in pkt:
            return
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return
        if len(payload) < 6 or payload[0] != 0x16:
            return
        from .. import tls as _tls
        idx = 0
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        ts = float(pkt.time)
        while idx + 5 <= len(payload):
            if payload[idx] != 0x16:
                break
            rec_len = (payload[idx + 3] << 8) | payload[idx + 4]
            if rec_len == 0 or idx + 5 + rec_len > len(payload):
                break
            record = payload[idx + 5:idx + 5 + rec_len]
            idx += 5 + rec_len
            if not record:
                continue
            hs_type = record[0]
            if hs_type == 0x01:
                ch = _tls.parse_client_hello(record)
                if ch:
                    ch.update({'src': src, 'dst': dst,
                               'sport': sport, 'dport': dport, 'ts': ts})
                    self.info['client_hellos'].append(ch)
            elif hs_type == 0x02:
                sh = _tls.parse_server_hello(record)
                if sh:
                    sh.update({'src': src, 'dst': dst,
                               'sport': sport, 'dport': dport, 'ts': ts})
                    self.info['server_hellos'].append(sh)
            elif hs_type == 0x0B:
                certs = _tls.parse_certificate_message(record)
                if certs:
                    # Server is the source of the Certificate message; the
                    # SNI/host the client asked for sits on the matching
                    # ClientHello we already captured. Attach flow metadata
                    # so post-detectors can correlate.
                    self.info['certificates'].append({
                        'src': src, 'dst': dst,
                        'sport': sport, 'dport': dport, 'ts': ts,
                        'chain': certs,
                    })

    def finalize(self, results):
        self.analyzer._tls_info = self.info


class SshInfoAggregator(StreamingAggregator):
    """Capture plaintext SSH banners and KEXINIT messages. HASSH/HASSH-Server
    md5s are computed per KEXINIT and attached to analyzer._ssh_info.

    Direction (client vs server) is inferred via the SSH-2.0 banner that each
    side sends first. The peer whose banner we observe first on a flow is
    fixed as the *server* for that flow (RFC 4253 §4.2 says server typically
    speaks first, but we tolerate either). If we never see banners we fall
    back to standard port 22: src_port==22 → server side, dst_port==22 →
    client side."""
    name = 'ssh_info'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.info = {
            'banners': [],
            'kexinits': [],
        }
        # flow key (frozenset of ip:port pairs) → ip that sent banner first
        self._server_ip = {}

    @staticmethod
    def _flow_key(a_ip, a_port, b_ip, b_port):
        return frozenset(((a_ip, a_port), (b_ip, b_port)))

    def update(self, pkt):
        if TCP not in pkt or IP not in pkt or Raw not in pkt:
            return
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return
        if not payload:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        # Heuristic prefilter: only proceed if traffic looks SSH-shaped, to
        # keep this aggregator cheap on non-SSH packets.
        likely_ssh_port = 22 in (sport, dport)
        from .. import ssh as _ssh
        is_banner = _ssh.looks_like_ssh_banner(payload)
        if not is_banner and not likely_ssh_port:
            return
        ts = float(pkt.time)
        key = self._flow_key(src, sport, dst, dport)

        if is_banner:
            try:
                line_end = payload.find(b'\r\n')
                if line_end < 0:
                    line_end = payload.find(b'\n')
                banner = payload[:line_end if line_end > 0 else 255]
                banner_str = banner.decode('ascii', errors='ignore')
            except Exception:
                banner_str = ''
            self.info['banners'].append({
                'src': src, 'dst': dst,
                'sport': sport, 'dport': dport,
                'ts': ts, 'banner': banner_str,
            })
            # First banner on this flow → that IP is the server. SSH spec
            # has the server announce first; clients-first is rarer but the
            # important thing is consistency within the flow.
            if key not in self._server_ip:
                self._server_ip[key] = src
            return

        # Try to peel a KEXINIT off the payload.
        body = _ssh.extract_kexinit_from_tcp_payload(payload)
        if not body:
            return
        parsed = _ssh.parse_kexinit(body)
        if not parsed:
            return
        server_ip = self._server_ip.get(key)
        if server_ip is None:
            # Fallback: port 22 is the server.
            if sport == 22 and dport != 22:
                server_ip = src
            elif dport == 22 and sport != 22:
                server_ip = dst
        is_server = (server_ip == src) if server_ip else (sport == 22)
        parsed.update({
            'src': src, 'dst': dst,
            'sport': sport, 'dport': dport,
            'ts': ts,
            'is_server': bool(is_server),
        })
        self.info['kexinits'].append(parsed)

    def finalize(self, results):
        self.analyzer._ssh_info = self.info


class HttpInfoAggregator(StreamingAggregator):
    """Substitui _extract_http_info. Pass 1 (per-packet) durante load; Pass 2
    (sobre tcp_flows reassembled) no finalize — depende de TcpFlowAggregator
    rodar antes."""
    name = 'http_info'

    LIKELY_HTTP_PORTS = (80, 8080, 8000, 8008, 3000, 5000)

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.info = {'requests': []}
        self.seen_keys = set()

    def _parse_http_payload(self, payload, src, dst, sport, dport, ts):
        if len(payload) < 16:
            return
        head = payload[:16].upper()
        if not any(head.startswith(m) for m in self.analyzer.HTTP_METHODS):
            return
        try:
            text = payload.decode('latin-1', errors='ignore')
        except Exception:
            return
        req_line_end = text.find('\r\n')
        if req_line_end < 0:
            return
        parts = text[:req_line_end].split(' ', 2)
        if len(parts) < 2:
            return
        method = parts[0].upper()
        path = parts[1]
        http_version = parts[2].strip() if len(parts) >= 3 else ''
        dedup_key = (src, sport, dst, dport, method, path[:200])
        if dedup_key in self.seen_keys:
            return
        self.seen_keys.add(dedup_key)
        headers_end = text.find('\r\n\r\n', req_line_end)
        if headers_end < 0:
            headers_block = text[req_line_end + 2:]
            body = ''
        else:
            headers_block = text[req_line_end + 2:headers_end]
            body = text[headers_end + 4:headers_end + 4 + 4096]
        host = ''
        user_agent = ''
        cookie_value = ''
        referer = ''
        accept_lang = ''
        header_names_order = []  # preserves wire order, original case
        for line in headers_block.split('\r\n'):
            if ':' not in line:
                continue
            name, _, value = line.partition(':')
            name = name.strip()
            value = value.strip()
            if not name:
                continue
            header_names_order.append(name)
            lower = name.lower()
            if lower == 'host':
                host = value
            elif lower == 'user-agent':
                user_agent = value
            elif lower == 'cookie':
                cookie_value = value
            elif lower == 'referer':
                referer = value
            elif lower == 'accept-language':
                accept_lang = value
        ja4h = _compute_ja4h(
            method, http_version, header_names_order,
            cookie_value, referer, accept_lang,
        )
        self.info['requests'].append({
            'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
            'method': method, 'path': path,
            'host': host, 'user_agent': user_agent,
            'headers_sample': headers_block[:2048],
            'body_sample': body,
            'ts': ts,
            'ja4h': ja4h,
        })

    def update(self, pkt):
        # Pass 1: parse single-segment HTTP requests inline.
        if TCP not in pkt or IP not in pkt or Raw not in pkt:
            return
        try:
            self._parse_http_payload(
                bytes(pkt[Raw].load),
                pkt[IP].src, pkt[IP].dst,
                pkt[TCP].sport, pkt[TCP].dport,
                float(pkt.time),
            )
        except Exception:
            pass

    def finalize(self, results):
        # Pass 2: reassembled flows — catches multi-segment requests. Depende
        # de TcpFlowAggregator já ter populado self.analyzer._tcp_flows.
        tcp_flows = getattr(self.analyzer, '_tcp_flows', None) or {}
        for (src, sport, dst, dport), payload in tcp_flows.items():
            if (dport not in self.LIKELY_HTTP_PORTS
                    and sport not in (80, 8080)):
                continue
            try:
                self._parse_http_payload(payload, src, dst, sport, dport, 0.0)
            except Exception:
                continue
        self.analyzer._http_info = self.info


class QuicHttp2Aggregator(StreamingAggregator):
    """Identify QUIC flows (HTTP/3) and HTTP/2 sessions.

    QUIC: RFC 9000 §17.2 long-header form has the high bit (0x80) set in
    byte 0; bytes 1..5 carry the 32-bit version (0x00000001 = QUIC v1,
    0x00000000 = Version Negotiation, 0xff000000..0xff0000ff = drafts).
    Initial packets are protected with keys derived from the destination
    Connection ID; decrypting them just to read SNI is expensive and not
    worth the dependency footprint for v1 — we aggregate per (src,dst) and
    rely on the IP-level newness signal for "unknown destination" alerts.

    HTTP/2: two signals, both lightweight —
      * h2c preface (cleartext): a TCP payload that starts with
        "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n" (RFC 7540 §3.5).
      * ALPN: TlsInfoAggregator extracts the application_layer_protocol_
        negotiation extension; a ClientHello/ServerHello containing 'h2'
        means the TLS-protected flow speaks HTTP/2. We finalize after
        TlsInfoAggregator so analyzer._tls_info is already populated.

    Outputs:
        results['quic_flows']  : list[{src,dst,packets,bytes,versions,is_local_dst}]
        results['http2_flows'] : list[{src,dst,sport,dport,detection,alpn,sni}]
        observed_artifacts['quic_dest'] gains every external QUIC server IP
        so the existing first-seen correlation tracks new HTTP/3 destinations.
    """
    name = 'quic_http2'

    # Long-header QUIC packet types we name for the alert details. Lower bits
    # of byte 0 are protected, so we only key by version + the high-2 flag.
    _KNOWN_QUIC_VERSIONS = {
        0x00000000: 'version_negotiation',
        0x00000001: 'quic_v1',
        0x6b3343cf: 'quic_v2',  # RFC 9369
    }

    H2C_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        # (src_ip, dst_ip) → aggregate
        self.quic = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'versions': set(),
            'first_ts': None,
            'last_ts': None,
        })
        # h2c preface sightings — keyed by full 4-tuple so we don't double-
        # count a flow that retransmits the preface.
        self.h2c_seen = set()
        self.h2c_flows = []

    @staticmethod
    def _version_name(versions: set) -> list:
        names = []
        for v in versions:
            name = QuicHttp2Aggregator._KNOWN_QUIC_VERSIONS.get(v)
            if name:
                names.append(name)
            elif 0xff000000 <= v <= 0xff0000ff:
                names.append(f'draft-{v & 0xff:02x}')
            else:
                names.append(f'0x{v:08x}')
        return sorted(set(names))

    def update(self, pkt):
        if UDP in pkt and Raw in pkt:
            u = pkt[UDP]
            if u.dport in (443, 80) or u.sport in (443, 80):
                try:
                    payload = bytes(pkt[Raw].load)
                except Exception:
                    payload = b''
                if len(payload) >= 5 and (payload[0] & 0x80):
                    version = (
                        (payload[1] << 24)
                        | (payload[2] << 16)
                        | (payload[3] << 8)
                        | payload[4]
                    )
                    src_ip = dst_ip = None
                    if IP in pkt:
                        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
                    elif IPv6 in pkt:
                        src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
                    if src_ip and dst_ip:
                        # Normalize key so client→server and server→client
                        # accrue into the same flow record. The "destination"
                        # we want for the alert is whichever side is the
                        # external server; we resolve that in finalize.
                        key = self._flow_key(src_ip, dst_ip, u.sport, u.dport)
                        rec = self.quic[key]
                        rec['packets'] += 1
                        rec['bytes'] += len(pkt)
                        rec['versions'].add(version)
                        ts = float(pkt.time)
                        if rec['first_ts'] is None or ts < rec['first_ts']:
                            rec['first_ts'] = ts
                        if rec['last_ts'] is None or ts > rec['last_ts']:
                            rec['last_ts'] = ts
            return

        if TCP in pkt and Raw in pkt:
            try:
                head = bytes(pkt[Raw].load)[:24]
            except Exception:
                return
            if head.startswith(self.H2C_PREFACE) and IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                key = (src, sport, dst, dport)
                if key in self.h2c_seen:
                    return
                self.h2c_seen.add(key)
                self.h2c_flows.append({
                    'src': src, 'dst': dst,
                    'sport': sport, 'dport': dport,
                    'detection': 'h2c_preface',
                    'alpn': None,
                    'sni': None,
                })

    def _flow_key(self, src, dst, sport, dport):
        """Order endpoints so both directions of the same flow share a key.
        We put the higher port first so client side comes first when the
        server is on 443. For server↔server (both 443) the lexicographic IP
        order keeps the key stable."""
        if dport in (443, 80) and sport not in (443, 80):
            return (src, dst)
        if sport in (443, 80) and dport not in (443, 80):
            return (dst, src)
        return (min(src, dst), max(src, dst))

    def finalize(self, results):
        is_local = self.analyzer._is_local_ip
        quic_flows = []
        external_dests = set()
        for (a, b), rec in self.quic.items():
            # `a` is the side facing the server, `b` is the server (per the
            # ordering in _flow_key). Surface duration only when meaningful.
            duration = 0.0
            if rec['first_ts'] is not None and rec['last_ts'] is not None:
                duration = max(0.0, float(rec['last_ts']) - float(rec['first_ts']))
            quic_flows.append({
                'src': a,
                'dst': b,
                'packets': rec['packets'],
                'bytes': rec['bytes'],
                'duration': round(duration, 3),
                'versions': self._version_name(rec['versions']),
                'is_local_src': is_local(a),
                'is_local_dst': is_local(b),
            })
            if not is_local(b):
                external_dests.add(b)
        quic_flows.sort(key=lambda f: f['bytes'], reverse=True)
        results['quic_flows'] = quic_flows

        # ALPN-derived HTTP/2 from already-finalized TLS data.
        http2_flows = list(self.h2c_flows)
        tls_info = getattr(self.analyzer, '_tls_info', None) or {}
        h2_seen_keys = set()
        for ch in tls_info.get('client_hellos') or []:
            alpn = [p.lower() for p in (ch.get('alpn') or [])]
            if 'h2' not in alpn:
                continue
            key = (ch.get('src'), ch.get('sport'), ch.get('dst'), ch.get('dport'))
            if key in h2_seen_keys:
                continue
            h2_seen_keys.add(key)
            http2_flows.append({
                'src': ch.get('src'),
                'dst': ch.get('dst'),
                'sport': ch.get('sport'),
                'dport': ch.get('dport'),
                'detection': 'alpn_client',
                'alpn': alpn,
                'sni': ch.get('sni'),
            })
        for sh in tls_info.get('server_hellos') or []:
            alpn = [p.lower() for p in (sh.get('alpn') or [])]
            if 'h2' not in alpn:
                continue
            # ServerHello src is the server, dst is the client — invert so
            # the alert and the http2_flows shape match ClientHello rows.
            key = (sh.get('dst'), sh.get('dport'), sh.get('src'), sh.get('sport'))
            if key in h2_seen_keys:
                continue
            h2_seen_keys.add(key)
            http2_flows.append({
                'src': sh.get('dst'),
                'dst': sh.get('src'),
                'sport': sh.get('dport'),
                'dport': sh.get('sport'),
                'detection': 'alpn_server',
                'alpn': alpn,
                'sni': None,
            })
        results['http2_flows'] = http2_flows

        # Stash the external QUIC destinations so _collect_observed_artifacts
        # can promote them into observed_artifacts for cross-scan first-seen.
        self.analyzer._quic_external_dests = sorted(external_dests)


class AssetInventoryAggregator(StreamingAggregator):
    """Streaming de asset_inventory.extract_assets. Per-MAC fingerprint
    (TTL + DHCP options) sem precisar da lista self.packets."""
    name = 'asset_inventory'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.obs = defaultdict(lambda: {
            'ips': set(),
            'ttl_min': None,
            'ttl_initial_candidates': set(),
            'dhcp_vendor': None,
            'dhcp_hostname': None,
            'dhcp_param_list': None,
        })
        # DHCP class via PktView usa _ScapyDHCP (escopo de módulo).
        self._DHCP = _ScapyDHCP

    def update(self, pkt):
        if Ether not in pkt:
            return
        src_mac = (pkt[Ether].src or '').lower()
        if not src_mac:
            return
        if src_mac in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
            return
        try:
            if int(src_mac.split(':', 1)[0], 16) & 0x01:
                return
        except ValueError:
            return
        rec = self.obs[src_mac]
        if IP in pkt:
            ip = pkt[IP]
            rec['ips'].add(ip.src)
            try:
                ttl = int(ip.ttl)
            except Exception:
                ttl = 0
            if ttl > 0:
                if rec['ttl_min'] is None or ttl > rec['ttl_min']:
                    rec['ttl_min'] = ttl
                try:
                    from asset_inventory import _classify_ttl
                    initial, _ = _classify_ttl(ttl)
                    if initial:
                        rec['ttl_initial_candidates'].add(initial)
                except Exception:
                    pass
        if self._DHCP is not None and self._DHCP in pkt:
            try:
                for opt in pkt[self._DHCP].options or []:
                    if not isinstance(opt, tuple) or len(opt) < 2:
                        continue
                    name, val = opt[0], opt[1]
                    if name == 'vendor_class_id':
                        try:
                            rec['dhcp_vendor'] = (
                                val.decode('utf-8', errors='ignore')
                                if isinstance(val, (bytes, bytearray))
                                else str(val)
                            )
                        except Exception:
                            pass
                    elif name == 'hostname':
                        try:
                            rec['dhcp_hostname'] = (
                                val.decode('utf-8', errors='ignore')
                                if isinstance(val, (bytes, bytearray))
                                else str(val)
                            )
                        except Exception:
                            pass
                    elif name == 'param_req_list':
                        if isinstance(val, (bytes, bytearray)):
                            rec['dhcp_param_list'] = list(val)
                        elif isinstance(val, (list, tuple)):
                            rec['dhcp_param_list'] = [int(x) for x in val]
            except Exception:
                pass

    def finalize(self, results):
        try:
            from asset_inventory import _classify_ttl, _classify_vendor_class
        except Exception:
            results['assets'] = {}
            return
        assets = {}
        for mac, rec in self.obs.items():
            ttl_observed = rec['ttl_min']
            ttl_initial, ttl_label = (None, None)
            if rec['ttl_initial_candidates']:
                ttl_initial = max(rec['ttl_initial_candidates'])
                _, ttl_label = _classify_ttl(ttl_initial)
            os_guess = _classify_vendor_class(rec['dhcp_vendor']) or ttl_label
            param_hash = None
            if rec['dhcp_param_list']:
                digest = hashlib.md5(
                    bytes(rec['dhcp_param_list'])).hexdigest()
                param_hash = digest[:16]
            assets[mac] = {
                'mac': mac,
                'ip_addresses': sorted(rec['ips']),
                'os_guess': os_guess,
                'ttl_initial': ttl_initial,
                'ttl_observed': ttl_observed,
                'dhcp_vendor': rec['dhcp_vendor'],
                'dhcp_hostname': rec['dhcp_hostname'],
                'dhcp_param_list_hash': param_hash,
                'dhcp_param_list': rec['dhcp_param_list'],
            }
        results['assets'] = assets


class FlowAnomalyAggregator(StreamingAggregator):
    """Streaming de flow_anomaly.detect_anomalous_flows. Acumula features
    de fluxo durante o load; roda IsolationForest no finalize."""
    name = 'flow_anomaly'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        # Memória limitada: em vez de guardar a lista inteira de timestamps e
        # sizes por fluxo (O(N pacotes) — estoura a RAM em captures grandes),
        # acumulamos apenas momentos estatísticos suficientes para reconstruir
        # média/desvio: contagem, soma, soma de quadrados, min/max ts e o ts
        # anterior para os inter-arrival times (IAT).
        self.flows = defaultdict(lambda: {
            'count': 0,
            'byte_sum': 0.0, 'byte_sqsum': 0.0,
            'min_ts': None, 'max_ts': None, 'prev_ts': None,
            'iat_sum': 0.0, 'iat_sqsum': 0.0, 'iat_count': 0,
        })

    def update(self, pkt):
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        if TCP in pkt:
            dport = int(pkt[TCP].dport)
            proto = 'TCP'
        elif UDP in pkt:
            dport = int(pkt[UDP].dport)
            proto = 'UDP'
        elif ICMP in pkt:
            dport = 0
            proto = 'ICMP'
        else:
            return
        ts = float(pkt.time)
        size = int(len(pkt))
        flow = self.flows[(src, dst, dport, proto)]
        flow['count'] += 1
        flow['byte_sum'] += size
        flow['byte_sqsum'] += size * size
        if flow['min_ts'] is None or ts < flow['min_ts']:
            flow['min_ts'] = ts
        if flow['max_ts'] is None or ts > flow['max_ts']:
            flow['max_ts'] = ts
        if flow['prev_ts'] is not None:
            iat = ts - flow['prev_ts']
            flow['iat_sum'] += iat
            flow['iat_sqsum'] += iat * iat
            flow['iat_count'] += 1
        flow['prev_ts'] = ts

    def finalize(self, results):
        thresholds = (self.settings.get('thresholds') or {})
        min_flows = int(thresholds.get('flow_anomaly_min_flows', 50))
        max_alerts = int(thresholds.get('flow_anomaly_max_alerts', 10))
        contamination = float(
            thresholds.get('flow_anomaly_contamination', 0.05))
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            # sklearn ausente: nenhum alerta gerado (mesmo comportamento legado).
            self.analyzer._flow_anomaly_alerts = []
            return

        def _std_from_moments(total, sqsum, n):
            """Desvio-padrão amostral a partir dos momentos acumulados."""
            if n < 2:
                return 0.0
            var = (sqsum - (total * total) / n) / (n - 1)
            return math.sqrt(var) if var > 0 else 0.0

        keys = []
        features = []
        for key, flow in self.flows.items():
            pkt_count = flow['count']
            if pkt_count < 2:
                continue
            duration = flow['max_ts'] - flow['min_ts']
            byte_count = int(flow['byte_sum'])
            mean_size = flow['byte_sum'] / pkt_count
            std_size = _std_from_moments(
                flow['byte_sum'], flow['byte_sqsum'], pkt_count)
            iat_count = flow['iat_count']
            mean_iat = flow['iat_sum'] / iat_count if iat_count else 0.0
            std_iat = _std_from_moments(
                flow['iat_sum'], flow['iat_sqsum'], iat_count)
            keys.append(key)
            features.append([duration, pkt_count, byte_count,
                             mean_size, std_size, mean_iat, std_iat])

        if len(features) < min_flows:
            self.analyzer._flow_anomaly_alerts = []
            return

        model = IsolationForest(
            n_estimators=100, contamination=contamination, random_state=42,
        )
        model.fit(features)
        scores = model.decision_function(features)
        predictions = model.predict(features)
        anomalies = [
            (i, scores[i]) for i in range(len(keys)) if predictions[i] == -1
        ]
        anomalies.sort(key=lambda x: x[1])

        now = datetime.now().isoformat()
        alerts = []
        for idx, score in anomalies[:max_alerts]:
            src, dst, dport, proto = keys[idx]
            feat = features[idx]
            (duration, pkt_count, byte_count, mean_size, std_size,
             mean_iat, std_iat) = feat
            if score <= -0.15:
                severity = 'high'
            elif score <= -0.05:
                severity = 'medium'
            else:
                severity = 'low'
            alerts.append({
                'severity': severity,
                'category': 'anomaly',
                'title': 'Anomalous Flow (Isolation Forest)',
                'description': (
                    f'Flow {src} -> {dst}:{dport}/{proto} is statistically '
                    f'distinct from the rest of the capture (score '
                    f'{score:.3f}, {pkt_count} pkts, {byte_count} bytes, '
                    f'duration {duration:.1f}s)'
                ),
                'ip': src,
                'details': {
                    'src': src, 'dst': dst, 'dst_port': dport,
                    'protocol': proto,
                    'anomaly_score': round(float(score), 4),
                    'duration_seconds': round(duration, 3),
                    'packet_count': pkt_count,
                    'byte_count': byte_count,
                    'mean_packet_size': round(mean_size, 2),
                    'std_packet_size': round(std_size, 2),
                    'mean_inter_arrival_seconds': round(mean_iat, 4),
                    'std_inter_arrival_seconds': round(std_iat, 4),
                },
                'recommendation': (
                    'This flow is an outlier in the unsupervised statistical '
                    'model. Use this as a triage hint, not a verdict — '
                    'investigate the src/dst pair and confirm whether the '
                    'deviation has a benign explanation (large transfer, '
                    'long-lived session) or signals covert activity '
                    '(low-and-slow exfil, beacon over uncommon port).'
                ),
                'timestamp': now,
            })
        # Guarda para _run_detections agregar com os alertas dos detectores.
        self.analyzer._flow_anomaly_alerts = alerts


class UserRulesAggregator(StreamingAggregator):
    """Streaming de user_rules.evaluate_user_rules. Carrega regras uma vez;
    durante update, extrai 5-tuple do pacote e atualiza grupos por regra."""
    name = 'user_rules'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        # Lazy-load regras
        self.rules = []
        try:
            from user_rules import load_rules, DEFAULT_RULES_DIR
            self.rules = load_rules(DEFAULT_RULES_DIR) or []
        except Exception as e:
            print(f"[pcap_analyzer] user_rules load failed: {e}")
            self.rules = []
        # Para cada regra: groups dict (key -> stats)
        self.rule_groups = {
            rule['id']: defaultdict(lambda: {
                'count': 0, 'first_ts': None, 'last_ts': None,
                'src': None, 'dst': None, 'dport': None,
            })
            for rule in self.rules
        }
        # Import auxiliares para matching/grouping
        try:
            from user_rules import _packet_matches, _group_key
            self._matches = _packet_matches
            self._group_key = _group_key
        except Exception:
            self._matches = None
            self._group_key = None

    def _packet_5tuple(self, pkt):
        """Versão streaming de user_rules._packet_5tuple."""
        if IP not in pkt:
            return None
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = dport = None
        if TCP in pkt:
            proto = 'tcp'
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        elif UDP in pkt:
            proto = 'udp'
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            if DNS in pkt:
                proto = 'dns'
        elif ICMP in pkt:
            proto = 'icmp'
        else:
            proto = 'other'
        payload = b''
        if Raw in pkt:
            try:
                payload = bytes(pkt[Raw].load)
            except Exception:
                payload = b''
        try:
            ts = float(pkt.time)
        except Exception:
            ts = 0.0
        return (proto, src, dst, sport, dport, payload, ts)

    def update(self, pkt):
        if not self.rules or self._matches is None:
            return
        ft = self._packet_5tuple(pkt)
        if ft is None:
            return
        for rule in self.rules:
            try:
                if not self._matches(rule, ft):
                    continue
                key = self._group_key(rule, ft)
                g = self.rule_groups[rule['id']][key]
                g['count'] += 1
                if g['first_ts'] is None:
                    g['first_ts'] = ft[6]
                g['last_ts'] = ft[6]
                if g['src'] is None:
                    g['src'] = ft[1]
                    g['dst'] = ft[2]
                    g['dport'] = ft[4]
            except Exception:
                pass

    def finalize(self, results):
        if not self.rules:
            self.analyzer._user_rules_alerts = []
            return
        now_iso = datetime.now().isoformat()
        alerts = []
        for rule in self.rules:
            agg = rule.get('aggregate', {})
            min_count = int(agg.get('min_count', 1))
            window = agg.get('window_seconds')
            groups = self.rule_groups.get(rule['id'], {})
            for group_id, g in groups.items():
                if g['count'] < min_count:
                    continue
                if window is not None and g['first_ts'] and g['last_ts']:
                    span = g['last_ts'] - g['first_ts']
                    if span > window:
                        continue
                tmpl_ctx = {
                    'src': g['src'], 'dst': g['dst'], 'dst_port': g['dport'],
                    'count': g['count'], 'rule_id': rule['id'],
                    'rule_name': rule.get('name', rule['id']),
                }
                alert_template = rule.get('alert') or {}
                try:
                    title = (alert_template.get('title') or rule.get('name')
                             or rule['id']).format(**tmpl_ctx)
                except (KeyError, IndexError):
                    title = (alert_template.get('title') or rule.get('name')
                             or rule['id'])
                try:
                    desc = (alert_template.get('description')
                            or f"Rule {rule['id']} matched {g['count']} "
                               'time(s)').format(**tmpl_ctx)
                except (KeyError, IndexError):
                    desc = f"Rule {rule['id']} matched {g['count']} time(s)"
                alerts.append({
                    'severity': rule.get('severity', 'medium'),
                    'category': rule.get('category', 'user-rule'),
                    'title': title,
                    'description': desc,
                    'ip': g['src'],
                    'details': {
                        'rule_id': rule['id'],
                        'src': g['src'], 'dst': g['dst'], 'dport': g['dport'],
                        'count': g['count'],
                    },
                    'recommendation': rule.get('recommendation', ''),
                    'timestamp': now_iso,
                })
        self.analyzer._user_rules_alerts = alerts


STREAMING_AGGREGATORS = [
    SummaryAggregator,
    MacIpAggregator,
    IpStatsAggregator,
    ProtocolStatsAggregator,
    TimelineAggregator,
    TcpFlowAggregator,
    FileCarvingFlowAggregator,  # opt-in, gated by settings.carving.enabled
    TlsInfoAggregator,
    SshInfoAggregator,
    HttpInfoAggregator,  # finalize AFTER TcpFlowAggregator (lê tcp_flows)
    QuicHttp2Aggregator,  # finalize AFTER TlsInfoAggregator (lê _tls_info)
    AssetInventoryAggregator,
    FlowAnomalyAggregator,
    UserRulesAggregator,
]
STREAMING_AGGREGATOR_NAMES = frozenset(c.name for c in STREAMING_AGGREGATORS)
# Nomes que correspondem a pre-computes legados em detection_steps —
# devem ser pulados em _run_detections.
STREAMING_PRECOMPUTE_NAMES = frozenset({'tcp_flows', 'tls_info', 'http_info'})
