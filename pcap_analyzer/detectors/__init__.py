"""
Streaming detectors.

Each detector observes packets incrementally (update) during the single-pass
load and emits alerts in finalize(). The detector instance receives the
PCAPAnalyzer in its constructor so it can read settings, call analyzer helpers
(_is_local_ip, _calculate_entropy, _dga_score, _binned_autocorrelation_peak,
_extract_dns_label, _parse_client_hello, _parse_server_hello) and reach the
detection constants exposed as class attributes on the analyzer.

This module was extracted from pcap_analyzer/_core.py. The historical
STREAMING_DETECTORS list and STREAMING_DETECTOR_NAMES set are exported below.
"""

import math
import hashlib
import ipaddress
import time
from collections import defaultdict, Counter
from datetime import datetime

from scapy.all import IP, IPv6, TCP, UDP, ARP, DNS, DNSQR, DNSRR, ICMP, Raw, Ether

from ..pkt_view import (
    LLMNR_LAYER, NBNS_LAYER, SMB2_CREATE_LAYER, DCERPC_BIND_LAYER, NDP_LAYER,
)


# === Streaming detector framework (Fase 3) ====================================
# Cada detector vira uma classe stateful com update(pkt)/finalize(). Permite
# passada única sobre o arquivo, eliminando self.packets como lista em memória.
# Migração das 32 detecções é incremental — detectores ainda não convertidos
# continuam rodando sobre self.packets no caminho legado.


class StreamingDetector:
    """Base para detectores incrementais. Override update() e finalize().

    update(pkt) é chamado para cada PktView durante a passada de streaming.
    finalize() é chamado ao fim e retorna lista de alertas.
    """
    name = 'base'

    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.settings = analyzer.settings
        self.thresholds = analyzer.settings.get('thresholds') or {}

    def update(self, pkt):  # noqa: ARG002
        pass

    def finalize(self):
        return []


# Severity ladder used by the sanctioned-destination downgrade below.
_SEV_LADDER = ['info', 'low', 'medium', 'high', 'critical']


def _apply_sanctioned_downgrade(analyzer, dst_ip, severity, details,
                                description, recommendation):
    """If `dst_ip` resolves (via TLS SNI / HTTP Host seen in the capture) to a
    sanctioned bulk-transfer destination (cloud backup, OS update, CDN,
    video/conferencing), lower the severity one notch and annotate the alert.

    Returns (severity, description, recommendation) — possibly modified.
    Never suppresses: attackers do abuse cloud services for exfil, so the
    analyst still sees it, just de-prioritized. Mutates `details` in place to
    record the match and the matched hostnames.
    """
    from ..constants import is_sanctioned_bulk_destination
    try:
        hostnames = analyzer._hostname_index().get(dst_ip) or set()
    except Exception:
        hostnames = set()
    if not hostnames:
        return severity, description, recommendation
    match = is_sanctioned_bulk_destination(hostnames)
    if not match:
        details['dest_hostnames'] = sorted(hostnames)[:5]
        return severity, description, recommendation
    try:
        idx = _SEV_LADDER.index(severity)
    except ValueError:
        idx = 2
    new_severity = _SEV_LADDER[max(0, idx - 1)]
    details['likely_sanctioned'] = True
    details['sanctioned_match'] = match
    details['dest_hostnames'] = sorted(hostnames)[:5]
    details['severity_original'] = severity
    details['severity_reason'] = (
        f'Rebaixado: o destino resolve para um serviço sancionado de '
        f'transferência em massa ({match}). Confirme se o upload é esperado '
        f'antes de descartar.'
    )
    description += (
        f' O destino corresponde a um serviço sancionado de transferência em '
        f'massa ({match}) — provavelmente tráfego legítimo de '
        'cloud/backup/atualização, mas confirme.'
    )
    recommendation = (
        f'O destino ({match}) é um serviço conhecido de '
        'cloud/backup/atualização/conferência que legitimamente move grandes '
        'volumes para fora. Confirme a aplicação dona e que o upload é '
        'esperado; note que esses serviços também são abusados para exfil, '
        'então não descarte sem verificar o que foi transferido. ' + recommendation
    )
    return new_severity, description, recommendation


def _apply_known_service_downgrade(analyzer, dst_ip, severity, details):
    """Lower `severity` one notch when `dst_ip` resolves (SNI / HTTP Host /
    DNS answer seen in the capture) to a large, well-known platform
    (OS vendors, push/telemetry, CDN, collaboration SaaS) — the usual
    source of periodic check-ins and opaque QUIC volume.

    Never suppresses: C2 does hide behind these platforms (domain fronting,
    cloud functions), so the alert stays visible, annotated in `details`.
    Returns the (possibly lowered) severity.
    """
    from ..constants import KNOWN_BENIGN_SERVICE_SUFFIXES, hostname_suffix_match
    try:
        hostnames = analyzer._hostname_index().get(dst_ip) or set()
    except Exception:
        hostnames = set()
    if not hostnames:
        return severity
    details.setdefault('dest_hostnames', sorted(hostnames)[:5])
    match = hostname_suffix_match(hostnames, KNOWN_BENIGN_SERVICE_SUFFIXES)
    if not match:
        return severity
    try:
        idx = _SEV_LADDER.index(severity)
    except ValueError:
        idx = 2
    new_severity = _SEV_LADDER[max(1, idx - 1)]
    if new_severity != severity:
        details['severity_original'] = severity
    details['known_service'] = match
    details['severity_reason'] = (
        f'Rebaixado: o destino resolve para um serviço conhecido ({match}), '
        'fonte comum de tráfego periódico legítimo (telemetria, push, '
        'atualização). Confirme a aplicação antes de descartar.'
    )
    return new_severity


def _cap_severity(severity, cap):
    """min(severity, cap) on the info..critical ladder."""
    try:
        return _SEV_LADDER[min(_SEV_LADDER.index(severity),
                               _SEV_LADDER.index(cap))]
    except ValueError:
        return severity


class TcpFlowTracker:
    """Per-flow TCP handshake state + byte counter + ICMP-unreachable marker.

    Detectors reuse this to answer two questions about every alert they emit:
      - did the TCP connection actually establish? (3-way handshake or data)
      - how many payload bytes crossed the wire?

    A flow is keyed by ``(server, client, port)`` where ``port`` is the
    server-side port. The caller decides direction by passing
    ``sender_is_client`` to :meth:`observe_tcp` — this matters because SYN,
    SYN-ACK, RST and Raw bytes must be bucketed correctly even when packets
    arrive out of order. ``observe_icmp_error`` inspects the IP+TCP header
    embedded inside an ICMP type 3/11 message and marks the *referenced*
    flow as ``icmp_unreachable`` (covers the case where the only on-wire
    evidence of a failed connection is the router's error reply).

    Status order (most informative wins):
      established > open_no_ack > icmp_unreachable > scan_rejected > scan_no_response
    """

    _F_FIN = 0x01
    _F_SYN = 0x02
    _F_RST = 0x04
    _F_ACK = 0x10

    def __init__(self):
        self.flows = {}  # (server, client, port) -> state

    def _new_rec(self):
        return {
            'syn_seen': False,
            'syn_ack_seen': False,
            'client_ack_seen': False,
            'data_seen': False,
            'rst_seen': False,
            'fin_seen': False,
            'icmp_unreachable': False,
            'packets': 0,
            'bytes_c2s': 0,
            'bytes_s2c': 0,
            'first_ts': None,
            'last_ts': None,
        }

    def _flow(self, server, client, port):
        key = (server, client, port)
        rec = self.flows.get(key)
        if rec is None:
            rec = self._new_rec()
            self.flows[key] = rec
        return rec

    @staticmethod
    def _stamp(rec, pkt):
        try:
            ts = float(pkt.time)
        except Exception:
            return
        if rec['first_ts'] is None or ts < rec['first_ts']:
            rec['first_ts'] = ts
        if rec['last_ts'] is None or ts > rec['last_ts']:
            rec['last_ts'] = ts

    def observe_tcp(self, server, client, port, pkt, sender_is_client):
        """Update flow state from a TCP packet. ``sender_is_client`` indicates
        which side sent this packet (True = client → server)."""
        if TCP not in pkt:
            return
        rec = self._flow(server, client, port)
        rec['packets'] += 1
        self._stamp(rec, pkt)

        flags = int(pkt[TCP].flags)
        is_syn = bool(flags & self._F_SYN)
        is_ack = bool(flags & self._F_ACK)
        is_rst = bool(flags & self._F_RST)
        is_fin = bool(flags & self._F_FIN)

        if is_rst:
            rec['rst_seen'] = True
        if is_fin:
            rec['fin_seen'] = True

        if sender_is_client:
            if is_syn and not is_ack:
                rec['syn_seen'] = True
            elif is_ack and not is_syn and rec['syn_ack_seen']:
                rec['client_ack_seen'] = True
        else:
            if is_syn and is_ack:
                rec['syn_ack_seen'] = True

        try:
            # Header-derived payload length first: Raw is missing whenever
            # scapy dissects the payload (SMB2/NetBIOS), which made SMB
            # sessions look data-less ("not established", 0 bytes).
            n = getattr(pkt[TCP], 'plen', None)
            if n is None:
                n = len(bytes(pkt[Raw].load)) if Raw in pkt else 0
            if n > 0:
                rec['data_seen'] = True
                if sender_is_client:
                    rec['bytes_c2s'] += n
                else:
                    rec['bytes_s2c'] += n
        except Exception:
            pass

    def observe_icmp_error(self, pkt, ports=None, create_missing=True):
        """If ``pkt`` is an ICMP error (type 3/11) embedding a TCP header,
        mark the referenced flow as icmp_unreachable. Returns the affected
        key, or None.

        ``ports`` (iterable of ints) restricts which embedded TCP ports the
        caller cares about — keeps this cheap when the detector only watches
        a specific port set.
        ``create_missing`` controls whether an ICMP error for a flow we've
        never seen TCP packets for still creates a record. Detectors that
        care about scan-only failures (e.g. InsecureProtocols) want True;
        detectors driven by other gating (e.g. BruteForce) usually want
        False so random ICMP errors don't manufacture ghost alerts.
        """
        if ICMP not in pkt:
            return None
        icmp = pkt[ICMP]
        try:
            if int(icmp.type) not in (3, 11):
                return None
            if getattr(icmp, 'inner_proto', None) != 'tcp':
                return None
            client = icmp.inner_ip_src
            server = icmp.inner_ip_dst
            sport = int(icmp.inner_sport)
            dport = int(icmp.inner_dport)
        except Exception:
            return None
        if not (client and server):
            return None

        if ports is not None:
            ports = set(ports)
            if dport in ports:
                port = dport
            elif sport in ports:
                # Embedded packet was server→client (unusual: server's reply
                # is the one that hit ICMP error). Flip the roles.
                client, server = server, client
                port = sport
            else:
                return None
        else:
            port = dport

        key = (server, client, port)
        rec = self.flows.get(key)
        if rec is None:
            if not create_missing:
                return None
            rec = self._new_rec()
            self.flows[key] = rec
        rec['icmp_unreachable'] = True
        self._stamp(rec, pkt)
        return key

    @staticmethod
    def status_for(rec):
        """Classify a flow record. Most informative status wins."""
        if rec['client_ack_seen'] or rec['data_seen']:
            return 'established'
        if rec['syn_ack_seen']:
            return 'open_no_ack'
        if rec['icmp_unreachable']:
            return 'icmp_unreachable'
        if rec['rst_seen']:
            return 'scan_rejected'
        return 'scan_no_response'

    def status(self, server, client, port):
        rec = self.flows.get((server, client, port))
        return None if rec is None else self.status_for(rec)

    def bytes_exchanged(self, server, client, port):
        rec = self.flows.get((server, client, port))
        if rec is None:
            return 0
        return rec['bytes_c2s'] + rec['bytes_s2c']

    def record(self, server, client, port):
        return self.flows.get((server, client, port))


# Phrases for connection_status field — shared so detector messages stay
# consistent (front-end uses the bare status string for the badge).
CONNECTION_STATUS_TEXT = {
    'established': (
        'Conexão TCP estabelecida (3-way handshake completo ou dados '
        'trafegados) — investigar com prioridade.'
    ),
    'open_no_ack': (
        'Servidor respondeu SYN-ACK (porta aberta), mas sem ACK/dados do '
        'cliente — handshake incompleto.'
    ),
    'icmp_unreachable': (
        'Roteador/host respondeu ICMP "destination unreachable" — pacote '
        'TCP nunca chegou ao serviço (conexão NÃO estabelecida).'
    ),
    'scan_rejected': (
        'Apenas tentativa de scan — servidor respondeu RST (porta fechada), '
        'sem conexão estabelecida.'
    ),
    'scan_no_response': (
        'Apenas tentativa de scan — sem resposta observada do servidor '
        '(porta filtrada ou host indisponível).'
    ),
}


class PortScanStreamingDetector(StreamingDetector):
    """Versão streaming de _detect_port_scans. Usa janela deslizante para
    capturar scans rápidos (nmap default) e mantém um caminho separado para
    scans lentos/slow-scan onde o número absoluto de portas distintas é
    significativamente acima do limiar.

    Onda 6 (B.4): também captura window-size e opções TCP do primeiro SYN
    por src para gerar fingerprint nmap (window=1024 + opts sem Timestamp/
    WScale = SYN scan default), e expõe ``analyzer._port_scan_sources``
    para que ``GreyNoiseRiotDetector`` possa marcar scans benignos
    (Shodan/Censys/etc) como informational pós-fato.
    """
    name = 'port_scans'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold_ports = self.thresholds.get('port_scan_min_ports', 20)
        self.threshold_time = self.thresholds.get('port_scan_time_window', 30)
        self.slow_multiplier = self.thresholds.get('port_scan_slow_multiplier', 5)
        # Probes are grouped per (source, TARGET): a vertical port scan is
        # many ports on ONE host. The pre-2026-09 code pooled every SYN of a
        # source regardless of destination, so a P2P/BitTorrent/VoIP client
        # or a NAT gateway opening connections to 20+ different peers, each
        # on its own random port, looked exactly like a port scan. Many
        # targets x one port each is the horizontal-scan detector's job.
        self.syn_by_src = defaultdict(
            lambda: {
                'per_dst': defaultdict(lambda: {'ports': [], 'timestamps': []}),
                'windows': Counter(), 'opt_sets': Counter(),
                'syn_count': 0,
            }
        )

    def update(self, pkt):
        if TCP not in pkt or IP not in pkt:
            return
        flags = int(pkt[TCP].flags)
        # Conta apenas SYN puro (início de conexão, enviado pelo scanner).
        # SYN-ACK (SYN+ACK = 0x12) é a *resposta* de um host que está sendo
        # escaneado; como `flags & 0x02` também é verdadeiro para SYN-ACK,
        # contá-lo inverteria a atribuição — o alvo apareceria como scanner.
        # Exigir ACK=0 (0x10) garante que só o lado atacante seja contado.
        if not (flags & 0x02) or (flags & 0x10):
            return
        rec = self.syn_by_src[pkt[IP].src]
        dst_rec = rec['per_dst'][pkt[IP].dst]
        dst_rec['ports'].append(int(pkt[TCP].dport))
        dst_rec['timestamps'].append(float(pkt.time))
        rec['syn_count'] += 1
        # Window + TCP option names (kept as a tuple so it's hashable).
        # PktView pre-extracts them for pure-SYN packets as `window` /
        # `opt_names`; the scapy attributes remain a fallback for raw packets.
        tcp = pkt[TCP]
        try:
            win = getattr(tcp, 'window', None)
            if win is not None:
                rec['windows'][int(win)] += 1
        except Exception:
            pass
        try:
            opt_names = getattr(tcp, 'opt_names', None)
            if opt_names is None:
                opt_names = tuple(
                    (o[0] if isinstance(o, tuple) else str(o))
                    for o in (getattr(tcp, 'options', None) or [])
                )
            rec['opt_sets'][tuple(opt_names)] += 1
        except Exception:
            pass

    # Severity ladder for the direction-aware modulation below.
    _SEV_LADDER = ('info', 'low', 'medium', 'high', 'critical')

    def _scan_severity(self, src_ip, primary_dst, nmap_like):
        """Modulate port-scan severity by direction instead of always-critical.

        The pré-2026-07 code hard-coded 'critical' for every port scan, so a
        benign internet scanner hitting us, an authorized internal admin
        running nmap, and a compromised host probing outward all looked
        identical. Direction is the strongest cheap context:

          external → internal : critical  (someone outside mapping our host)
          internal → internal : high      (internal recon / lateral)
          internal → external : medium    (local host scanning the internet —
                                            often a tool/misconfig, but could
                                            be a compromised host)
          external → external : medium    (transit / spoofed, rarely ours)

        An nmap fingerprint means deliberate tooling → bump one notch (capped
        at critical). GreyNoiseRiotDetector still adds its benign-scanner
        counter-signal on top.
        """
        src_local = self.analyzer._is_local_ip(src_ip)
        dst_local = (self.analyzer._is_local_ip(primary_dst)
                     if primary_dst else False)
        if (not src_local) and dst_local:
            severity = 'critical'
        elif src_local and dst_local:
            severity = 'high'
        else:
            severity = 'medium'
        if nmap_like and severity != 'critical':
            idx = self._SEV_LADDER.index(severity)
            severity = self._SEV_LADDER[min(len(self._SEV_LADDER) - 1, idx + 1)]
        return severity

    def _nmap_fingerprint(self, windows, opt_sets):
        """Onda 6 — return (is_nmap_like, label) for a SYN-source profile.

        nmap default `-sS`: window=1024, options exactly contain MSS+SAckOK
        and NEVER contain Timestamp or WScale (real OS stacks always do).
        nmap OS-detection: distinctive non-standard windows (1, 63, 4...).
        """
        from ..constants import (
            NMAP_DEFAULT_WINDOWS, NMAP_OS_DETECT_WINDOWS,
            NMAP_REQUIRED_OPTS, NMAP_DISQUALIFYING_OPTS,
        )
        if not windows or not opt_sets:
            return False, ''
        # Most common option-set across this src's SYNs.
        top_opts, _ = opt_sets.most_common(1)[0]
        top_opts_set = set(top_opts)
        top_win, _ = windows.most_common(1)[0]
        if top_win in NMAP_OS_DETECT_WINDOWS:
            return True, f'nmap OS-detection probe (window={top_win})'
        if (top_win in NMAP_DEFAULT_WINDOWS
                and NMAP_REQUIRED_OPTS.issubset(top_opts_set)
                and not (NMAP_DISQUALIFYING_OPTS & top_opts_set)):
            return True, 'nmap -sS default SYN scan (window=1024, no TS/WS)'
        return False, ''

    def _evaluate_target(self, ports_seq, ts_seq):
        """Scan verdict for the SYNs one source sent to ONE target.

        Returns None when below threshold, else (scan_type, ports_count,
        duration, ports_sample, total_unique, first_ts, last_ts). 'fast' =
        >= threshold distinct ports inside the sliding window; 'slow' =
        >= threshold*slow_multiplier distinct ports over the whole capture.
        """
        if not ts_seq:
            return None
        total_unique = len(set(ports_seq))
        if total_unique < self.threshold_ports:
            return None
        order = sorted(range(len(ts_seq)), key=lambda i: ts_seq[i])
        sorted_ts = [ts_seq[i] for i in order]
        sorted_ports = [ports_seq[i] for i in order]
        window = self.threshold_time
        best_ports = 0
        best_duration = 0.0
        best_sample = []
        counts = Counter()
        distinct = 0
        j = 0
        n = len(sorted_ts)
        for i in range(n):
            while j < n and sorted_ts[j] - sorted_ts[i] <= window:
                p = sorted_ports[j]
                if counts[p] == 0:
                    distinct += 1
                counts[p] += 1
                j += 1
            if distinct > best_ports:
                best_ports = distinct
                best_duration = sorted_ts[j - 1] - sorted_ts[i] if j > i else 0
                best_sample = sorted(set(sorted_ports[i:j]))[:20]
            p = sorted_ports[i]
            counts[p] -= 1
            if counts[p] == 0:
                distinct -= 1
                del counts[p]
        if best_ports >= self.threshold_ports:
            return ('fast', best_ports, best_duration, best_sample,
                    total_unique, sorted_ts[0], sorted_ts[-1])
        if total_unique >= self.threshold_ports * self.slow_multiplier:
            return ('slow', total_unique, sorted_ts[-1] - sorted_ts[0],
                    sorted(set(sorted_ports))[:20], total_unique,
                    sorted_ts[0], sorted_ts[-1])
        return None

    def finalize(self):
        from ..constants import (
            SCAN_DURATION_BAND_ULTRA_SLOW_SEC,
            SCAN_DURATION_BAND_SLOW_SEC,
        )
        alerts = []
        # Expose scan sources for downstream GreyNoise RIOT enrichment.
        scan_sources = {}
        for src_ip, data in self.syn_by_src.items():
            # Evaluate each target separately; keep the targets that were
            # actually port-scanned and report the strongest one.
            qualifying = []  # (rank, dst, scan_type, ports_count, duration, sample, total_unique, first, last)
            for dst_ip, drec in data['per_dst'].items():
                res = self._evaluate_target(drec['ports'], drec['timestamps'])
                if res is None:
                    continue
                scan_type_d, ports_d, dur_d, sample_d, uniq_d, first_d, last_d = res
                rank = (1 if scan_type_d == 'fast' else 0, ports_d)
                qualifying.append((rank, dst_ip, scan_type_d, ports_d, dur_d,
                                   sample_d, uniq_d, first_d, last_d))
            if not qualifying:
                continue
            qualifying.sort(key=lambda q: q[0], reverse=True)
            (_rank, primary_dst, scan_type, ports_count, duration,
             ports_sample, total_unique, first_ts, last_ts) = qualifying[0]
            window = self.threshold_time

            # Onda 6 — duration band labelling for slow scans.
            if scan_type == 'slow':
                if duration >= SCAN_DURATION_BAND_ULTRA_SLOW_SEC:
                    duration_band = 'ultra-slow (>1h)'
                elif duration >= SCAN_DURATION_BAND_SLOW_SEC:
                    duration_band = f'slow (~{duration / 60:.1f} min)'
                else:
                    duration_band = f'extended (~{duration:.0f}s)'
            else:
                duration_band = f'fast (<{window}s)'

            # Onda 6 — nmap fingerprint heuristic.
            nmap_like, nmap_label = self._nmap_fingerprint(
                data['windows'], data['opt_sets'],
            )
            top_win = (data['windows'].most_common(1)[0][0]
                       if data['windows'] else None)
            top_opts = (list(data['opt_sets'].most_common(1)[0][0])
                        if data['opt_sets'] else [])

            title = 'Port Scan Detected'
            if scan_type == 'slow':
                title += f' ({duration_band})'
            if nmap_like:
                title += ' — nmap fingerprint'

            scan_sources[src_ip] = {
                'scan_type': scan_type,
                'duration': duration,
                'duration_band': duration_band,
                'nmap_like': nmap_like,
                'nmap_label': nmap_label,
            }

            # Alvo(s) do scan — só hosts que de fato tiveram portas varridas.
            targets = [q[1] for q in qualifying]
            if not primary_dst:
                target_str = 'an unknown host'
            elif len(targets) == 1:
                target_str = f'host {primary_dst}'
            else:
                target_str = f'{len(targets)} hosts (e.g. {primary_dst})'

            description = (
                f'O IP {src_ip} varreu {ports_count} portas em {target_str} em '
                f'{duration:.2f} segundos ({duration_band})'
            )
            if nmap_like:
                description += f'. Perfil TCP: {nmap_label}.'
            severity = self._scan_severity(src_ip, primary_dst, nmap_like)
            alerts.append({
                'severity': severity,
                'category': 'scan',
                'title': title,
                'description': description,
                'ip': src_ip,
                'dst_ip': primary_dst,
                'details': {
                    'src_ip': src_ip,
                    'dst_ip': primary_dst,
                    'direction': (
                        'inbound'
                        if (not self.analyzer._is_local_ip(src_ip)
                            and primary_dst
                            and self.analyzer._is_local_ip(primary_dst))
                        else ('internal'
                              if self.analyzer._is_local_ip(src_ip)
                              and primary_dst
                              and self.analyzer._is_local_ip(primary_dst)
                              else 'outbound')
                    ),
                    'targets': targets[:10],
                    'targets_count': len(targets),
                    'ports_count': ports_count,
                    'duration': round(duration, 2),
                    'duration_band': duration_band,
                    'ports': ports_sample,
                    'scan_type': scan_type,
                    'total_unique_ports': total_unique,
                    'first_ts': first_ts,
                    'last_ts': last_ts,
                    'nmap_fingerprint': nmap_like,
                    'nmap_label': nmap_label,
                    'syn_window': top_win,
                    'syn_options': top_opts,
                },
                'recommendation': (
                    'Investigue a atividade do host em busca de possível '
                    'comprometimento. Bloqueie se for uma varredura não autorizada.'
                ),
            })
        # Hand-off to RIOT enrichment post-detector (analyzer attr).
        try:
            self.analyzer._port_scan_sources = scan_sources
        except Exception:
            pass
        return alerts


class SuspiciousPortsStreamingDetector(StreamingDetector):
    """Streaming de _detect_suspicious_ports.

    O "server side" do fluxo é o host cuja porta bate na lista de portas
    suspeitas — i.e., quem está (ou finge estar) escutando naquela porta.
    O outro lado é o cliente/iniciador (o scanner, quando o fluxo nunca passa
    do SYN). Direção é derivada das flags TCP, não da ordem em que o pacote
    aparece, para que SYN→servidor e SYN-ACK←servidor caiam no mesmo fluxo.

    Estado do handshake, bytes trocados e ICMP unreachable embutindo TCP/porta
    suspeita ficam todos no :class:`TcpFlowTracker` compartilhado — usado por
    outros detectores para o mesmo padrão de campo "connection_status +
    bytes_exchanged".
    """
    name = 'suspicious_ports'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        from ..constants import ALPN_WEB_OK_PORTS
        self.suspicious = analyzer.SUSPICIOUS_PORTS
        self.tracker = TcpFlowTracker()
        self._web_ports = ALPN_WEB_OK_PORTS
        # Who really LISTENS on the suspicious port? Ports like 4444, 1337,
        # 1080, 5555, 6666 or 65000 are also perfectly ordinary EPHEMERAL
        # source ports (Windows 49152-65535, NAT/PAT 1024-65535, legacy
        # 1025-5000). Matching the port on either side turned every client
        # that happened to draw sport=65000 for an HTTPS request into a
        # "critical backdoor on port 65000" with an established connection.
        # Keys are the tracker's (holder, peer, port).
        self._listening = set()   # SYN sent TO the port / SYN-ACK FROM it
        self._ephemeral = set()   # SYN sent FROM the port / SYN-ACK TO it
        self._peer_is_service = set()  # peer side is a well-known service

    def _is_known_service_port(self, port):
        return port < 1024 or port in self._web_ports

    def update(self, pkt):
        if IP not in pkt:
            return
        if TCP in pkt:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            # Identificar lado-servidor pela porta. Se as duas portas estiverem
            # na lista (raro), prefere dport — assim o iniciador do SYN vira
            # cliente.
            if dport in self.suspicious:
                port = dport
                server = pkt[IP].dst
                client = pkt[IP].src
                sender_is_client = True
                peer_port = sport
            elif sport in self.suspicious:
                port = sport
                server = pkt[IP].src
                client = pkt[IP].dst
                sender_is_client = False
                peer_port = dport
            else:
                return
            key = (server, client, port)
            flags = int(pkt[TCP].flags)
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
            if is_syn and not is_ack:
                # The SYN's destination is the listener.
                (self._listening if sender_is_client
                 else self._ephemeral).add(key)
            elif is_syn and is_ack:
                # The SYN-ACK's source is the listener.
                (self._ephemeral if sender_is_client
                 else self._listening).add(key)
            if self._is_known_service_port(peer_port):
                self._peer_is_service.add(key)
            self.tracker.observe_tcp(
                server, client, port, pkt, sender_is_client,
            )
            return
        if ICMP in pkt:
            # ICMP unreachable referenciando TCP suspeito = tentativa que nem
            # chegou ao serviço. Marca o fluxo se já existe (create_missing=
            # False evita inventar alertas em ICMPs aleatórios).
            self.tracker.observe_icmp_error(
                pkt, ports=self.suspicious.keys(), create_missing=False,
            )

    def finalize(self):
        # Agregar por (porta, servidor) para 1 alerta por host:porta.
        per_host = defaultdict(lambda: {
            'clients': set(),
            'established': set(),
            'open': set(),
            'icmp': set(),
            'rejected': set(),
            'no_response': set(),
            'first_ts': None,
            'last_ts': None,
            'packets': 0,
            'bytes_total': 0,
        })
        status_bucket = {
            'established': 'established',
            'open_no_ack': 'open',
            'icmp_unreachable': 'icmp',
            'scan_rejected': 'rejected',
            'scan_no_response': 'no_response',
        }
        for (server, client, port), rec in self.tracker.flows.items():
            if port not in self.suspicious:
                continue
            key = (server, client, port)
            if key not in self._listening:
                # Handshake proves the suspicious port was the initiator's
                # ephemeral port -> not a service on that port.
                if key in self._ephemeral:
                    continue
                # Mid-stream capture (no SYN/SYN-ACK seen): if the other side
                # is a well-known service (443, 22, 53...), the suspicious
                # number is just the client's ephemeral port.
                if key in self._peer_is_service:
                    continue
            status = TcpFlowTracker.status_for(rec)
            bucket = per_host[(port, server)]
            bucket['clients'].add(client)
            bucket[status_bucket[status]].add(client)
            bucket['packets'] += rec['packets']
            bucket['bytes_total'] += rec['bytes_c2s'] + rec['bytes_s2c']
            if rec['first_ts'] is not None and (
                bucket['first_ts'] is None
                or rec['first_ts'] < bucket['first_ts']
            ):
                bucket['first_ts'] = rec['first_ts']
            if rec['last_ts'] is not None and (
                bucket['last_ts'] is None
                or rec['last_ts'] > bucket['last_ts']
            ):
                bucket['last_ts'] = rec['last_ts']

        alerts = []
        for (port, server), bucket in per_host.items():
            name, severity = self.suspicious[port]
            base_severity = severity
            clients_sorted = sorted(bucket['clients'])
            established_sorted = sorted(bucket['established'])

            if established_sorted:
                conn_status = 'established'
                primary_client = established_sorted[0]
            elif bucket['open']:
                conn_status = 'open_no_ack'
                primary_client = sorted(bucket['open'])[0]
            elif bucket['icmp']:
                conn_status = 'icmp_unreachable'
                primary_client = sorted(bucket['icmp'])[0]
            elif bucket['rejected']:
                conn_status = 'scan_rejected'
                primary_client = sorted(bucket['rejected'])[0]
            else:
                conn_status = 'scan_no_response'
                primary_client = clients_sorted[0] if clients_sorted else None

            # Severity follows the evidence: nothing answered on the port
            # (RST / silence / ICMP unreachable) means no service is there —
            # a probe, which the scan detectors already cover. A SYN-ACK or
            # an established session means something IS listening.
            if conn_status in ('scan_rejected', 'scan_no_response',
                               'icmp_unreachable'):
                severity = 'low'
            conn_text = CONNECTION_STATUS_TEXT.get(conn_status, '')
            description = (
                f'Porta {port} ({name}) no host {server} '
                f'acessada por {len(clients_sorted)} cliente(s). ' + conn_text
            )

            alerts.append({
                'severity': severity,
                'category': 'port',
                'title': f'Suspicious Port {port}',
                'description': description,
                'ip': server,
                'details': {
                    'port': port,
                    'port_name': name,
                    'src_ip': primary_client,
                    'dst_ip': server,
                    # peer_ips lista os clientes (origens). peer_role indica
                    # para o SOC matching que peers são sources, não dsts.
                    'peer_ips': clients_sorted[:10],
                    'peer_count': len(clients_sorted),
                    'peer_role': 'client',
                    'connection_established': bool(established_sorted),
                    'connection_status': conn_status,
                    'severity_original': (base_severity
                                          if severity != base_severity
                                          else None),
                    'bytes_exchanged': bucket['bytes_total'],
                    'established_clients': established_sorted[:10],
                    'open_clients': sorted(bucket['open'])[:10],
                    'icmp_clients': sorted(bucket['icmp'])[:10],
                    'rejected_clients': sorted(bucket['rejected'])[:10],
                    'no_response_clients': sorted(bucket['no_response'])[:10],
                    'flow_count': len(bucket['clients']),
                    'packet_count': bucket['packets'],
                    'first_ts': bucket['first_ts'],
                    'last_ts': bucket['last_ts'],
                },
                'recommendation': (
                    f'Investigue o tráfego na porta {port}. Essa porta é '
                    'comumente associada a atividade maliciosa.'
                    + (' A conexão foi estabelecida — provavelmente tráfego real de C2/backdoor.'
                       if established_sorted else
                       ' Nenhuma conexão bem-sucedida observada — provavelmente varredura de reconhecimento.')
                ),
            })
        return alerts


class ArpSpoofingStreamingDetector(StreamingDetector):
    """ARP-based MITM detection.

    An IP whose MAC changes is only *sometimes* an attack: DHCP handing a
    freed address to another device, a NIC/laptop swap or a VM migration all
    produce exactly one clean change. Poisoning has a different shape, so the
    verdict is taken in finalize() over the whole capture:

      * **flip-flop** — the IP bounces back to a MAC it already had (the
        legitimate owner keeps answering while the attacker re-poisons);
      * **aggressive re-announcement** — the new MAC re-claims the IP
        >= ``arp_gratuitous_max`` times inside ``arp_claim_window`` seconds
        (arpspoof/ettercap/bettercap refresh every 1-2 s);
      * **dual identity** — the new MAC keeps claiming ANOTHER IP after it
        took this one (a DHCP reassignment moves a device, it does not make
        it answer for two addresses at once).

    Any of those -> critical ``ARP Spoofing Detected``. A single change with
    none of them -> medium ``ARP IP-to-MAC Change`` (high when the IP looks
    like a gateway), so the analyst still sees it without a critical page.
    The gratuitous-ARP flood counter is windowed for the same reason: every
    host sends a few GARPs per link-up/DHCP renew, and over a day-long
    capture a lifetime counter crossed 5 for ordinary machines.
    """
    name = 'arp_spoofing'

    MAX_TRANSITIONS_PER_IP = 50
    MAX_CLAIMS_TRACKED = 500

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold = self.thresholds.get('arp_gratuitous_max', 5)
        self.claim_window = float(self.thresholds.get('arp_claim_window', 60))
        self.device_types = (self.settings.get('device_types') or {})
        self.ip_to_mac = {}
        # ip -> [(ts, old_mac, new_mac)]
        self.transitions = defaultdict(list)
        # ip -> sequence of owning MACs (consecutive duplicates collapsed)
        self.ip_mac_history = defaultdict(list)
        # (mac, ip) -> last claim ts / bounded claim timestamps
        self.claim_last = {}
        self.claim_ts = defaultdict(list)
        # gratuitous flood: mac -> timestamps inside the sliding window
        self.garp_ts = defaultdict(list)
        self.garp_total = defaultdict(int)
        self.flood_alerted = set()
        self.alerts = []

    def _is_gateway(self, ip):
        if self.device_types.get(ip) == 'Roteador':
            return True
        return str(ip).rsplit('.', 1)[-1] in ('1', '254')

    def update(self, pkt):
        if ARP not in pkt:
            return
        a = pkt[ARP]
        # Requests (op=1) also assert "psrc is at hwsrc" — poisoning via
        # gratuitous *requests* is just as common as via replies, so both
        # feed the MAC-change tracker and the gratuitous-flood counter.
        if a.op not in (1, 2):
            return
        src_ip = a.psrc
        src_mac = a.hwsrc
        # ACD/DHCP probes announce psrc 0.0.0.0 — not an ownership claim;
        # letting them into the tracker would poison the IP->MAC state.
        if not src_ip or src_ip == '0.0.0.0' or not src_mac:
            return
        src_mac = str(src_mac).lower()
        try:
            ts = float(pkt.time)
        except Exception:
            ts = 0.0
        old = self.ip_to_mac.get(src_ip)
        if old is not None and old != src_mac:
            tr = self.transitions[src_ip]
            if len(tr) < self.MAX_TRANSITIONS_PER_IP:
                tr.append((ts, old, src_mac))
        self.ip_to_mac[src_ip] = src_mac
        hist = self.ip_mac_history[src_ip]
        if not hist or hist[-1] != src_mac:
            if len(hist) < self.MAX_TRANSITIONS_PER_IP:
                hist.append(src_mac)
        self.claim_last[(src_mac, src_ip)] = ts
        cts = self.claim_ts[(src_mac, src_ip)]
        if len(cts) < self.MAX_CLAIMS_TRACKED:
            cts.append(ts)

        if a.pdst == a.psrc:
            dq = self.garp_ts[src_mac]
            dq.append(ts)
            while dq and ts - dq[0] > self.claim_window:
                dq.pop(0)
            self.garp_total[src_mac] += 1
            if len(dq) >= self.threshold and src_mac not in self.flood_alerted:
                self.flood_alerted.add(src_mac)
                self.alerts.append({
                    'severity': 'high',
                    'category': 'arp',
                    'title': 'Gratuitous ARP Flood',
                    'description': (
                        f'O MAC {src_mac} enviou {len(dq)} pacotes ARP '
                        f'gratuitos em {self.claim_window:.0f}s'
                    ),
                    'ip': src_ip,
                    'details': {
                        'mac': src_mac,
                        'count': len(dq),
                        'window_seconds': self.claim_window,
                        'first_ts': dq[0],
                    },
                    'recommendation': (
                        'Possível tentativa de envenenamento ARP. Monitore '
                        'este endereço MAC em busca de atividade suspeita.'
                    ),
                })

    def _max_claims_in_window(self, stamps, since):
        pts = sorted(t for t in stamps if t >= since)
        best = 0
        j = 0
        for i in range(len(pts)):
            while j < len(pts) and pts[j] - pts[i] <= self.claim_window:
                j += 1
            best = max(best, j - i)
        return best

    def finalize(self):
        alerts = list(self.alerts)
        for a in alerts:
            if a['title'] == 'Gratuitous ARP Flood':
                a['details']['total_count'] = self.garp_total.get(
                    a['details']['mac'], a['details']['count'])
        mac_ips = defaultdict(set)
        for (mac, ip) in self.claim_last:
            mac_ips[mac].add(ip)
        for ip, trs in self.transitions.items():
            first_ts, old_mac, new_mac = trs[0]
            history = self.ip_mac_history[ip]
            flip_flop = len(set(history)) < len(history)
            reasons = []
            if flip_flop:
                reasons.append(
                    'o IP alternou de volta para um MAC anterior (flip-flop)')
            max_burst = 0
            dual_ips = set()
            for ts, _old, nm in trs:
                burst = self._max_claims_in_window(
                    self.claim_ts.get((nm, ip), []), ts)
                max_burst = max(max_burst, burst)
                for other in mac_ips.get(nm, ()):
                    if other != ip and self.claim_last.get((nm, other), 0) >= ts:
                        dual_ips.add(other)
            if max_burst >= self.threshold:
                reasons.append(
                    f'o novo MAC reanunciou o IP {max_burst}x em '
                    f'{self.claim_window:.0f}s')
            dual_ips = sorted(dual_ips)
            if dual_ips:
                reasons.append(
                    'o novo MAC continuou respondendo também por '
                    + ', '.join(dual_ips[:3]))
            details = {
                'src_ip': ip,
                'old_mac': old_mac,
                'new_mac': new_mac,
                'mac_history': history[:10],
                'transitions': len(trs),
                'flip_flop': flip_flop,
                'max_claims_in_window': max_burst,
                'new_mac_other_ips': dual_ips[:10],
                'first_ts': first_ts,
                'last_ts': trs[-1][0],
            }
            if reasons:
                details['evidence'] = reasons
                alerts.append({
                    'severity': 'critical',
                    'category': 'arp',
                    'title': 'ARP Spoofing Detected',
                    'description': (
                        f'O IP {ip} trocou o MAC de {old_mac} para {new_mac} '
                        'com padrão de envenenamento: ' + '; '.join(reasons)
                    ),
                    'ip': ip,
                    'details': details,
                    'recommendation': (
                        'Padrão característico de ARP spoofing / MITM. Isole o '
                        'MAC atacante na porta do switch, ative Dynamic ARP '
                        'Inspection e verifique as sessões que passaram por ele.'
                    ),
                })
            else:
                gateway = self._is_gateway(ip)
                details['likely_gateway'] = gateway
                alerts.append({
                    'severity': 'high' if gateway else 'medium',
                    'category': 'arp',
                    'title': 'ARP IP-to-MAC Change',
                    'description': (
                        f'O IP {ip} trocou o MAC de {old_mac} para {new_mac} '
                        'uma única vez, sem flip-flop nem reanúncios agressivos'
                        + (' — o IP parece ser um gateway' if gateway else '')
                        + '. Compatível com reatribuição DHCP ou troca de '
                        'equipamento.'
                    ),
                    'ip': ip,
                    'details': details,
                    'recommendation': (
                        'Confirme se houve troca de dispositivo/placa ou '
                        'reatribuição DHCP. Se o IP for do gateway ou de um '
                        'servidor com MAC fixo, trate como possível MITM.'
                    ),
                })
        return alerts


class ArpHostDiscoveryStreamingDetector(StreamingDetector):
    """Detecta máquinas internas varrendo a rede via ARP request (host
    discovery). Ignora origens marcadas como Roteador e exclui requisições
    cujo destino é uma Impressora — endpoints comuns que uma estação
    contata legitimamente. Alvos para os quais ainda não temos device_type
    cadastrado contam normalmente, pois é justamente esse o caso que o
    usuário quer investigar."""
    name = 'arp_host_discovery'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold_targets = self.thresholds.get('arp_discovery_min_targets', 10)
        self.threshold_window = self.thresholds.get('arp_discovery_time_window', 60)
        self.device_types = (self.settings.get('device_types') or {})
        self.by_src = defaultdict(lambda: {'targets': set(), 'ts': []})

    def _is_router(self, ip):
        dt = self.device_types.get(ip)
        if dt == 'Roteador':
            return True
        # Fallback heurístico: gateways comuns terminam em .1 ou .254
        try:
            last = ip.rsplit('.', 1)[-1]
            return last in ('1', '254')
        except Exception:
            return False

    def _is_printer(self, ip):
        return self.device_types.get(ip) == 'Impressora'

    def update(self, pkt):
        if ARP not in pkt:
            return
        a = pkt[ARP]
        # Apenas requests (who-has)
        if a.op != 1:
            return
        src_ip = a.psrc or ''
        dst_ip = a.pdst or ''
        if not src_ip or not dst_ip:
            return
        if src_ip in ('0.0.0.0', '255.255.255.255'):
            return
        # Origem é roteador → varredura legítima
        if self._is_router(src_ip):
            return
        # Destino é impressora → comunicação legítima (descoberta de printer)
        if self._is_printer(dst_ip):
            return
        # Gratuitous ARP (probe do próprio IP) — não conta como discovery
        if src_ip == dst_ip:
            return
        rec = self.by_src[src_ip]
        rec['targets'].add(dst_ip)
        rec['ts'].append((float(pkt.time), dst_ip))

    def finalize(self):
        alerts = []
        for src, data in self.by_src.items():
            targets = data['targets']
            if len(targets) < self.threshold_targets:
                continue
            events = sorted(data['ts'])
            # Janela deslizante sobre ALVOS DISTINTOS. A versão anterior
            # contava requests — um host repetindo who-has para o mesmo IP
            # morto 10x em 60s "enchia" a janela e, somado a 10 vizinhos ao
            # longo do dia, virava varredura.
            window = self.threshold_window
            best = 1
            counts = Counter()
            distinct = 0
            j = 0
            n = len(events)
            for i in range(n):
                while j < n and events[j][0] - events[i][0] <= window:
                    if counts[events[j][1]] == 0:
                        distinct += 1
                    counts[events[j][1]] += 1
                    j += 1
                best = max(best, distinct)
                tgt = events[i][1]
                counts[tgt] -= 1
                if counts[tgt] == 0:
                    distinct -= 1
            fast = best >= self.threshold_targets
            if window > 0 and not fast:
                # Fora da janela apertada: um servidor que conversa com muitos
                # clientes ao longo do dia também faz ARP para todos eles. A
                # varredura prolongada só é mantida quando o total é bem maior
                # que o limiar — e com severidade menor.
                if len(targets) < self.threshold_targets * 3:
                    continue
            ts = [e[0] for e in events]
            duration = float(ts[-1] - ts[0]) if ts else 0.0
            alerts.append({
                'severity': 'high' if fast else 'medium',
                'category': 'scan',
                'title': 'ARP Host Discovery (varredura interna)',
                'description': (
                    f'O host {src} enviou ARP requests para {len(targets)} '
                    f'destinos distintos (não-impressoras) em {duration:.1f}s'
                ),
                'ip': src,
                'details': {
                    'src': src,
                    'targets_count': len(targets),
                    'targets_sample': sorted(targets)[:15],
                    'duration_seconds': round(duration, 2),
                    'window_max_targets': best,
                },
                'recommendation': (
                    'Uma estação varrendo a rede por ARP normalmente indica '
                    'reconhecimento interno. Verifique se o host está '
                    'comprometido ou se é uma ferramenta autorizada (nmap/arp-scan). '
                    'Se for autorizado, cadastre o IP como confiável.'
                ),
            })
        return alerts


class NdpSpoofingStreamingDetector(StreamingDetector):
    """IPv6 Neighbor Discovery spoofing — the v6 analogue of ARP spoofing.

    A Neighbor Advertisement (ICMPv6 type 136) asserts "IPv6 `tgt` is at MAC
    `lladdr`". Forging NAs poisons neighbor caches for MITM, exactly like
    gratuitous ARP on v4. ArpSpoofingStreamingDetector only sees v4, so this
    closes the gap opened when IPv6 coverage was added.

    Signals:
      * **tgt->MAC conflict** (critical): the same IPv6 target address is
        advertised with two different link-layer addresses — a live poisoning
        race or MITM insertion.
      * **Unsolicited NA flood** (high): many override-flag NAs from one MAC.
        `Responder`/`parasite6`-style tools spam override NAs to keep a
        poisoned mapping fresh; a burst above threshold is the signature.
    """
    name = 'ndp_spoofing'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold = self.thresholds.get('ndp_override_max', 5)
        self.tgt_to_mac = {}
        self.override_count = defaultdict(int)
        self.alerts = []

    def update(self, pkt):
        if NDP_LAYER is None or NDP_LAYER not in pkt:
            return
        nd = pkt[NDP_LAYER]
        # Only advertisements assert an address→MAC binding.
        if int(getattr(nd, 'nd_type', 0)) != 136:
            return
        tgt = getattr(nd, 'tgt', None)
        mac = getattr(nd, 'lladdr', None)
        if not tgt or not mac:
            return
        if tgt in self.tgt_to_mac and self.tgt_to_mac[tgt] != mac:
            self.alerts.append({
                'severity': 'critical',
                'category': 'arp',
                'title': 'IPv6 NDP Spoofing Detected',
                'description': (
                    f'O IPv6 {tgt} trocou o MAC de {self.tgt_to_mac[tgt]} '
                    f'para {mac} em um Neighbor Advertisement'
                ),
                'ip': tgt,
                'details': {
                    'src_ip': tgt,
                    'target_ip': tgt,
                    'old_mac': self.tgt_to_mac[tgt],
                    'new_mac': mac,
                    'protocol': 'ICMPv6-ND',
                },
                'recommendation': (
                    'Uma associação IPv6→MAC que muda em Neighbor '
                    'Advertisements é o equivalente v6 do ARP spoofing (MITM). '
                    'Ative RA Guard / inspeção ND nos switches, verifique qual '
                    'host é o dono legítimo do endereço e isole o MAC que está '
                    'anunciando.'
                ),
            })
        self.tgt_to_mac[tgt] = mac
        # Unsolicited (override-flag) NAs: the poisoning-refresh signature.
        if int(getattr(nd, 'override', 0)):
            self.override_count[mac] += 1
            if self.override_count[mac] == self.threshold:
                self.alerts.append({
                    'severity': 'high',
                    'category': 'arp',
                    'title': 'Unsolicited IPv6 NA Flood',
                    'description': (
                        f'O MAC {mac} enviou {self.override_count[mac]} '
                        'Neighbor Advertisements com flag override (não solicitados)'
                    ),
                    'ip': getattr(nd, 'src_ip', None) or tgt,
                    'details': {
                        'mac': mac,
                        'src_ip': getattr(nd, 'src_ip', None),
                        'count': self.override_count[mac],
                        'protocol': 'ICMPv6-ND',
                    },
                    'recommendation': (
                        'Rajadas de NAs override não solicitados são como as '
                        'ferramentas de envenenamento v6 (parasite6, Responder) '
                        'mantêm viva uma entrada de cache forjada. Ative RA '
                        'Guard / inspeção ND e monitore este MAC.'
                    ),
                })

    def finalize(self):
        return self.alerts


class DnsTunnelingStreamingDetector(StreamingDetector):
    """Long, high-entropy subdomains -> DNS tunneling / exfil.

    Aggregated per (source, registrable zone) — the pre-2026-09 version
    raised one *critical* per query and only looked at the FIRST label, which
    (a) turned a single odd lookup into a critical and (b) missed tools like
    dnscat2/iodine/DNSExfiltrator that split the payload across several
    <=63-byte labels. The encoded part is now everything below the base
    zone (dots removed), and severity grows with the number of distinct
    suspicious names sent to the zone.

    Queries to zones of DNS-based reputation services (AV/EDR file-hash
    lookups, DNSBLs, Team Cymru) are skipped: they are long hex/base32 by
    design and are resolved by the vendor's own authoritative servers, so
    they cannot be an attacker-controlled channel.
    """
    name = 'dns_tunneling'

    MAX_ZONES = 50_000
    MAX_SAMPLES = 5

    def __init__(self, analyzer):
        super().__init__(analyzer)
        from ..constants import DNS_REPUTATION_LOOKUP_ZONES
        self.subdomain_threshold = self.thresholds.get(
            'dns_subdomain_length', 50)
        self.entropy_threshold = self.thresholds.get('dns_entropy_min', 3.5)
        self._benign_zones = DNS_REPUTATION_LOOKUP_ZONES
        # (src, base_zone) -> aggregate
        self.agg = {}

    def _is_benign_zone(self, base, query):
        for z in self._benign_zones:
            if base == z or query.endswith('.' + z):
                return True
        return False

    def update(self, pkt):
        if DNS not in pkt or IP not in pkt:
            return
        d = pkt[DNS]
        if d.qr != 0 or DNSQR not in pkt:
            return
        try:
            query = pkt[DNSQR].qname
            if isinstance(query, bytes):
                query = query.decode('utf-8', errors='ignore')
            query = query.rstrip('.').lower()
            parts = query.split('.')
            if len(parts) < 3:
                return
            if parts[-1] in ('local', 'arpa', 'localdomain', 'home',
                             'internal', 'lan'):
                return
            from ..constants import base_zone
            base = base_zone(parts)
            n_base = base.count('.') + 1
            sub_labels = parts[:-n_base]
            if not sub_labels:
                return
            longest = max(len(lbl) for lbl in sub_labels)
            encoded = ''.join(sub_labels)
            # One long label (classic) OR the payload split across several
            # labels whose concatenation is long (dnscat2/iodine style).
            if not (longest > self.subdomain_threshold
                    or (len(sub_labels) >= 2
                        and len(encoded) > self.subdomain_threshold * 1.6)):
                return
            entropy = self.analyzer._calculate_entropy(encoded)
            if entropy <= self.entropy_threshold:
                return
            if self._is_benign_zone(base, query):
                return
            src = pkt[IP].src
            key = (src, base)
            rec = self.agg.get(key)
            ts = float(pkt.time)
            if rec is None:
                if len(self.agg) >= self.MAX_ZONES:
                    return
                rec = self.agg[key] = {
                    'names': set(), 'samples': [], 'max_len': 0,
                    'max_entropy': 0.0, 'first_ts': ts, 'last_ts': ts,
                    'first_sub': '.'.join(sub_labels),
                    'first_entropy': entropy,
                }
            if query not in rec['names'] and len(rec['names']) < 10_000:
                rec['names'].add(query)
                if len(rec['samples']) < self.MAX_SAMPLES:
                    rec['samples'].append(query)
            rec['max_len'] = max(rec['max_len'], len('.'.join(sub_labels)))
            rec['max_entropy'] = max(rec['max_entropy'], entropy)
            rec['first_ts'] = min(rec['first_ts'], ts)
            rec['last_ts'] = max(rec['last_ts'], ts)
        except Exception:
            pass

    def finalize(self):
        alerts = []
        for (src, base), rec in self.agg.items():
            n = len(rec['names'])
            if n >= 10:
                severity = 'critical'
            elif n >= 3:
                severity = 'high'
            else:
                severity = 'medium'
            alerts.append({
                'severity': severity,
                'category': 'dns',
                'title': 'DNS Tunneling Suspected',
                'description': (
                    f'O host {src} enviou {n} consulta(s) distinta(s) para a '
                    f'zona {base} com subdomínio longo (até {rec["max_len"]} '
                    f'caracteres) e entropia alta (até '
                    f'{rec["max_entropy"]:.2f})'
                ),
                'ip': src,
                'details': {
                    'src_ip': src,
                    'base_domain': base,
                    'domain': rec['samples'][0] if rec['samples'] else base,
                    'subdomain': rec['first_sub'],
                    'subdomain_length': rec['max_len'],
                    'entropy': round(rec['max_entropy'], 2),
                    'distinct_queries': n,
                    'samples': rec['samples'],
                    'first_ts': rec['first_ts'],
                    'last_ts': rec['last_ts'],
                },
                'recommendation': (
                    'Bloqueie o domínio e investigue o host em busca de '
                    'malware. O tunelamento DNS é comumente usado para '
                    'exfiltração de dados. Poucas consultas isoladas podem ser '
                    'um serviço legítimo de reputação/telemetria — confira o '
                    'dono da zona antes de escalar.'
                ),
            })
        return alerts


class DnsCumulativeExfilStreamingDetector(StreamingDetector):
    """Detect cumulative DNS exfiltration to a single authoritative zone.

    O DnsTunnelingStreamingDetector clássico exige subdomínio longo *E*
    entropia alta — sinal forte por query, mas perde o caso de exfil
    fragmentada em queries curtas. Aqui acumulamos por (src_ip, zona-base)
    o volume total de bytes de qname enviados e o número de subdomínios
    distintos. Acima de 50KB acumulados ou 100 subdomínios únicos para uma
    única zona externa, é forte indicador de tunelamento por baixo do
    radar de entropia.

    A zona-base é extraída via constants.base_zone, que entende sufixos
    públicos compostos (co.uk, com.br); um servidor exfil tipicamente é
    `something.evil.com`, então `evil.com` agrega todos os subdomínios.
    """
    name = 'dns_cumulative_exfil'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.byte_threshold = self.thresholds.get(
            'dns_cumulative_exfil_bytes', 50 * 1024,
        )
        self.subdomain_threshold = self.thresholds.get(
            'dns_cumulative_exfil_subdomains', 100,
        )
        from ..constants import (
            DNS_REPUTATION_LOOKUP_ZONES, DNS_PROVIDER_OWNED_ZONES,
        )
        # Zones whose authoritative servers belong to the vendor — queries
        # there can never reach an attacker (see constants).
        self._skip_zones = set(DNS_REPUTATION_LOOKUP_ZONES) | set(
            DNS_PROVIDER_OWNED_ZONES)
        # (src_ip, base_domain) -> {bytes, subdomains:set, encoded, first_ts, last_ts}
        self.agg = defaultdict(lambda: {
            'bytes': 0,
            'subdomains': set(),
            'encoded': 0,
            'first_ts': 0.0,
            'last_ts': 0.0,
        })

    def _looks_encoded(self, sub):
        """Payload-carrying subdomains are long base32/base64/hex blobs;
        hostnames under a corporate/CDN zone (srv01, wks-finance-12,
        eu-west-1) are short and pronounceable."""
        joined = sub.replace('.', '')
        if (len(joined) >= 20
                and self.analyzer._calculate_entropy(joined) >= 3.8):
            return True
        return (len(joined) >= 12
                and self.analyzer._dga_score(joined) >= 0.7)

    def update(self, pkt):
        if DNS not in pkt or IP not in pkt:
            return
        d = pkt[DNS]
        if d.qr != 0 or DNSQR not in pkt:
            return
        try:
            query = pkt[DNSQR].qname
            if isinstance(query, bytes):
                query = query.decode('utf-8', errors='ignore')
            query = query.rstrip('.').lower()
            if not query:
                return
            parts = query.split('.')
            if len(parts) < 3:
                return
            # Pula zonas internas e LLMNR/mDNS — irrelevantes para exfil DNS.
            if parts[-1] in ('local', 'arpa', 'localdomain', 'home',
                             'internal', 'lan'):
                return
            # base_zone entende sufixos públicos compostos (co.uk, com.br):
            # `a.b.evil.co.uk` agrega em `evil.co.uk`, não em `co.uk` — o que
            # misturaria domínios não relacionados na mesma zona.
            from ..constants import base_zone
            base = base_zone(parts)
            if base in self._skip_zones:
                return
            n_base = base.count('.') + 1
            # O "sub" é tudo antes da zona-base. Para `a.b.c.evil.com` →
            # subdomínio = 'a.b.c'.
            sub = '.'.join(parts[:-n_base])
            if not sub:
                return
            src_ip = pkt[IP].src
            rec = self.agg[(src_ip, base)]
            rec['bytes'] += len(query)
            if sub not in rec['subdomains'] and len(rec['subdomains']) < 20_000:
                rec['subdomains'].add(sub)
                if self._looks_encoded(sub):
                    rec['encoded'] += 1
            if rec['first_ts'] == 0.0:
                rec['first_ts'] = pkt.time
            rec['last_ts'] = pkt.time
        except Exception:
            return

    def finalize(self):
        alerts = []
        for (src_ip, base), rec in self.agg.items():
            n_sub = len(rec['subdomains'])
            if (rec['bytes'] < self.byte_threshold
                    and n_sub < self.subdomain_threshold):
                continue
            duration = max(0.0, rec['last_ts'] - rec['first_ts'])
            # Fração de subdomínios com cara de payload codificado. Muitos
            # nomes LEGÍVEIS numa zona (hostnames de uma rede corporativa,
            # edges regionais de um SaaS) é inventário, não exfiltração.
            encoded_ratio = rec['encoded'] / n_sub if n_sub else 0.0
            both = (rec['bytes'] >= self.byte_threshold
                    and n_sub >= self.subdomain_threshold)
            if encoded_ratio >= 0.5:
                # Bytes acima do limite + muitos subdomínios = critical;
                # qualquer um dos dois sozinho = high.
                severity = 'critical' if both else 'high'
            elif encoded_ratio >= 0.2:
                severity = 'medium'
            else:
                severity = 'low'
            alerts.append({
                'severity': severity,
                'category': 'dns',
                'title': 'Cumulative DNS Exfiltration Suspected',
                'description': (
                    f'O host {src_ip} enviou {rec["bytes"]} bytes distribuídos '
                    f'em {n_sub} subdomínios distintos para uma única zona '
                    f'({base}) ao longo de {duration:.0f}s. O padrão condiz '
                    'com exfiltração DNS lenta, mesmo quando as queries '
                    'individuais parecem normais.'
                ),
                'ip': src_ip,
                'details': {
                    'source_ip': src_ip,
                    'base_domain': base,
                    'cumulative_bytes': rec['bytes'],
                    'unique_subdomains': n_sub,
                    'encoded_subdomains': rec['encoded'],
                    'encoded_ratio': round(encoded_ratio, 3),
                    'duration_seconds': round(duration, 1),
                    'first_ts': rec['first_ts'],
                    'last_ts': rec['last_ts'],
                    'subdomain_samples': sorted(
                        rec['subdomains'],
                    )[:5],
                },
                'recommendation': (
                    f'Bloqueie o domínio {base} nos resolvers internos, '
                    f'inspecione {src_ip} em busca de implantes que usam DNS '
                    'como canal C2/exfil (iodine, dnscat2, DNSExfiltrator) e '
                    'audite o que foi extraído antes do bloqueio.'
                ),
            })
        return alerts


class InsecureProtocolsStreamingDetector(StreamingDetector):
    """Detecta FTP (porta 21) e Telnet (porta 23) em claro.

    Acompanha cada fluxo (server, client, port) via TcpFlowTracker e
    determina, no fim, se a conexão foi de fato estabelecida ou se só
    houve scan / ICMP-unreachable. A severidade do alerta acompanha o
    estado: conexão real = alta (FTP) / crítica (Telnet); só scan ou
    falha de entrega = baixa (informativo). Isso evita inflar o triage
    com alertas para tráfego que nunca chegou ao serviço.
    """
    name = 'insecure_protocols'

    _PORTS = {21: 'FTP', 23: 'Telnet'}
    _PROTO_META = {
        'FTP': {
            'title': 'Insecure Protocol: FTP',
            'desc_prefix': (
                'Protocolo FTP detectado - credenciais transmitidas em texto claro'
            ),
            'recommendation':
                'Migre para SFTP ou FTPS para transferências de arquivos seguras.',
            'severity_established': 'high',
            'severity_open': 'high',
            'severity_failed': 'low',
            'port': 21,
        },
        'Telnet': {
            'title': 'Insecure Protocol: Telnet',
            'desc_prefix': 'Protocolo Telnet detectado - extremamente inseguro',
            'recommendation': (
                'Substitua o Telnet por SSH imediatamente. O Telnet transmite '
                'todos os dados em texto claro.'
            ),
            'severity_established': 'critical',
            'severity_open': 'high',
            'severity_failed': 'low',
            'port': 23,
        },
    }
    _STATUS_PRIORITY = (
        'established', 'open_no_ack', 'icmp_unreachable',
        'scan_rejected', 'scan_no_response',
    )

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.tracker = TcpFlowTracker()

    def update(self, pkt):
        if IP not in pkt:
            return
        if TCP in pkt:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            if dport in self._PORTS:
                port, server, client = dport, pkt[IP].dst, pkt[IP].src
                sender_is_client = True
            elif sport in self._PORTS:
                port, server, client = sport, pkt[IP].src, pkt[IP].dst
                sender_is_client = False
            else:
                return
            self.tracker.observe_tcp(server, client, port, pkt, sender_is_client)
            return
        if ICMP in pkt:
            # Só enriquece fluxos já existentes (create_missing=False) — um
            # ICMP-error solto sem TCP correspondente não é evidência de FTP.
            self.tracker.observe_icmp_error(
                pkt, ports=self._PORTS.keys(), create_missing=False,
            )

    def finalize(self):
        per_target = defaultdict(lambda: {
            'clients': set(),
            'by_status': defaultdict(set),
            'bytes_total': 0,
            'first_ts': None,
            'last_ts': None,
            'packets': 0,
        })
        for (server, client, port), rec in self.tracker.flows.items():
            proto = self._PORTS.get(port)
            if not proto:
                continue
            status = TcpFlowTracker.status_for(rec)
            bucket = per_target[(proto, server)]
            bucket['clients'].add(client)
            bucket['by_status'][status].add(client)
            bucket['bytes_total'] += rec['bytes_c2s'] + rec['bytes_s2c']
            bucket['packets'] += rec['packets']
            if rec['first_ts'] is not None and (
                bucket['first_ts'] is None
                or rec['first_ts'] < bucket['first_ts']
            ):
                bucket['first_ts'] = rec['first_ts']
            if rec['last_ts'] is not None and (
                bucket['last_ts'] is None
                or rec['last_ts'] > bucket['last_ts']
            ):
                bucket['last_ts'] = rec['last_ts']

        alerts = []
        for (proto, server), bucket in per_target.items():
            meta = self._PROTO_META[proto]
            overall_status = None
            for s in self._STATUS_PRIORITY:
                if bucket['by_status'].get(s):
                    overall_status = s
                    break
            if overall_status is None:
                continue
            primary_client = sorted(bucket['by_status'][overall_status])[0]
            established_clients = sorted(
                bucket['by_status'].get('established', set())
            )

            if overall_status == 'established':
                severity = meta['severity_established']
            elif overall_status == 'open_no_ack':
                severity = meta['severity_open']
            else:
                severity = meta['severity_failed']

            description = (
                f'{meta["desc_prefix"]}. '
                + CONNECTION_STATUS_TEXT.get(overall_status, '')
            )
            alerts.append({
                'severity': severity,
                'category': 'protocol',
                'title': meta['title'],
                'description': description,
                'ip': server,
                'details': {
                    'protocol': proto,
                    'port': meta['port'],
                    'src_ip': primary_client,
                    'dst_ip': server,
                    'peer_ips': sorted(bucket['clients'])[:10],
                    'peer_count': len(bucket['clients']),
                    'peer_role': 'client',
                    'connection_established': bool(established_clients),
                    'connection_status': overall_status,
                    'bytes_exchanged': bucket['bytes_total'],
                    'established_clients': established_clients[:10],
                    'first_ts': bucket['first_ts'],
                    'last_ts': bucket['last_ts'],
                    'flow_count': len(bucket['clients']),
                    'packet_count': bucket['packets'],
                },
                'recommendation': meta['recommendation'],
            })
        return alerts


class CleartextCredentialsStreamingDetector(StreamingDetector):
    """Detecta credenciais em claro em protocolos de mail/FTP/HTTP.

    SMTP/IMAP/POP3 (e FTP) frequentemente fazem AUTH antes de qualquer
    STARTTLS. Quando o cliente despeja `AUTH PLAIN <b64>`, `AUTH LOGIN`,
    `USER`/`PASS` ou `LOGIN user pass` em payload TCP RAW, a credencial
    já vazou — uma única ocorrência basta. Também olhamos HTTP Basic
    Authorization header em portas HTTP cleartext (80, 8080)."""
    name = 'cleartext_credentials'

    # Portas onde uma sessão *deveria* estar dentro de TLS/SSL puro.
    # Ports 465/993/995 só apareceriam em RAW se TLS falhar; manter aqui
    # custa nada e cobre o edge case.
    MAIL_PORTS_PLAIN = {25, 110, 143, 587}
    MAIL_PORTS_TLS_NATIVE = {465, 993, 995}
    HTTP_PORTS = {80, 8080, 8000, 8888}
    FTP_PORT = 21

    def __init__(self, analyzer):
        super().__init__(analyzer)
        # (src, dst, port, kind) -> first timestamp seen.
        self.seen = {}
        # Marca pares (cliente, servidor) que já fizeram STARTTLS — pacotes
        # após esse marco em uma mesma conexão são considerados criptografados
        # e ignorados pelo detector. Chave: (cliente, servidor, port).
        self.starttls_done = set()
        self.tracker = TcpFlowTracker()
        self._tracked_ports = (
            set(self.MAIL_PORTS_PLAIN) | set(self.HTTP_PORTS) | {self.FTP_PORT}
        )

    def _record(self, src, dst, port, kind, ts):
        key = (src, dst, port, kind)
        if key in self.seen:
            return
        self.seen[key] = ts

    def update(self, pkt):
        if IP not in pkt:
            return
        # Alimenta o tracker (handshake + bytes + ICMP) mesmo em pacotes sem
        # Raw, pra que bytes_exchanged e connection_status saiam corretos.
        if TCP in pkt:
            sport_i = int(pkt[TCP].sport)
            dport_i = int(pkt[TCP].dport)
            if dport_i in self._tracked_ports:
                self.tracker.observe_tcp(
                    pkt[IP].dst, pkt[IP].src, dport_i, pkt,
                    sender_is_client=True,
                )
            elif sport_i in self._tracked_ports:
                self.tracker.observe_tcp(
                    pkt[IP].src, pkt[IP].dst, sport_i, pkt,
                    sender_is_client=False,
                )
        elif ICMP in pkt:
            self.tracker.observe_icmp_error(
                pkt, ports=self._tracked_ports, create_missing=False,
            )
            return
        if TCP not in pkt or Raw not in pkt:
            return
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        # client -> server: dport é o port do serviço
        if dport in self.MAIL_PORTS_PLAIN:
            client, server, port = pkt[IP].src, pkt[IP].dst, dport
            direction = 'c2s'
        elif sport in self.MAIL_PORTS_PLAIN:
            client, server, port = pkt[IP].dst, pkt[IP].src, sport
            direction = 's2c'
        elif dport in self.HTTP_PORTS:
            client, server, port = pkt[IP].src, pkt[IP].dst, dport
            direction = 'http_c2s'
        elif dport == self.FTP_PORT:
            client, server, port = pkt[IP].src, pkt[IP].dst, dport
            direction = 'ftp_c2s'
        else:
            return
        if (client, server, port) in self.starttls_done:
            return
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return
        if not payload:
            return
        # Limita inspeção aos primeiros 1024 bytes para evitar custo em
        # transferências grandes. Comandos auth aparecem no início.
        head = payload[:1024]
        # Heurística rápida: comandos são linha ASCII curta. Se não há
        # nenhum byte ASCII printable comum, pula.
        if not any(32 <= b < 127 for b in head[:8]):
            return
        try:
            text = head.decode('ascii', errors='ignore')
        except Exception:
            return
        upper = text.upper()
        # ---- STARTTLS upgrade: marca o par como criptografado dali em diante.
        # Só o COMANDO do cliente conta (STARTTLS / IMAP "tag STARTTLS" /
        # POP3 STLS / FTP AUTH TLS). A versão anterior marcava quando
        # qualquer lado mencionava STARTTLS — mas o servidor ANUNCIA
        # "250-STARTTLS" na resposta ao EHLO em toda sessão SMTP, então um
        # cliente que ignorava o upgrade e mandava AUTH LOGIN em claro (o
        # exato caso que este detector existe para pegar) ficava invisível.
        if direction in ('c2s', 'ftp_c2s'):
            first_line = upper.splitlines()[0].strip() if upper else ''
            tokens = first_line.split()
            if (any(t in ('STARTTLS', 'STLS') for t in tokens[:2])
                    or first_line.startswith(('AUTH TLS', 'AUTH SSL'))):
                self.starttls_done.add((client, server, port))
                return
        ts = pkt.time
        # ---- Mail: SMTP/POP3/IMAP/Submission.
        if direction == 'c2s' and port in self.MAIL_PORTS_PLAIN:
            # SMTP AUTH PLAIN <b64>  /  AUTH LOGIN
            if upper.startswith('AUTH PLAIN') or upper.startswith('AUTH LOGIN'):
                self._record(client, server, port, 'smtp_auth', ts)
                return
            # POP3 USER ... + PASS ...
            if upper.startswith('USER ') or upper.startswith('PASS '):
                if port == 110 or port == 25 or port == 587:
                    self._record(client, server, port, 'pop3_or_smtp_userpass', ts)
                    return
            # IMAP LOGIN user pass  (linha tipicamente prefixada por tag — ex: "a001 LOGIN ...")
            # Detectamos pela presença de " LOGIN " seguida de dois tokens.
            if port == 143:
                # IMAP usa tag arbitrária; basta procurar " LOGIN " no payload.
                if ' LOGIN ' in upper or upper.startswith('LOGIN '):
                    # Evita falso positivo: "CAPABILITY ... LOGINDISABLED" do
                    # servidor — só registra se for direção cliente->servidor
                    # (já garantido por direction == 'c2s').
                    self._record(client, server, port, 'imap_login', ts)
                    return
        # ---- FTP: USER/PASS em claro (21).
        if direction == 'ftp_c2s':
            if upper.startswith('USER ') or upper.startswith('PASS '):
                self._record(client, server, port, 'ftp_userpass', ts)
                return
        # ---- HTTP Basic em porta cleartext.
        if direction == 'http_c2s':
            if 'AUTHORIZATION: BASIC ' in upper:
                self._record(client, server, port, 'http_basic', ts)
                return

    def finalize(self):
        alerts = []
        # Agrupa por (client, server, port) para evitar 1 alerta por kind
        # quando o mesmo par fez USER + PASS + ...
        bundles = defaultdict(list)
        for (src, dst, port, kind), ts in self.seen.items():
            bundles[(src, dst, port)].append((kind, ts))
        meta_by_kind = {
            'smtp_auth': ('SMTP AUTH', 'SMTP'),
            'pop3_or_smtp_userpass': ('POP3/SMTP USER+PASS', 'POP3/SMTP'),
            'imap_login': ('IMAP LOGIN', 'IMAP'),
            'ftp_userpass': ('FTP USER+PASS', 'FTP'),
            'http_basic': ('HTTP Basic Authorization header', 'HTTP'),
        }
        for (src, dst, port), kinds in bundles.items():
            kinds.sort(key=lambda k: k[1])
            first_kind = kinds[0][0]
            label, proto = meta_by_kind.get(first_kind, (first_kind, 'TCP'))
            other_labels = ', '.join(
                sorted({meta_by_kind.get(k, (k, ''))[0] for k, _ in kinds[1:]}),
            )
            conn_status = self.tracker.status(dst, src, port)
            bytes_exchanged = self.tracker.bytes_exchanged(dst, src, port)
            # Credencial em claro que atravessa a internet é exposta a
            # qualquer salto do caminho (critical); dentro da LAN (impressora,
            # roteador, intranet) continua sendo exposição real, mas restrita
            # a quem já está na rede (high).
            internal = (self.analyzer._is_local_ip(src)
                        and self.analyzer._is_local_ip(dst))
            alerts.append({
                'severity': 'high' if internal else 'critical',
                'category': 'protocol',
                'title': f'Cleartext Credentials ({proto})',
                'description': (
                    f'Autenticação em texto claro observada: {label} de '
                    f'{src} para {dst}:{port}' + (
                        f' (também: {other_labels})' if other_labels else ''
                    ) + '. As credenciais ficam visíveis para qualquer um na rede.'
                ),
                'ip': src,
                'details': {
                    'source_ip': src,
                    'src_ip': src,
                    'dst_ip': dst,
                    'target_ip': dst,
                    'port': port,
                    'protocol': proto,
                    'evidence': [meta_by_kind.get(k, (k, ''))[0]
                                 for k, _ in kinds],
                    'first_ts': float(kinds[0][1]),
                    'last_ts': float(kinds[-1][1]),
                    'connection_status': conn_status or 'established',
                    'connection_established': (
                        conn_status is None or conn_status == 'established'
                    ),
                    'bytes_exchanged': bytes_exchanged,
                },
                'recommendation': (
                    'Force TLS/STARTTLS neste serviço. Para SMTP use 587 + '
                    'STARTTLS ou 465 com TLS implícito; para IMAP use 993; para '
                    'POP3 use 995. Troque a senha de qualquer conta cujas '
                    'credenciais possam ter sido transmitidas e audite capturas '
                    'antigas dos mesmos hosts.'
                ),
            })
        return alerts


class ExternalSmbStreamingDetector(StreamingDetector):
    """Streaming de _detect_external_smb_access.

    Acompanha o estado da conexão SMB (handshake + bytes + ICMP) para que
    o analista priorize sessões reais sobre tentativas que ficaram só no
    SYN. Mantém o critério legado de emissão (um alerta por par + sentido).
    """
    name = 'external_smb'

    _STATUS_PRIORITY = (
        'established', 'open_no_ack', 'icmp_unreachable',
        'scan_rejected', 'scan_no_response',
    )

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.smb_ports = analyzer.SMB_PORTS
        self.tuples = set()  # (src, dst, direction)
        self.tracker = TcpFlowTracker()

    def update(self, pkt):
        if IP not in pkt:
            return
        if TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            if dport not in self.smb_ports and sport not in self.smb_ports:
                return
            if dport in self.smb_ports:
                server, client, port = dst_ip, src_ip, dport
                sender_is_client = True
            else:
                server, client, port = src_ip, dst_ip, sport
                sender_is_client = False
            src_local = self.analyzer._is_local_ip(src_ip)
            dst_local = self.analyzer._is_local_ip(dst_ip)
            if (not src_local) and dst_local and dport in self.smb_ports:
                self.tuples.add((src_ip, dst_ip, 'inbound'))
            if src_local and (not dst_local) and dport in self.smb_ports:
                self.tuples.add((src_ip, dst_ip, 'outbound'))
            self.tracker.observe_tcp(
                server, client, port, pkt, sender_is_client,
            )
            return
        if ICMP in pkt:
            self.tracker.observe_icmp_error(
                pkt, ports=self.smb_ports, create_missing=False,
            )

    def _aggregate(self, server, client):
        """Best status + bytes summed across SMB ports for one direction."""
        best_status = None
        established = False
        total_bytes = 0
        for port in self.smb_ports:
            rec = self.tracker.record(server, client, port)
            if rec is None:
                continue
            st = TcpFlowTracker.status_for(rec)
            if st == 'established':
                established = True
            try:
                idx_st = self._STATUS_PRIORITY.index(st)
            except ValueError:
                idx_st = len(self._STATUS_PRIORITY)
            try:
                idx_best = (
                    self._STATUS_PRIORITY.index(best_status)
                    if best_status else len(self._STATUS_PRIORITY)
                )
            except ValueError:
                idx_best = len(self._STATUS_PRIORITY)
            if idx_st < idx_best:
                best_status = st
            total_bytes += rec['bytes_c2s'] + rec['bytes_s2c']
        return best_status, established, total_bytes

    def finalize(self):
        alerts = []
        for src_ip, dst_ip, direction in self.tuples:
            # SMB port é sempre no dst (inbound/outbound já filtram).
            server, client = dst_ip, src_ip
            conn_status, established, bytes_total = self._aggregate(
                server, client,
            )
            if direction == 'inbound':
                base = {
                    'severity': 'critical',
                    'category': 'smb',
                    'title': 'External IP Accessing SMB',
                    'description': (
                        f'O IP externo {src_ip} está acessando SMB no host '
                        f'local {dst_ip}'
                    ),
                    'recommendation': (
                        'O SMB NÃO deveria estar acessível a partir de redes '
                        'externas. Bloqueie as portas SMB (445, 139) no '
                        'firewall para tráfego externo. Investigue um possível '
                        'comprometimento.'
                    ),
                    'details_extra': {
                        'external_ip': src_ip,
                        'local_target': dst_ip,
                        'direction': 'inbound',
                    },
                }
            else:
                base = {
                    'severity': 'high',
                    'category': 'smb',
                    'title': 'SMB Traffic to External IP',
                    'description': (
                        f'O host local {src_ip} está enviando tráfego SMB para '
                        f'o IP externo {dst_ip}'
                    ),
                    'recommendation': (
                        'Tráfego SMB para IPs externos é incomum e '
                        'potencialmente perigoso. Pode indicar exfiltração de '
                        'dados ou host comprometido. Investigue imediatamente.'
                    ),
                    'details_extra': {
                        'local_source': src_ip,
                        'external_target': dst_ip,
                        'direction': 'outbound',
                    },
                }
            # Severity follows how far the session got. An SMB session that
            # established across the perimeter is the real finding; a probe
            # that only met RST/silence means the service was not reachable.
            severity = base['severity']
            if not established:
                if direction == 'inbound':
                    # SYN-ACK = the internal host answers the internet on 445
                    # (exposed); RST/silence = firewall let the probe in but
                    # nothing listened.
                    severity = ('high' if conn_status == 'open_no_ack'
                                else 'medium')
                else:
                    # Blocked/unanswered outbound SMB: still worth a look (a
                    # UNC path in a lure document leaks NTLM when it works),
                    # but nothing left the network.
                    severity = 'medium'
            details = dict(base['details_extra'])
            details.update({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'ports': list(self.smb_ports),
                'connection_status': conn_status,
                'connection_established': established,
                'bytes_exchanged': bytes_total,
            })
            if severity != base['severity']:
                details['severity_original'] = base['severity']
            alerts.append({
                'severity': severity,
                'category': base['category'],
                'title': base['title'],
                'description': base['description'],
                'ip': src_ip,
                'details': details,
                'recommendation': base['recommendation'],
            })
        return alerts


class PingSweepStreamingDetector(StreamingDetector):
    """Streaming de _detect_ping_sweep."""
    name = 'ping_sweep'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold_hosts = self.thresholds.get('ping_sweep_min_hosts', 15)
        self.threshold_window = self.thresholds.get('ping_sweep_time_window', 60)
        self.by_src = defaultdict(lambda: {'targets': set(), 'ts': []})

    def update(self, pkt):
        if ICMP not in pkt or IP not in pkt:
            return
        try:
            if int(pkt[ICMP].type) != 8:  # echo request
                return
        except Exception:
            return
        dst = pkt[IP].dst
        # Multicast/broadcast echo (all-hosts ping) is one packet, not a
        # sweep of distinct hosts.
        try:
            ipobj = ipaddress.ip_address(dst)
            if ipobj.is_multicast or dst.endswith('.255'):
                return
        except ValueError:
            return
        rec = self.by_src[pkt[IP].src]
        rec['targets'].add(dst)
        if len(rec['ts']) < 200_000:
            rec['ts'].append((float(pkt.time), dst))

    def finalize(self):
        alerts = []
        for src, data in self.by_src.items():
            targets = data['targets']
            total_targets = len(targets)
            if total_targets < self.threshold_hosts:
                continue
            events = sorted(data['ts'])
            duration = events[-1][0] - events[0][0]
            # Sliding window over DISTINCT targets (the old check only
            # compared the capture-long duration against the window).
            best = 0
            counts = Counter()
            distinct = 0
            j = 0
            n = len(events)
            for i in range(n):
                while j < n and events[j][0] - events[i][0] <= self.threshold_window:
                    if counts[events[j][1]] == 0:
                        distinct += 1
                    counts[events[j][1]] += 1
                    j += 1
                best = max(best, distinct)
                counts[events[i][1]] -= 1
                if counts[events[i][1]] == 0:
                    distinct -= 1
            fast = (self.threshold_window <= 0
                    or best >= self.threshold_hosts)
            if not fast and total_targets < self.threshold_hosts * 3:
                continue
            # Monitoring (Zabbix/Nagios/PRTG/UPS agents) pings the SAME hosts
            # over and over at a fixed cadence; a discovery sweep touches
            # each target once or twice. Median echoes per target separates
            # them.
            per_target = sorted(Counter(t for _, t in events).values())
            median_pings = per_target[len(per_target) // 2]
            monitoring_like = median_pings >= 4 and duration > 300
            if monitoring_like:
                severity = 'low'
            elif fast:
                severity = 'high'
            else:
                severity = 'medium'
            description = (
                f'O host {src} fez ping em {total_targets} hosts distintos '
                f'em {duration:.1f}s (pico de {best} alvos em '
                f'{self.threshold_window}s)'
            )
            if monitoring_like:
                description += (
                    f'. Cada alvo recebeu ~{median_pings} pings de forma '
                    'recorrente — padrão de monitoramento, não de descoberta.'
                )
            alerts.append({
                'severity': severity,
                'category': 'scan',
                'title': 'ICMP Ping Sweep',
                'description': description,
                'ip': src,
                'details': {
                    'src': src,
                    'targets_count': total_targets,
                    'window_max_targets': best,
                    'duration_seconds': round(duration, 2),
                    'median_pings_per_target': median_pings,
                    'monitoring_pattern': monitoring_like,
                    'targets_sample': sorted(targets)[:10],
                    'first_ts': events[0][0],
                    'last_ts': events[-1][0],
                },
                'recommendation': (
                    'Um host disparando muitos ICMP echo requests por uma '
                    'sub-rede está fazendo descoberta de hosts. Investigue a '
                    'origem.' + (
                        ' O padrão repetitivo sugere um servidor de '
                        'monitoramento — se for o caso, cadastre o papel do '
                        'host ou crie uma regra de supressão.'
                        if monitoring_like else '')
                ),
            })
        return alerts


class HorizontalScanStreamingDetector(StreamingDetector):
    """Streaming de _detect_horizontal_port_scan."""
    name = 'horizontal_scan'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold_hosts = self.thresholds.get('host_scan_min_hosts', 20)
        self.threshold_window = self.thresholds.get('host_scan_time_window', 60)
        # Slow scan: nº de hosts exigido = threshold_hosts * slow_multiplier.
        self.slow_multiplier = self.thresholds.get(
            'host_scan_slow_multiplier', 3)
        # Confirmação por handshake (SYN-ACK): faixas de answer_ratio.
        # >= benign  -> suprime (uso legítimo de serviços)
        # <  critical-> severity critical;  < high -> high;  senão medium
        self.answer_ratio_benign = self.thresholds.get(
            'host_scan_answer_ratio_benign', 0.9)
        self.answer_ratio_critical = self.thresholds.get(
            'host_scan_answer_ratio_critical', 0.2)
        self.answer_ratio_high = self.thresholds.get(
            'host_scan_answer_ratio_high', 0.5)
        self.by_src_port = defaultdict(
            lambda: {'hosts': set(), 'ts': [], 'answered': set()}
        )

    def update(self, pkt):
        if TCP not in pkt or IP not in pkt:
            return
        flags = int(pkt[TCP].flags)
        is_syn = bool(flags & 0x02)
        is_ack = bool(flags & 0x10)
        if not is_syn:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        if src == dst:
            return
        if not is_ack:
            # SYN puro: a sonda enviada pelo scanner.
            rec = self.by_src_port[(src, int(pkt[TCP].dport))]
            rec['hosts'].add(dst)
            rec['ts'].append(pkt.time)
        else:
            # SYN-ACK (0x12): resposta do host sondado. Mapeia de volta ao
            # registro do scanner — (scanner=dst, porta=sport) — e marca que
            # este destino completou o handshake (host vivo, porta aberta).
            # Um sweep de reconhecimento gera muitos SYN sem este retorno.
            rec = self.by_src_port[(dst, int(pkt[TCP].sport))]
            rec['answered'].add(src)

    def finalize(self):
        from ..constants import ALPN_WEB_OK_PORTS
        alerts = []
        # One-sided-capture guard: answer_ratio (SYN-ACK confirmation) is only
        # meaningful when the tap sees the return path. On an egress-only /
        # asymmetric tap NO SYN-ACK is ever captured, so every record scores
        # answer_ratio=0 and the old code called EVERYTHING critical —
        # including a benign monitoring/backup server polling many hosts.
        # If not a single SYN-ACK was seen across the whole capture, treat the
        # handshake signal as unavailable and fall back to fan-out magnitude.
        global_answered = sum(
            len(d['answered']) for d in self.by_src_port.values()
        )
        one_sided = (global_answered == 0)
        for (src, port), data in self.by_src_port.items():
            hosts = data['hosts']
            # Falso-positivo clássico: um cliente interno abrindo conexões
            # para muitos hosts PÚBLICOS na porta 443/80 é apenas navegação
            # web / telemetria de nuvem — não reconhecimento. Um host sweep
            # real numa porta web visa a própria rede interna (varre o LAN).
            # Por isso, em portas web/cliente contamos só destinos internos;
            # em portas não-web (22/445/3389...) o comportamento é inalterado.
            if port in ALPN_WEB_OK_PORTS:
                effective = {
                    h for h in hosts if self.analyzer._is_local_ip(h)
                }
            else:
                effective = hosts
            if len(effective) < self.threshold_hosts:
                continue
            ts = sorted(data['ts'])
            duration = ts[-1] - ts[0]
            if self.threshold_window > 0 and duration > self.threshold_window:
                # Slow horizontal scan: alerta se total de hosts é muito alto
                if len(effective) < self.threshold_hosts * self.slow_multiplier:
                    continue
            # Confirmação por handshake: um sweep de reconhecimento gera
            # muitos SYN sem resposta (hosts mortos, portas fechadas ou
            # filtradas). Conexões legítimas completam o 3-way handshake e o
            # destino devolve SYN-ACK. answer_ratio = fração dos destinos
            # sondados que responderam.
            answered = data['answered'] & effective
            wide_fanout = len(effective) >= self.threshold_hosts * self.slow_multiplier
            if one_sided:
                # No return-path visibility: can't confirm via handshake.
                # Score on fan-out magnitude alone. Only a very wide sweep
                # (>= slow-scan host count) still rates critical; otherwise
                # cap at high so a benign server polling many hosts on an
                # asymmetric tap isn't auto-critical.
                answer_ratio = None
                severity = 'critical' if wide_fanout else 'high'
            else:
                answer_ratio = len(answered) / len(effective)
                if answer_ratio >= self.answer_ratio_benign:
                    # Praticamente todo destino respondeu: uso legítimo de
                    # serviços (proxy, monitor, cliente), não varredura.
                    continue
                if answer_ratio < self.answer_ratio_critical:
                    severity = 'critical'
                elif answer_ratio < self.answer_ratio_high:
                    severity = 'high'
                else:
                    severity = 'medium'
            if one_sided:
                handshake_txt = (
                    'caminho de retorno não capturado (tap assimétrico/somente '
                    'saída) — confirmação por handshake indisponível'
                )
            else:
                handshake_txt = f'{len(answered)} completaram o handshake TCP'
            alerts.append({
                'severity': severity,
                'category': 'scan',
                'title': 'Horizontal Port Scan (Host Sweep)',
                'description': (
                    f'O host {src} sondou a porta {port} em {len(effective)} '
                    f'hosts distintos em {duration:.1f}s ({handshake_txt})'
                ),
                'ip': src,
                'details': {
                    'src': src,
                    'port': port,
                    'hosts_count': len(effective),
                    'hosts_answered': len(answered),
                    'answer_ratio': (round(answer_ratio, 3)
                                     if answer_ratio is not None else None),
                    'capture_one_sided': one_sided,
                    'duration_seconds': round(duration, 2),
                    'hosts_sample': sorted(effective)[:10],
                },
                'recommendation': (
                    'Uma única origem sondando uma porta em muitos hosts '
                    'indica descoberta de serviços / varredura de hosts '
                    '(frequentemente reconhecimento pré-ataque). '
                    + ('O caminho de retorno não foi capturado, então o '
                       'handshake TCP não pôde confirmar a varredura — um '
                       'servidor legítimo de monitoramento/backup consultando '
                       'muitos hosts parece igual num tap assimétrico. '
                       'Correlacione com o papel do host antes de escalar.'
                       if one_sided else
                       'Uma razão de respostas baixa (poucos handshakes '
                       'completos) significa que a maioria das sondas atingiu '
                       'hosts mortos ou filtrados — uma forte assinatura de '
                       'varredura. Investigue a origem em busca de comprometimento.')
                ),
            })
        return alerts


class SnmpWalkStreamingDetector(StreamingDetector):
    """Streaming de _detect_snmp_walk. Mantém timestamps por (src,dst)
    e procura janela de 30s com >= threshold queries no finalize."""
    name = 'snmp_walk'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold = self.thresholds.get('snmp_walk_threshold', 50)
        self.window = self.thresholds.get('snmp_walk_window', 30)
        self.by_pair = defaultdict(list)

    def update(self, pkt):
        if UDP not in pkt or IP not in pkt:
            return
        try:
            if int(pkt[UDP].dport) != 161:
                return
        except Exception:
            return
        self.by_pair[(pkt[IP].src, pkt[IP].dst)].append(pkt.time)

    def finalize(self):
        alerts = []
        for (src, dst), ts_list in self.by_pair.items():
            if len(ts_list) < self.threshold:
                continue
            ts_list.sort()
            best = 0
            for i in range(len(ts_list)):
                count = 0
                for j in range(i, len(ts_list)):
                    if ts_list[j] - ts_list[i] <= self.window:
                        count += 1
                    else:
                        break
                if count > best:
                    best = count
                if best >= self.threshold:
                    break
            if best < self.threshold:
                continue
            # An NMS (Zabbix/LibreNMS/PRTG/Cacti) walks the same device on a
            # fixed poll cycle: several separate bursts over the capture. A
            # one-off enumeration is a single burst. Bursts = groups of
            # queries separated by gaps longer than the window.
            bursts = 1
            for k in range(1, len(ts_list)):
                if ts_list[k] - ts_list[k - 1] > self.window:
                    bursts += 1
            recurring = bursts >= 3
            src_external = not self.analyzer._is_local_ip(src)
            if src_external:
                severity = 'critical'
            elif recurring:
                severity = 'low'
            else:
                severity = 'high'
            description = (
                f'O host {src} enviou {best} queries SNMP para {dst} '
                f'dentro de uma janela de {self.window}s '
                f'(total {len(ts_list)} na captura, {bursts} rajada(s))'
            )
            if src_external:
                description += '. A origem é EXTERNA à rede.'
            elif recurring:
                description += (
                    '. Rajadas recorrentes indicam polling de um sistema de '
                    'monitoramento, não enumeração pontual.'
                )
            alerts.append({
                'severity': severity,
                'category': 'scan',
                'title': 'SNMP Walk Detected',
                'description': description,
                'ip': src,
                'details': {
                    'src': src, 'dst': dst,
                    'queries_in_window': best,
                    'total_queries': len(ts_list),
                    'window_seconds': self.window,
                    'bursts': bursts,
                    'recurring_polling': recurring,
                    'first_ts': ts_list[0],
                    'last_ts': ts_list[-1],
                },
                'recommendation': (
                    'Queries SNMP em alto volume (GETNEXT/GETBULK) indicam um '
                    'SNMP walk usado para enumerar a configuração do '
                    'dispositivo. Verifique se é autorizado; imponha SNMPv3 '
                    'com autenticação e restrinja o SNMP no firewall.'
                ),
            })
        return alerts


class LlmnrNbtnsStreamingDetector(StreamingDetector):
    """Streaming de _detect_llmnr_nbtns_response."""
    name = 'llmnr_nbtns'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold = self.thresholds.get('llmnr_response_threshold', 10)
        self.by_src = defaultdict(int)
        self.names_by_src = defaultdict(set)

    def update(self, pkt):
        if UDP not in pkt or IP not in pkt:
            return
        try:
            sport = int(pkt[UDP].sport)
        except Exception:
            return
        if sport not in (5355, 137):
            return
        src = pkt[IP].src
        if not self.analyzer._is_local_ip(src):
            return
        # scapy dissects LLMNR (5355) as LLMNRResponse and NBT-NS (137) as
        # NBNSHeader — neither is the generic DNS class, so the old
        # `DNS in pkt` guard never matched. pkt_view normalises both into a
        # qr/ancount view keyed by the concrete scapy class.
        layer = None
        if sport == 5355 and LLMNR_LAYER is not None and LLMNR_LAYER in pkt:
            layer = pkt[LLMNR_LAYER]
        elif sport == 137 and NBNS_LAYER is not None and NBNS_LAYER in pkt:
            layer = pkt[NBNS_LAYER]
        if layer is None:
            return
        try:
            if int(layer.qr) == 1 and int(layer.ancount) > 0:
                self.by_src[src] += 1
                name = getattr(layer, 'qname', '') or ''
                if name:
                    names = self.names_by_src[src]
                    if len(names) < 200:
                        names.add(name)
        except Exception:
            pass

    def finalize(self):
        alerts = []
        for src, count in self.by_src.items():
            if count < self.threshold:
                continue
            names = self.names_by_src.get(src) or set()
            # Every Windows host answers LLMNR/NBT-NS for its OWN name (and
            # its NetBIOS variants) — a busy file server does so hundreds of
            # times a day. Responder answers for WHATEVER is asked. So the
            # number of distinct names answered is the discriminator.
            if names and len(names) <= 2:
                severity = 'low'
            elif count >= self.threshold * 3 or len(names) >= 5:
                severity = 'critical'
            else:
                severity = 'high'
            names_txt = (f' para {len(names)} nome(s) distinto(s)'
                         if names else '')
            description = (
                f'O host {src} respondeu {count} requisição(ões) '
                f'LLMNR/NBT-NS{names_txt}'
            )
            if names and len(names) <= 2:
                description += (
                    ' — sempre o(s) mesmo(s) nome(s), o que é o host '
                    'respondendo pelo próprio nome (comportamento normal do '
                    'Windows com LLMNR/NetBIOS ativos).'
                )
            else:
                description += (
                    ' — característico de envenenamento no estilo Responder')
            alerts.append({
                'severity': severity,
                'category': 'lateral',
                'title': 'LLMNR/NBT-NS Response Activity (Possible Poisoning)',
                'description': description,
                'ip': src,
                'details': {
                    'src': src, 'response_count': count,
                    'distinct_names': len(names),
                    'names_sample': sorted(names)[:10],
                },
                'recommendation': (
                    'Respostas LLMNR/NBT-NS frequentes são incomuns fora de '
                    'servidores de nomes legítimos. Desative o LLMNR via Group '
                    'Policy, desative o NetBIOS sobre TCP/IP e isole este host '
                    'para análise forense.'
                ),
            })
        return alerts


class IcmpTunnelingStreamingDetector(StreamingDetector):
    """Streaming de _detect_icmp_tunneling."""
    name = 'icmp_tunneling'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold_size = self.thresholds.get('icmp_payload_threshold', 64)
        self.threshold_count = self.thresholds.get('icmp_min_large_packets', 10)
        self.by_pair = defaultdict(
            lambda: {'count': 0, 'total': 0, 'sizes': [], 'filler': 0})

    def update(self, pkt):
        if ICMP not in pkt or IP not in pkt:
            return
        try:
            icmp_type = int(pkt[ICMP].type)
        except Exception:
            return
        if icmp_type not in (0, 8):
            return
        payload = b''
        if Raw in pkt:
            try:
                payload = bytes(pkt[Raw].load)
            except Exception:
                payload = b''
        payload_len = len(payload)
        if payload_len < self.threshold_size:
            return
        rec = self.by_pair[(pkt[IP].src, pkt[IP].dst)]
        rec['count'] += 1
        rec['total'] += payload_len
        if len(rec['sizes']) < 10_000:
            rec['sizes'].append(payload_len)
        if self._is_filler_pattern(payload):
            rec['filler'] += 1

    @staticmethod
    def _is_filler_pattern(payload):
        """True for the fixed filler that ping tools put in echo data:
        Windows repeats 'abcdefghijklmnopqrstuvwabcdefghi', Linux/BSD send
        an incrementing byte run after the timestamp, others zero-fill.
        Large pings with filler are MTU/path tests or monitoring probes; a
        tunnel carries changing data (commands, encrypted/compressed bytes).
        """
        body = payload[16:] if len(payload) > 32 else payload
        if not body:
            return True
        if len(set(body)) <= 2:
            return True
        steps = sum(1 for i in range(1, len(body))
                    if (body[i] - body[i - 1]) & 0xFF == 1)
        if steps >= 0.9 * (len(body) - 1):
            return True
        for period in range(1, 33):
            if len(body) > period * 2 and body[period:] == body[:-period]:
                return True
        return False

    def finalize(self):
        alerts = []
        for (src, dst), s in self.by_pair.items():
            if s['count'] < self.threshold_count:
                continue
            avg = s['total'] / s['count']
            max_size = max(s['sizes'])
            filler_ratio = s['filler'] / s['count']
            if filler_ratio >= 0.9:
                severity = 'low'
            else:
                severity = 'critical' if avg >= 512 else 'high'
            description = (
                f'{s["count"]} pacotes ICMP echo grandes de {src} para {dst} '
                f'(payload médio {avg:.0f}B, máx {max_size}B)'
            )
            if filler_ratio >= 0.9:
                description += (
                    '. O conteúdo é o preenchimento padrão de ferramentas de '
                    'ping (sequência repetida/incremental) — típico de teste de '
                    'MTU ou monitoramento, não de dados tunelados.'
                )
            alerts.append({
                'severity': severity,
                'category': 'exfil',
                'title': 'Possible ICMP Tunneling',
                'description': description,
                'ip': src,
                'details': {
                    'src': src, 'dst': dst,
                    'large_packet_count': s['count'],
                    'avg_payload_bytes': round(avg, 0),
                    'max_payload_bytes': max_size,
                    'total_payload_bytes': s['total'],
                    'filler_pattern_ratio': round(filler_ratio, 3),
                },
                'recommendation': (
                    'O ICMP echo padrão carrega payload mínimo. Payloads '
                    'grandes ou numerosos indicam tunelamento oculto (ptunnel, '
                    'icmpsh, Loki). Bloqueie a saída de ICMP ou restrinja a '
                    'fontes de monitoramento conhecidas.'
                ),
            })
        return alerts


class VolumeExfiltrationStreamingDetector(StreamingDetector):
    """Streaming de _detect_volume_exfiltration. Acumula bytes out/in por
    par (local, externo) e emite alerta no finalize quando out/in passa do
    threshold."""
    name = 'volume_exfil'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold_bytes = self.thresholds.get(
            'exfil_min_bytes_out', 10 * 1024 * 1024)
        self.ratio_threshold = self.thresholds.get('exfil_min_ratio', 5.0)
        self.flow = defaultdict(lambda: {
            'out': 0, 'in': 0, 'first_ts': None, 'last_ts': None,
        })

    def update(self, pkt):
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        size = len(pkt)
        ts = pkt.time
        src_local = self.analyzer._is_local_ip(src)
        dst_local = self.analyzer._is_local_ip(dst)
        if src_local == dst_local:
            return
        if src_local:
            key = (src, dst)
            self.flow[key]['out'] += size
        else:
            key = (dst, src)
            self.flow[key]['in'] += size
        rec = self.flow[key]
        if rec['first_ts'] is None or ts < rec['first_ts']:
            rec['first_ts'] = ts
        if rec['last_ts'] is None or ts > rec['last_ts']:
            rec['last_ts'] = ts

    def finalize(self):
        alerts = []
        for (src, dst), s in self.flow.items():
            if s['out'] < self.threshold_bytes:
                continue
            in_b = max(s['in'], 1)
            ratio = s['out'] / in_b
            if ratio < self.ratio_threshold:
                continue
            duration = (s['last_ts'] or 0) - (s['first_ts'] or 0)
            severity = 'high' if s['out'] >= self.threshold_bytes * 5 else 'medium'
            details = {
                'src': src, 'dst': dst,
                'src_ip': src, 'dst_ip': dst,
                'bytes_out': s['out'],
                'bytes_in': s['in'],
                'ratio': round(ratio, 2),
                'duration_seconds': round(duration, 2),
                'first_ts': s['first_ts'],
                'last_ts': s['last_ts'],
            }
            description = (
                f'O host {src} enviou {s["out"] / 1024 / 1024:.1f} MB para '
                f'{dst} (razão saída/entrada {ratio:.1f}x)'
            )
            recommendation = (
                'Uma razão alta de upload em relação ao download é consistente '
                'com exfiltração de dados. Investigue o IP de destino, a '
                'aplicação dona da conexão e o tipo de dado transferido.'
            )
            severity, description, recommendation = _apply_sanctioned_downgrade(
                self.analyzer, dst, severity, details,
                description, recommendation,
            )
            alerts.append({
                'severity': severity,
                'category': 'exfil',
                'title': 'Possible Data Exfiltration (Upload Volume)',
                'description': description,
                'ip': src,
                'details': details,
                'recommendation': recommendation,
            })
        return alerts


class SustainedExfilRatioStreamingDetector(StreamingDetector):
    """Detect *slow* exfil: small bytes/sec but sustained inverted ratio.

    VolumeExfiltrationStreamingDetector exige >=10MB out. Implants modernos
    (cobaltstrike-data-channel, Empire trickle, drip RAT) saem com poucos
    KB/s mas mantém razão out>>in por horas. Esse detector captura o
    segundo padrão: razão >=5 e duração >=5 min, ainda que volume bruto
    fique aquém do limiar do detector clássico.

    Reusa a estrutura de flow (par local/externo) mas com limiares mais
    permissivos para volume e mais restritivos para duração.
    """
    name = 'sustained_exfil'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.min_bytes_out = self.thresholds.get(
            'sustained_exfil_min_bytes', 1 * 1024 * 1024,
        )
        self.min_ratio = self.thresholds.get(
            'sustained_exfil_min_ratio', 5.0,
        )
        self.min_duration = self.thresholds.get(
            'sustained_exfil_min_duration', 300.0,
        )
        # Limiar do detector "irmão" — não duplicamos alertas que ele já
        # emite. Lemos o valor diretamente para ficar coerente caso a
        # configuração mude.
        self.classic_threshold = self.thresholds.get(
            'exfil_min_bytes_out', 10 * 1024 * 1024,
        )
        self.flow = defaultdict(lambda: {
            'out': 0, 'in': 0, 'first_ts': None, 'last_ts': None,
        })

    def update(self, pkt):
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        size = len(pkt)
        ts = pkt.time
        src_local = self.analyzer._is_local_ip(src)
        dst_local = self.analyzer._is_local_ip(dst)
        if src_local == dst_local:
            return
        if src_local:
            key = (src, dst)
            self.flow[key]['out'] += size
        else:
            key = (dst, src)
            self.flow[key]['in'] += size
        rec = self.flow[key]
        if rec['first_ts'] is None or ts < rec['first_ts']:
            rec['first_ts'] = ts
        if rec['last_ts'] is None or ts > rec['last_ts']:
            rec['last_ts'] = ts

    def finalize(self):
        alerts = []
        for (src, dst), s in self.flow.items():
            out_b = s['out']
            # Skip se já caísse no detector clássico — evita duplicação.
            if out_b >= self.classic_threshold:
                continue
            if out_b < self.min_bytes_out:
                continue
            in_b = max(s['in'], 1)
            ratio = out_b / in_b
            if ratio < self.min_ratio:
                continue
            duration = (s['last_ts'] or 0) - (s['first_ts'] or 0)
            if duration < self.min_duration:
                continue
            # bytes/s baixo + duração alta = mais suspeito. Severidade alta
            # quando bytes/s < 5 KB/s (trickle) e duration >= 30min.
            bps = out_b / max(duration, 1.0)
            if duration >= 1800 and bps < 5 * 1024:
                severity = 'high'
            else:
                severity = 'medium'
            details = {
                'src': src, 'dst': dst,
                'src_ip': src, 'dst_ip': dst,
                'bytes_out': out_b,
                'bytes_in': s['in'],
                'ratio': round(ratio, 2),
                'duration_seconds': round(duration, 1),
                'bytes_per_second': round(bps, 1),
                'first_ts': s['first_ts'],
                'last_ts': s['last_ts'],
            }
            description = (
                f'O host {src} enviou {out_b / 1024:.0f} KB para {dst} '
                f'de forma sustentada por {duration / 60:.1f} min com razão '
                f'saída/entrada {ratio:.1f}x (~{bps / 1024:.1f} KB/s). O volume '
                f'fica abaixo do alerta de exfil tradicional, mas '
                f'o padrão lento+constante é típico de implant.'
            )
            recommendation = (
                'Confirme a aplicação local responsável pelo flow e '
                'verifique se a destinação é legítima (cloud-sync, '
                'telemetria) ou C2. Em RDR/EDR procure por processos '
                'com conexões persistentes a esse IP.'
            )
            severity, description, recommendation = _apply_sanctioned_downgrade(
                self.analyzer, dst, severity, details,
                description, recommendation,
            )
            alerts.append({
                'severity': severity,
                'category': 'exfil',
                'title': 'Sustained Exfiltration Ratio (Slow Drip)',
                'description': description,
                'ip': src,
                'details': details,
                'recommendation': recommendation,
            })
        return alerts


class InternalLateralStreamingDetector(StreamingDetector):
    """Streaming de _detect_internal_lateral."""
    name = 'internal_lateral'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold = self.thresholds.get('lateral_min_targets', 5)
        # A target reached on the same port by >= this many OTHER internal
        # clients is treated as a shared server (DC, file/print server).
        self.shared_server_min_clients = self.thresholds.get(
            'lateral_shared_server_min_clients', 3)
        self.lateral_ports = analyzer.LATERAL_PORTS
        self.by_src_port = defaultdict(set)

    def update(self, pkt):
        if TCP not in pkt or IP not in pkt:
            return
        flags = int(pkt[TCP].flags)
        # Só SYN puro: SYN-ACK é resposta do servidor, não conexão dele.
        if not (flags & 0x02) or (flags & 0x10):
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        if src == dst:
            return
        if not (self.analyzer._is_local_ip(src) and self.analyzer._is_local_ip(dst)):
            return
        port = pkt[TCP].dport
        if port in self.lateral_ports:
            self.by_src_port[(src, port)].add(dst)

    def finalize(self):
        alerts = []
        # Shared servers: a (host, port) that several DIFFERENT internal
        # clients connect to is infrastructure — DCs on 88/135/445, file and
        # print servers on 445, jump hosts on 3389/22. A workstation mapping
        # drives on 3 DCs + 2 file servers is not lateral movement; lateral
        # movement fans out to peers nobody else talks to on that port.
        popularity = defaultdict(set)
        for (src, port), targets in self.by_src_port.items():
            for dst in targets:
                popularity[(dst, port)].add(src)
        for (src, port), targets in self.by_src_port.items():
            if len(targets) < self.threshold:
                continue
            shared = {d for d in targets
                      if len(popularity[(d, port)] - {src})
                      >= self.shared_server_min_clients}
            peers = targets - shared
            if len(peers) < self.threshold:
                continue
            proto = self.lateral_ports[port]
            severity = 'critical' if len(peers) >= self.threshold * 2 else 'high'
            alerts.append({
                'severity': severity,
                'category': 'lateral',
                'title': f'Internal Lateral Movement Suspected ({proto})',
                'description': (
                    f'O host interno {src} iniciou conexões {proto} para '
                    f'{len(peers)} alvo(s) interno(s) distinto(s) que não são '
                    f'servidores compartilhados'
                    + (f' (além de {len(shared)} servidor(es) usados por '
                       'outros clientes, desconsiderados)' if shared else '')
                ),
                'ip': src,
                'details': {
                    'src': src,
                    'protocol': proto,
                    'port': port,
                    'target_count': len(peers),
                    'targets_sample': sorted(peers)[:10],
                    'shared_servers_excluded': sorted(shared)[:10],
                },
                'recommendation': (
                    f'Um leque amplo de {proto} a partir de um único host '
                    'sugere credential spraying, movimento lateral por '
                    'PSExec/WinRM ou pivoteamento pós-exploração. Verifique a '
                    'integridade do host e revise os logs de autenticação nos '
                    'alvos.'
                ),
            })
        return alerts


class BeaconingStreamingDetector(StreamingDetector):
    """Streaming de _detect_beaconing. Multi-sinal:

    * **Jitter linear** + **autocorrelação binada** sobre timestamps de SYN
      por (src,dst,port) em conexões locais→externas (sinais base).
    * **NTP-anchored sleep** (B.1): se o intervalo médio cai em um valor
      "limpo" (60/300/3600s…) e a fase relativa ao grid wallclock é estável,
      é sinal forte de C2 com timer alinhado a clock (Sleep+jitter em CS).
    * **Periodicidade de tamanho** (B.1): se os primeiros payloads de cada
      conexão têm tamanho uniforme (CV baixo), a hipótese de "implant
      enviando o mesmo metadata a cada beacon" sobe.

    Os sinais B.1 não geram alertas próprios — eles *enriquecem* o alerta
    base (jitter ou AC) já emitido, bumpam severidade e elevam confidence.
    """
    name = 'beaconing'

    # Intervalos "limpos" típicos de Sleep em frameworks de C2. Tolerância
    # de 1% para absorver drift de clock e propagação de pacote.
    NTP_CLEAN_INTERVALS = (
        30, 45, 60, 90, 120, 180, 240, 300, 600, 900, 1200, 1800, 2400, 3600,
    )
    # Periodicity measured on few connections is weak evidence (see
    # _calibrate): below MIN_SAMPLES_HIGH the alert is capped at medium,
    # below MIN_SAMPLES_CRITICAL at high.
    MIN_SAMPLES_HIGH = 10
    MIN_SAMPLES_CRITICAL = 20

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold_connections = self.thresholds.get(
            'beaconing_min_connections', 5)
        self.max_jitter_percent = self.thresholds.get(
            'beaconing_max_jitter_percent', 10)
        self.ac_min_samples = self.thresholds.get(
            'beaconing_ac_min_samples', 16)
        self.ac_min_score = self.thresholds.get('beaconing_ac_min_score', 0.5)
        self.connections = defaultdict(list)
        # First non-zero Raw payload size per full 4-tuple flow. Used at
        # finalize to compute size-uniformity of beacon requests.
        self.first_sizes = {}

    def update(self, pkt):
        if TCP not in pkt or IP not in pkt:
            return
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if not (self.analyzer._is_local_ip(src_ip)
                and not self.analyzer._is_local_ip(dst_ip)):
            return
        flags = int(pkt[TCP].flags)
        # SYN puro = conexão iniciada pelo host local. SYN-ACK (resposta a
        # um scan externo) não conta como conexão de saída dele.
        if (flags & 0x02) and not (flags & 0x10):
            self.connections[(src_ip, dst_ip, pkt[TCP].dport)].append(pkt.time)
            return
        # Não-SYN: candidato a primeira request-payload do beacon.
        if Raw not in pkt:
            return
        try:
            size = len(pkt[Raw].load)
        except Exception:
            return
        if size <= 0:
            return
        key = (src_ip, int(pkt[TCP].sport), dst_ip, int(pkt[TCP].dport))
        if key not in self.first_sizes:
            self.first_sizes[key] = size

    @classmethod
    def _check_ntp_anchor(cls, timestamps, mean_interval):
        """Return (clean_interval, phase_locked) when timestamps look
        wallclock-aligned. clean_interval is None when mean_interval doesn't
        match a known clean cadence."""
        clean_interval = None
        for ci in cls.NTP_CLEAN_INTERVALS:
            if abs(mean_interval - ci) / ci <= 0.01:
                clean_interval = ci
                break
        if clean_interval is None:
            return None, False
        phases = [float(t) % clean_interval for t in timestamps]
        # Phase wraps around the interval boundary — measure tightness in
        # both the raw and half-shifted views and pick whichever is smaller.
        raw_range = max(phases) - min(phases)
        shifted = sorted((p + clean_interval / 2) % clean_interval
                         for p in phases)
        shifted_range = shifted[-1] - shifted[0]
        phase_locked = min(raw_range, shifted_range) < clean_interval * 0.05
        return clean_interval, phase_locked

    def _size_uniformity(self, src_ip, dst_ip, dst_port):
        """Coefficient of variation of first-payload sizes across
        connections (src→dst:dport). Returns (cv, n) where cv is None when
        we don't have enough samples (need >= 5)."""
        sizes = [
            sz for (s, _sp, d, dp), sz in self.first_sizes.items()
            if s == src_ip and d == dst_ip and dp == dst_port
        ]
        if len(sizes) < 5:
            return None, len(sizes)
        mean = sum(sizes) / len(sizes)
        if mean <= 0:
            return None, len(sizes)
        var = sum((s - mean) ** 2 for s in sizes) / len(sizes)
        cv = (var ** 0.5) / mean
        return cv, len(sizes)

    def finalize(self):
        SEVERITY_ORDER = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        alerts_by_key = {}

        def _record(key, candidate):
            existing = alerts_by_key.get(key)
            if existing is None or (
                SEVERITY_ORDER[candidate['severity']]
                > SEVERITY_ORDER[existing['severity']]
            ):
                alerts_by_key[key] = candidate

        for (src_ip, dst_ip, dst_port), timestamps in self.connections.items():
            timestamps = sorted(timestamps)
            if len(timestamps) < self.threshold_connections:
                continue
            intervals = [timestamps[i] - timestamps[i - 1]
                         for i in range(1, len(timestamps))]
            if not intervals:
                continue
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval <= 0:
                continue

            # B.1 multi-signal enrichment (shared by both branches).
            clean_interval, phase_locked = self._check_ntp_anchor(
                timestamps, mean_interval,
            )
            size_cv, size_n = self._size_uniformity(src_ip, dst_ip, dst_port)
            size_uniform = (size_cv is not None and size_cv < 0.20)
            multi_signal = {
                'clean_interval': clean_interval,
                'wallclock_phase_locked': bool(phase_locked),
                'size_uniformity_cv': (round(size_cv, 3)
                                       if size_cv is not None else None),
                'size_samples': size_n,
                'size_uniform': bool(size_uniform),
            }

            # (a) Linear jitter
            max_deviation = max(abs(iv - mean_interval) for iv in intervals)
            jitter_percent = (max_deviation / mean_interval) * 100
            if jitter_percent < self.max_jitter_percent:
                severity = 'critical' if jitter_percent < 5 else 'high'
                # NTP-anchored sleep + uniform request size → upgrade to
                # critical. Either signal alone is suggestive; together they
                # describe a hard-coded sleep timer with stable payload.
                if phase_locked and size_uniform:
                    severity = 'critical'
                # Confidence: starts at 100 - jitter*5, bumps for each
                # extra signal. Floor 40, cap 99.
                base_conf = max(40, min(99, int(100 - jitter_percent * 5)))
                bumps = (10 if phase_locked else 0) + (10 if size_uniform else 0)
                confidence = min(99, base_conf + bumps)
                desc = (
                    f'O host {src_ip} apresenta conexões periódicas para '
                    f'{dst_ip}:{dst_port} ({len(timestamps)} conexões, '
                    f'{jitter_percent:.1f}% de jitter, '
                    f'intervalo ~{mean_interval:.1f}s)'
                )
                if phase_locked:
                    desc += (
                        f'. Alinhado ao wallclock na grade de {clean_interval}s '
                        '(timer de sleep ancorado em NTP)'
                    )
                if size_uniform:
                    desc += f'. Tamanho de request uniforme (CV={size_cv:.2f}, n={size_n})'
                _record((src_ip, dst_ip, dst_port), {
                    'severity': severity,
                    'confidence': confidence,
                    'category': 'beaconing',
                    'title': 'Beaconing Behavior Detected (Possible C2)',
                    'description': desc,
                    'ip': src_ip,
                    'details': {
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'destination_port': dst_port,
                        'connection_count': len(timestamps),
                        'mean_interval_seconds': round(mean_interval, 2),
                        'jitter_percent': round(jitter_percent, 2),
                        'duration': round(timestamps[-1] - timestamps[0], 2),
                        'method': 'jitter',
                        'first_ts': float(timestamps[0]),
                        'last_ts': float(timestamps[-1]),
                        **multi_signal,
                    },
                    'recommendation': (
                        'Este padrão é consistente com beaconing de C2 '
                        '(Command and Control). Investigue o IP de destino '
                        f'{dst_ip} e a porta {dst_port}. Verifique se há '
                        'malware no host de origem. Bloqueie o destino se '
                        'confirmado como malicioso.'
                    ),
                })

            # (b) Autocorrelation peak
            if len(timestamps) < self.ac_min_samples:
                continue
            best_lag, peak_score, _bins = (
                self.analyzer._binned_autocorrelation_peak(
                    timestamps, mean_interval,
                )
            )
            if best_lag is None or peak_score < self.ac_min_score:
                continue
            existing = alerts_by_key.get((src_ip, dst_ip, dst_port))
            ac_severity = 'critical' if peak_score >= 0.75 else 'high'
            if phase_locked and size_uniform:
                ac_severity = 'critical'
            if existing and (
                SEVERITY_ORDER[ac_severity]
                <= SEVERITY_ORDER[existing['severity']]
            ):
                continue
            ac_confidence = max(40, min(99, int(peak_score * 100)))
            ac_confidence = min(
                99,
                ac_confidence
                + (10 if phase_locked else 0)
                + (10 if size_uniform else 0),
            )
            ac_desc = (
                f'O host {src_ip} apresenta conexões periódicas para '
                f'{dst_ip}:{dst_port} ({len(timestamps)} conexões, '
                f'pico de autocorrelação {peak_score:.2f} no lag '
                f'{best_lag}, intervalo médio ~{mean_interval:.1f}s). '
                'O padrão sobrevive a um jitter moderado por beacon que '
                'testes de jitter linear não detectariam.'
            )
            if phase_locked:
                ac_desc += (
                    f' Alinhado ao wallclock na grade de {clean_interval}s '
                    '(timer de sleep ancorado em NTP).'
                )
            if size_uniform:
                ac_desc += f' Tamanho de request uniforme (CV={size_cv:.2f}, n={size_n}).'
            _record((src_ip, dst_ip, dst_port), {
                'severity': ac_severity,
                'confidence': ac_confidence,
                'category': 'beaconing',
                'title': 'Beaconing Behavior Detected (Periodic Signal)',
                'description': ac_desc,
                'ip': src_ip,
                'details': {
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'destination_port': dst_port,
                    'connection_count': len(timestamps),
                    'mean_interval_seconds': round(mean_interval, 2),
                    'autocorrelation_peak': round(peak_score, 3),
                    'autocorrelation_lag': best_lag,
                    'jitter_percent': round(jitter_percent, 2),
                    'duration': round(timestamps[-1] - timestamps[0], 2),
                    'method': 'autocorrelation',
                    'first_ts': float(timestamps[0]),
                    'last_ts': float(timestamps[-1]),
                    **multi_signal,
                },
                'recommendation': (
                    'Sinal periódico detectado apesar do jitter. Isso é '
                    'consistente com frameworks de C2 (Cobalt Strike, Sliver, '
                    'Mythic) que injetam atraso aleatório entre beacons. '
                    f'Inspecione o destino {dst_ip}:{dst_port} e o '
                    f'host de origem {src_ip} em busca de implantes.'
                ),
            })

        return [self._calibrate(a) for a in alerts_by_key.values()]

    def _calibrate(self, alert):
        """Evidence-proportional severity.

        Five connections with low jitter used to be *critical*: any app that
        polls an API a handful of times (mail check, weather widget, update
        probe) looks exactly like that. Few samples cap the severity; the
        extra signals (wall-clock phase lock + uniform request size) still
        unlock critical because together they describe a hard-coded timer.
        Destinations that resolve to big platforms go one notch down.
        """
        d = alert['details']
        n = d.get('connection_count') or 0
        strong = d.get('wallclock_phase_locked') and d.get('size_uniform')
        sev = alert['severity']
        if n < self.MIN_SAMPLES_HIGH and not strong:
            sev = _cap_severity(sev, 'medium')
        elif n < self.MIN_SAMPLES_CRITICAL and not strong:
            sev = _cap_severity(sev, 'high')
        if sev != alert['severity']:
            d['severity_capped_by_samples'] = alert['severity']
        alert['severity'] = _apply_known_service_downgrade(
            self.analyzer, d.get('destination_ip'), sev, d)
        return alert


class ConnectionBeaconingStreamingDetector(StreamingDetector):
    """Detect C2 beaconing INSIDE a persistent connection.

    BeaconingStreamingDetector conta SYNs — um timestamp por conexão nova.
    C2 moderno (HTTP2 multiplexado, WebSocket, TLS keep-alive, Sliver/Mythic
    com long-poll) abre UMA conexão e faz check-ins periódicos dentro dela:
    um único SYN, muitos beacons — invisível ao detector clássico.

    Aqui o sinal é a periodicidade de *bursts* de payload cliente→servidor
    dentro de um mesmo fluxo (src, sport, dst, dport) local→externo. O
    agrupamento em bursts é feito online durante o streaming: um pacote de
    dados que chega mais de ``burst_gap`` segundos após o anterior inicia um
    burst novo, e só o timestamp de início (+ tamanho do primeiro payload)
    de cada burst é retido — custo de memória por fluxo é O(bursts), não
    O(pacotes). No finalize, os inícios de burst passam pela MESMA bateria
    do detector clássico: jitter linear, autocorrelação binada, âncora de
    wallclock (NTP-sleep) e uniformidade de tamanho.

    FP conhecido: canais de push/long-poll legítimos (WhatsApp Web, push
    de notificação, MQTT keep-alive) também são periódicos. Por isso a
    severidade base é mais conservadora que a do detector de SYN — critical
    exige os dois sinais extras (phase-lock + tamanho uniforme) — e
    keep-alives TCP puros (payload de 0-1 byte) são filtrados pelo
    ``min_payload``.
    """
    name = 'connection_beaconing'

    # Bound state on pathological captures: after this many distinct flows,
    # only already-tracked flows keep updating.
    MAX_FLOWS = 100_000
    # A flow that accumulates this many bursts is a chatty long-poll app,
    # not something we need more evidence on.
    MAX_BURSTS_PER_FLOW = 10_000

    def __init__(self, analyzer):
        super().__init__(analyzer)
        t = self.thresholds
        self.min_bursts = t.get('conn_beacon_min_bursts', 8)
        self.burst_gap = float(t.get('conn_beacon_burst_gap', 5.0))
        self.min_payload = int(t.get('conn_beacon_min_payload', 8))
        self.min_duration = float(t.get('conn_beacon_min_duration', 120.0))
        # Periodicity thresholds shared with the SYN-based detector so the
        # two stay consistent when the operator tunes them.
        self.max_jitter_percent = t.get('beaconing_max_jitter_percent', 10)
        self.ac_min_samples = t.get('beaconing_ac_min_samples', 16)
        self.ac_min_score = t.get('beaconing_ac_min_score', 0.5)
        # (src, sport, dst, dport) -> burst state
        self.flows = {}

    def update(self, pkt):
        if TCP not in pkt or IP not in pkt or Raw not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        if not (self.analyzer._is_local_ip(src)
                and not self.analyzer._is_local_ip(dst)):
            return
        try:
            size = len(pkt[Raw].load)
        except Exception:
            return
        # TCP keepalive probes carry 0-1 garbage bytes — not check-ins.
        if size < self.min_payload:
            return
        key = (src, int(pkt[TCP].sport), dst, int(pkt[TCP].dport))
        rec = self.flows.get(key)
        ts = float(pkt.time)
        if rec is None:
            if len(self.flows) >= self.MAX_FLOWS:
                return
            rec = {
                'burst_ts': [ts],
                'burst_sizes': [size],
                'last_ts': ts,
                'packets': 1,
                'bytes': size,
            }
            self.flows[key] = rec
            return
        rec['packets'] += 1
        rec['bytes'] += size
        if ts - rec['last_ts'] > self.burst_gap:
            if len(rec['burst_ts']) < self.MAX_BURSTS_PER_FLOW:
                rec['burst_ts'].append(ts)
                rec['burst_sizes'].append(size)
        if ts > rec['last_ts']:
            rec['last_ts'] = ts

    def _size_stats(self, sizes):
        """(cv, n) over burst first-payload sizes; cv None below 5 samples."""
        if len(sizes) < 5:
            return None, len(sizes)
        mean = sum(sizes) / len(sizes)
        if mean <= 0:
            return None, len(sizes)
        var = sum((s - mean) ** 2 for s in sizes) / len(sizes)
        return (var ** 0.5) / mean, len(sizes)

    def finalize(self):
        alerts = []
        for (src, sport, dst, dport), rec in self.flows.items():
            timestamps = rec['burst_ts']
            n = len(timestamps)
            if n < self.min_bursts:
                continue
            duration = timestamps[-1] - timestamps[0]
            if duration < self.min_duration:
                continue
            intervals = [timestamps[i] - timestamps[i - 1]
                         for i in range(1, n)]
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval <= 0:
                continue

            max_dev = max(abs(iv - mean_interval) for iv in intervals)
            jitter_percent = (max_dev / mean_interval) * 100

            method = None
            ac_peak = None
            ac_lag = None
            if jitter_percent < self.max_jitter_percent:
                method = 'jitter'
            elif n >= self.ac_min_samples:
                ac_lag, ac_peak, _bins = (
                    self.analyzer._binned_autocorrelation_peak(
                        timestamps, mean_interval,
                    )
                )
                if ac_lag is not None and ac_peak >= self.ac_min_score:
                    method = 'autocorrelation'
            if method is None:
                continue

            clean_interval, phase_locked = (
                BeaconingStreamingDetector._check_ntp_anchor(
                    timestamps, mean_interval,
                )
            )
            size_cv, size_n = self._size_stats(rec['burst_sizes'])
            size_uniform = (size_cv is not None and size_cv < 0.20)

            # Mais conservador que o detector de SYN: long-poll legítimo
            # também é periódico, então critical exige AMBOS os sinais
            # extras; periodicidade forte sozinha fica em high.
            if phase_locked and size_uniform:
                severity = 'critical'
            elif jitter_percent < 5 or (ac_peak or 0) >= 0.75:
                severity = 'high'
            else:
                severity = 'medium'
            known_service_details = {}
            severity = _apply_known_service_downgrade(
                self.analyzer, dst, severity, known_service_details)
            if method == 'jitter':
                base_conf = max(35, min(95, int(95 - jitter_percent * 5)))
            else:
                base_conf = max(35, min(95, int((ac_peak or 0) * 95)))
            confidence = min(99, base_conf
                             + (10 if phase_locked else 0)
                             + (10 if size_uniform else 0))

            desc = (
                f'O host {src} mantém UMA conexão TCP com {dst}:{dport} '
                f'(porta de origem {sport}) e envia dados em {n} bursts '
                f'periódicos (intervalo ~{mean_interval:.1f}s'
            )
            if method == 'jitter':
                desc += f', {jitter_percent:.1f}% de jitter'
            else:
                desc += f', pico de autocorrelação {ac_peak:.2f} no lag {ac_lag}'
            desc += (
                f') ao longo de {duration / 60:.1f} min. Beacons dentro de uma '
                'conexão persistente (C2 via HTTP2/WebSocket/keep-alive) nunca '
                'aparecem no beaconing baseado em SYN.'
            )
            if phase_locked:
                desc += (
                    f' Alinhado ao wallclock na grade de {clean_interval}s '
                    '(timer de sleep ancorado em NTP).'
                )
            if size_uniform:
                desc += (
                    f' Tamanho de check-in uniforme (CV={size_cv:.2f}, n={size_n}).'
                )

            alerts.append({
                'severity': severity,
                'confidence': confidence,
                'category': 'beaconing',
                'title': 'In-Connection Beaconing (Persistent C2 Channel)',
                'description': desc,
                'ip': src,
                'details': {
                    'src_ip': src,
                    'dst_ip': dst,
                    'src_port': sport,
                    'port': dport,
                    'burst_count': n,
                    'packet_count': rec['packets'],
                    'bytes_c2s': rec['bytes'],
                    'mean_interval_seconds': round(mean_interval, 2),
                    'jitter_percent': round(jitter_percent, 2),
                    'autocorrelation_peak': (round(ac_peak, 3)
                                             if ac_peak is not None else None),
                    'autocorrelation_lag': ac_lag,
                    'duration_seconds': round(duration, 2),
                    'burst_gap_seconds': self.burst_gap,
                    'method': method,
                    'clean_interval': clean_interval,
                    'wallclock_phase_locked': bool(phase_locked),
                    'size_uniformity_cv': (round(size_cv, 3)
                                           if size_cv is not None else None),
                    'size_samples': size_n,
                    'size_uniform': bool(size_uniform),
                    'first_ts': float(timestamps[0]),
                    'last_ts': float(timestamps[-1]),
                    'connection_status': 'established',
                    'connection_established': True,
                    'bytes_exchanged': rec['bytes'],
                    **known_service_details,
                },
                'recommendation': (
                    'Check-ins periódicos dentro de uma única conexão de longa '
                    'duração são como o C2 via HTTP2/WebSocket (Sliver, Mythic, '
                    'implantes customizados) escapa da detecção de beacon por '
                    f'conexão. Identifique o processo em {src} que mantém a '
                    f'conexão com {dst}:{dport}. Sósias legítimos: canais de '
                    'push/notificação e keep-alives MQTT — confirme a reputação '
                    'do destino e a aplicação dona antes de bloquear.'
                ),
            })
        return alerts


class KerberosAbuseStreamingDetector(StreamingDetector):
    """Detect Kerberos credential-access patterns on port 88.

    Sinais (todos por inspeção light no payload Kerberos BER/ASN.1):

      * **Kerberoasting** (T1558.003) — TGS-REQ pedindo etype RC4-HMAC (23).
        Em AD moderno o default é AES (17/18); pedir RC4 explicitamente
        sinaliza extração de TGS para crack offline.
      * **AS-REP Roasting** (T1558.004) — sequência repetida de AS-REQ →
        AS-REP do mesmo (src,dst) sem KRB-ERROR(KDC_ERR_PREAUTH_REQUIRED)
        intermediário E sem PA-ENC-TIMESTAMP nos AS-REQ (logon normal com
        pre-auth em cache carrega o timestamp já no primeiro AS-REQ).
        Indica enumeração de contas com bit DONT_REQUIRE_PREAUTH ativado.
      * **RC4 downgrade** (T1562.010) — AS-REQ cujo etype list inclui só
        RC4 (sem AES) em ambiente moderno.

    O parser é deliberadamente raso: identificamos o tag Kerberos (0x6A
    AS-REQ, 0x6B AS-REP, 0x6C TGS-REQ, 0x6D TGS-REP, 0x7E KRB-ERROR) no
    primeiro byte da mensagem (depois de pular o length-prefix em TCP) e
    procuramos por `02 01 17` (INTEGER 23 = RC4-HMAC) no payload bruto.
    Falsos positivos são possíveis em payloads grandes; mitigamos
    inspecionando só os primeiros 2048 bytes da mensagem.
    """
    name = 'kerberos_abuse'

    KRB_TAG_AS_REQ = 0x6A
    KRB_TAG_AS_REP = 0x6B
    KRB_TAG_TGS_REQ = 0x6C
    KRB_TAG_TGS_REP = 0x6D
    KRB_TAG_ERROR = 0x7E
    KRB_PORT = 88

    RC4_SIG = b'\x02\x01\x17'      # INTEGER 23 → eTYPE-RC4-HMAC
    AES128_SIG = b'\x02\x01\x11'   # INTEGER 17 → eTYPE-AES128
    AES256_SIG = b'\x02\x01\x12'   # INTEGER 18 → eTYPE-AES256
    # KDC_ERR_PREAUTH_REQUIRED = 25. Within KRB-ERROR, error-code is an
    # INTEGER element. Search the byte pattern `02 01 19` to detect the
    # PREAUTH-REQUIRED reply.
    PREAUTH_REQUIRED_SIG = b'\x02\x01\x19'
    # PA-DATA { padata-type [1] INTEGER (2 = PA-ENC-TIMESTAMP) }: an AS-REQ
    # carrying this is a NORMAL pre-authenticated logon. Roasting tools
    # (GetNPUsers, kerbrute) send AS-REQ without it — distinguishing the two
    # kills the mid-stream false positive where cached-preauth clients get
    # AS-REPs with zero PREAUTH_REQUIRED errors in the capture window.
    PA_ENC_TIMESTAMP_SIG = b'\xa1\x03\x02\x01\x02'

    MSG_LIMIT = 2048

    def __init__(self, analyzer):
        super().__init__(analyzer)
        # (src, dst) -> counts dict
        self.pair = defaultdict(lambda: {
            'as_req': 0,
            'as_rep': 0,
            'tgs_req': 0,
            'tgs_req_rc4': 0,
            'as_req_rc4_only': 0,
            'as_req_preauth': 0,
            'preauth_required': 0,
            'first_ts': 0.0,
            'last_ts': 0.0,
            'bytes': 0,
        })

    # ------------------------------------------------------------------
    def _inspect(self, payload, is_tcp, src, dst, ts):
        if not payload:
            return
        # TCP carries a 4-byte length prefix per RFC 4120 §7.2.2.
        if is_tcp:
            if len(payload) < 5:
                return
            payload = payload[4:]
        if not payload:
            return
        tag = payload[0]
        if tag not in (
            self.KRB_TAG_AS_REQ, self.KRB_TAG_AS_REP,
            self.KRB_TAG_TGS_REQ, self.KRB_TAG_TGS_REP,
            self.KRB_TAG_ERROR,
        ):
            return
        body = payload[:self.MSG_LIMIT]
        rec = self.pair[(src, dst)]
        if rec['first_ts'] == 0.0:
            rec['first_ts'] = ts
        rec['last_ts'] = ts
        has_rc4 = self.RC4_SIG in body
        has_aes = self.AES128_SIG in body or self.AES256_SIG in body
        if tag == self.KRB_TAG_AS_REQ:
            rec['as_req'] += 1
            if has_rc4 and not has_aes:
                rec['as_req_rc4_only'] += 1
            if self.PA_ENC_TIMESTAMP_SIG in body:
                rec['as_req_preauth'] += 1
        elif tag == self.KRB_TAG_AS_REP:
            rec['as_rep'] += 1
        elif tag == self.KRB_TAG_TGS_REQ:
            rec['tgs_req'] += 1
            if has_rc4 and not has_aes:
                rec['tgs_req_rc4'] += 1
        elif tag == self.KRB_TAG_ERROR:
            if self.PREAUTH_REQUIRED_SIG in body:
                rec['preauth_required'] += 1

    def update(self, pkt):
        if Raw not in pkt or IP not in pkt:
            return
        is_tcp = TCP in pkt
        is_udp = UDP in pkt
        if not (is_tcp or is_udp):
            return
        if is_tcp:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        else:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        if sport != self.KRB_PORT and dport != self.KRB_PORT:
            return
        # Normalize so 'src' is always the client side (the one talking to
        # the KDC on port 88).
        if dport == self.KRB_PORT:
            src, dst = pkt[IP].src, pkt[IP].dst
        else:
            src, dst = pkt[IP].dst, pkt[IP].src
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return
        try:
            self._inspect(payload, is_tcp, src, dst, pkt.time)
        except Exception:
            return
        # Acumula bytes do par pra surfacing em bytes_exchanged (Kerberos
        # mistura TCP/UDP, então não usamos TcpFlowTracker aqui).
        try:
            self.pair[(src, dst)]['bytes'] += len(payload)
        except Exception:
            pass

    # ------------------------------------------------------------------
    def finalize(self):
        alerts = []
        for (src, dst), rec in self.pair.items():
            # ---- Kerberoasting: any TGS-REQ explicitly carrying RC4-only.
            if rec['tgs_req_rc4'] >= 1:
                # >=3 reforça severidade; 1 ainda alerta como medium.
                severity = ('critical' if rec['tgs_req_rc4'] >= 3
                            else 'high')
                alerts.append({
                    'severity': severity,
                    'category': 'brute_force',
                    'title': 'Kerberoasting Suspected (RC4-HMAC TGS-REQ)',
                    'description': (
                        f'O cliente {src} solicitou {rec["tgs_req_rc4"]} '
                        f'ticket(s) de serviço Kerberos ao KDC {dst} usando '
                        f'RC4-HMAC (etype 23). O AD moderno usa AES; um TGS-REQ '
                        f'explicitamente em RC4 é a assinatura canônica de '
                        f'Kerberoasting para crack offline.'
                    ),
                    'ip': src,
                    'details': {
                        'source_ip': src,
                        'src_ip': src,
                        'dst_ip': dst,
                        'kdc_ip': dst,
                        'tgs_req_total': rec['tgs_req'],
                        'tgs_req_rc4_only': rec['tgs_req_rc4'],
                        'first_ts': rec['first_ts'],
                        'last_ts': rec['last_ts'],
                        'connection_status': 'established',
                        'connection_established': True,
                        'bytes_exchanged': rec['bytes'],
                    },
                    'recommendation': (
                        'Audite qual SPN foi solicitado (no servidor: Event '
                        'ID 4769 com ticket-encryption 0x17). Defina senhas '
                        'fortes, longas e aleatórias nas contas de serviço, ou '
                        'migre-as para gMSA. Desative o RC4 em todo o cluster '
                        'assim que todos os sistemas negociarem AES.'
                    ),
                    'mitre_attack': {
                        'technique_id': 'T1558.003',
                        'technique_name': 'Kerberoasting',
                        'tactic_id': 'TA0006',
                        'tactic_name': 'Credential Access',
                        'url': (
                            'https://attack.mitre.org/techniques/'
                            'T1558/003/'
                        ),
                    },
                })

            # ---- AS-REP Roasting: enumeração ativa de contas sem preauth.
            # Sinal: AS-REQs SEM PA-ENC-TIMESTAMP retornando AS-REP direto,
            # sem KRB-ERROR(PREAUTH_REQUIRED) no meio. Exigir que os AS-REQ
            # observados não carreguem pre-auth elimina o falso positivo de
            # captura mid-stream: clientes Windows com pre-auth em cache
            # mandam PA-ENC-TIMESTAMP já no primeiro AS-REQ, então um
            # terminal server com 5+ logons gerava 5 AS-REP com zero erros —
            # o antigo gatilho. Trade-off: captura só-de-respostas (tap
            # unidirecional, as_req=0) deixa de alertar.
            if (rec['as_rep'] >= 5 and rec['preauth_required'] == 0
                    and rec['as_req'] >= 1 and rec['as_req_preauth'] == 0):
                alerts.append({
                    'severity': 'high',
                    'category': 'brute_force',
                    'title': 'AS-REP Roasting Suspected (no PREAUTH-REQUIRED)',
                    'description': (
                        f'O cliente {src} recebeu {rec["as_rep"]} AS-REP '
                        f'Kerberos do KDC {dst} com zero erros '
                        f'PREAUTH-REQUIRED no meio. Ou os '
                        f'principais consultados têm DONT_REQUIRE_PREAUTH '
                        f'ativado (roastable), ou o cliente está enumerando '
                        f'contas para encontrar as roastable.'
                    ),
                    'ip': src,
                    'details': {
                        'source_ip': src,
                        'src_ip': src,
                        'dst_ip': dst,
                        'kdc_ip': dst,
                        'as_req': rec['as_req'],
                        'as_rep': rec['as_rep'],
                        'as_req_with_preauth': rec['as_req_preauth'],
                        'preauth_required_errors': rec['preauth_required'],
                        'first_ts': rec['first_ts'],
                        'last_ts': rec['last_ts'],
                        'connection_status': 'established',
                        'connection_established': True,
                        'bytes_exchanged': rec['bytes'],
                    },
                    'recommendation': (
                        'Liste as contas com DONT_REQUIRE_PREAUTH ativado '
                        '(Get-ADUser -Filter {DoesNotRequirePreAuth -eq '
                        '$true}) — elas podem ser extraídas por qualquer um '
                        'que alcance o KDC. Remova o flag onde possível e '
                        'force tipos de criptografia somente AES.'
                    ),
                    'mitre_attack': {
                        'technique_id': 'T1558.004',
                        'technique_name': 'AS-REP Roasting',
                        'tactic_id': 'TA0006',
                        'tactic_name': 'Credential Access',
                        'url': (
                            'https://attack.mitre.org/techniques/'
                            'T1558/004/'
                        ),
                    },
                })

            # ---- RC4 downgrade no AS-REQ.
            if rec['as_req_rc4_only'] >= 3:
                alerts.append({
                    'severity': 'high',
                    'category': 'brute_force',
                    'title': 'Kerberos RC4 Downgrade',
                    'description': (
                        f'O cliente {src} enviou {rec["as_req_rc4_only"]} '
                        f'AS-REQ para {dst} listando apenas RC4-HMAC como '
                        f'etype suportado. Esse padrão é usado para forçar a '
                        f'emissão de tickets RC4 para um Kerberoast posterior.'
                    ),
                    'ip': src,
                    'details': {
                        'source_ip': src,
                        'src_ip': src,
                        'dst_ip': dst,
                        'kdc_ip': dst,
                        'as_req_rc4_only': rec['as_req_rc4_only'],
                        'as_req_total': rec['as_req'],
                        'first_ts': rec['first_ts'],
                        'last_ts': rec['last_ts'],
                        'connection_status': 'established',
                        'connection_established': True,
                        'bytes_exchanged': rec['bytes'],
                    },
                    'recommendation': (
                        'Investigue este cliente — stacks Kerberos modernas de '
                        'Windows/Linux enviam etypes AES. Verifique se o '
                        'msDS-SupportedEncryptionTypes foi adulterado '
                        'na conta alvo.'
                    ),
                    'mitre_attack': {
                        'technique_id': 'T1562.010',
                        'technique_name': (
                            'Impair Defenses: Downgrade Attack'
                        ),
                        'tactic_id': 'TA0005',
                        'tactic_name': 'Defense Evasion',
                        'url': (
                            'https://attack.mitre.org/techniques/'
                            'T1562/010/'
                        ),
                    },
                })
        return alerts


class BruteForceStreamingDetector(StreamingDetector):
    """Streaming de _detect_brute_force. Acumula tentativas SYN (cliente)
    e RSTs (servidor) por (src,dst,port); janela deslizante no finalize.

    TARGET_PORTS expandido em 2026-05-19 para cobrir RDP/WinRM/SMB/bancos/mail
    além do SSH/FTP original. Mantemos um mapa secundário (RECOMMENDATIONS)
    para mensagens específicas por protocolo — fail2ban não aplica a tudo."""
    name = 'brute_force'

    TARGET_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        445: 'SMB',
        465: 'SMTPS',
        587: 'SMTP-Submission',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        5901: 'VNC',
        5985: 'WinRM-HTTP',
        5986: 'WinRM-HTTPS',
    }

    # Recomendações específicas por protocolo (fallback genérico embaixo).
    RECOMMENDATIONS = {
        'SSH': 'Bloqueie o IP, revise /var/log/auth.log no destino e instale '
               'fail2ban. Considere chaves SSH em vez de senha.',
        'FTP': 'Bloqueie o IP. FTP transmite credenciais em claro — migre o '
               'serviço para SFTP/FTPS.',
        'Telnet': 'Bloqueie o IP imediatamente. Telnet não deveria estar '
                  'exposto — desligue o serviço e migre para SSH.',
        'SMTP': 'Bloqueie o IP. Verifique se há AUTH PLAIN/LOGIN exposto em '
                'porta 25 (deveria ser apenas 587/465 com TLS).',
        'SMTPS': 'Bloqueie o IP. Padrão de spray contra autenticação SMTP — '
                 'cheque logs do servidor SMTP por contas usadas como pivot.',
        'SMTP-Submission': 'Bloqueie o IP. Brute force em 587 normalmente busca '
                           'contas para enviar spam — cheque o servidor.',
        'POP3': 'Bloqueie o IP. POP3 em 110 expõe credenciais em claro — '
                'force STARTTLS ou desligue.',
        'POP3S': 'Bloqueie o IP e revise logs do servidor de mail.',
        'IMAP': 'Bloqueie o IP. IMAP em 143 expõe credenciais — force '
                'STARTTLS ou desligue.',
        'IMAPS': 'Bloqueie o IP e revise logs do servidor de mail.',
        'SMB': 'CRÍTICO: brute force SMB normalmente precede ransomware. '
               'Bloqueie o IP, audite contas usadas (lockout policy) e '
               'considere desligar SMB exposto.',
        'MSSQL': 'Bloqueie o IP. Audite a conta sa e contas com BUILTIN'
                 '\\Administrators. Habilite Windows Authentication only.',
        'MySQL': 'Bloqueie o IP. MySQL exposto a internet é um anti-padrão — '
                 'restrinja por firewall ou bind a 127.0.0.1.',
        'PostgreSQL': 'Bloqueie o IP. Ajuste pg_hba.conf para limitar origem '
                      'e force scram-sha-256.',
        'RDP': 'CRÍTICO: RDP brute force é vetor #1 de ransomware. Bloqueie '
               'o IP, exija NLA, ative Network-Level lockout e considere '
               'colocar RDP atrás de VPN/RD-Gateway.',
        'VNC': 'Bloqueie o IP. VNC exposto sem TLS é alto risco — use '
               'tunelamento via SSH.',
        'WinRM-HTTP': 'Bloqueie o IP. WinRM via HTTP (5985) não deveria '
                      'estar exposto — exija HTTPS (5986) e Kerberos.',
        'WinRM-HTTPS': 'Bloqueie o IP. Brute force WinRM costuma vir de pivot '
                       'interno comprometido — investigue lateral movement.',
    }

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold_attempts = self.thresholds.get('brute_force_attempts', 10)
        self.time_window = self.thresholds.get('brute_force_time_window', 60)
        self.attempts = defaultdict(list)
        # Tracker compartilha estado de handshake + bytes por (server, client,
        # port). Permite reportar se ALGUMA tentativa virou conexão real.
        self.tracker = TcpFlowTracker()
        # Payload bytes per individual connection (client, server, port,
        # client_sport). Lets finalize tell a credential-guessing loop (many
        # short, same-sized auth exchanges) from an application connection
        # pool / chatty client (many connections carrying varied, sizeable
        # data) — the #1 false positive of a pure SYN-rate rule on DB ports.
        self.conn_bytes = {}

    MAX_CONN_TRACKED = 1_000_000

    def _add_conn_bytes(self, key, n):
        cur = self.conn_bytes.get(key)
        if cur is None:
            if len(self.conn_bytes) >= self.MAX_CONN_TRACKED:
                return
            cur = 0
        self.conn_bytes[key] = cur + n

    def update(self, pkt):
        if IP not in pkt:
            return
        if TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
            ts = pkt.time
            # Direção pra alimentar o tracker e a contabilidade legada.
            if dport in self.TARGET_PORTS:
                self.tracker.observe_tcp(
                    dst_ip, src_ip, dport, pkt, sender_is_client=True,
                )
            elif sport in self.TARGET_PORTS:
                self.tracker.observe_tcp(
                    src_ip, dst_ip, sport, pkt, sender_is_client=False,
                )
            if dport in self.TARGET_PORTS or sport in self.TARGET_PORTS:
                n = getattr(pkt[TCP], 'plen', None)
                if n is None:
                    try:
                        n = len(pkt[Raw].load) if Raw in pkt else 0
                    except Exception:
                        n = 0
                if n:
                    if dport in self.TARGET_PORTS:
                        self._add_conn_bytes((src_ip, dst_ip, dport, sport), n)
                    else:
                        self._add_conn_bytes((dst_ip, src_ip, sport, dport), n)
            # SYN para porta-alvo: nova tentativa do cliente. Exige ACK=0 para
            # não contar o SYN-ACK de resposta do servidor como tentativa.
            if dport in self.TARGET_PORTS and (flags & 0x02) and not (flags & 0x10):
                self.attempts[(src_ip, dst_ip, dport)].append({
                    'timestamp': ts, 'is_failed': False, 'sport': sport,
                })
            # RST do servidor: marca última tentativa como falha
            if sport in self.TARGET_PORTS and (flags & 0x04):
                key = (dst_ip, src_ip, sport)
                if key in self.attempts and self.attempts[key]:
                    self.attempts[key][-1]['is_failed'] = True
            return
        if ICMP in pkt:
            self.tracker.observe_icmp_error(
                pkt, ports=self.TARGET_PORTS.keys(), create_missing=False,
            )

    @staticmethod
    def _profile(sizes):
        """(with_data, median, cv) over per-connection payload sizes."""
        data = sorted(b for b in sizes if b > 0)
        if not data:
            return 0, 0, None
        median = data[len(data) // 2]
        mean = sum(data) / len(data)
        if len(data) < 3 or mean <= 0:
            return len(data), median, None
        var = sum((b - mean) ** 2 for b in data) / len(data)
        return len(data), median, (var ** 0.5) / mean

    def finalize(self):
        alerts = []
        for (src_ip, dst_ip, dst_port), attempt_list in self.attempts.items():
            if len(attempt_list) < self.threshold_attempts:
                continue
            attempt_list.sort(key=lambda x: x['timestamp'])
            # Two-pointer sliding window (the old per-start rescan was
            # O(n^2): a DB client with 100k pooled connections stalled the
            # whole analysis here). Keeps the densest window.
            best_i, best_j = 0, 0
            j = 0
            n = len(attempt_list)
            for i in range(n):
                limit = attempt_list[i]['timestamp'] + self.time_window
                while j < n and attempt_list[j]['timestamp'] <= limit:
                    j += 1
                if j - i > best_j - best_i:
                    best_i, best_j = i, j
            in_window = attempt_list[best_i:best_j]
            if len(in_window) < self.threshold_attempts:
                continue
            failed_count = sum(1 for a in in_window if a['is_failed'])
            protocol = self.TARGET_PORTS[dst_port]
            sizes = [self.conn_bytes.get((src_ip, dst_ip, dst_port,
                                          a.get('sport')), 0)
                     for a in in_window]
            with_data, median_bytes, size_cv = self._profile(sizes)
            external_src = (not self.analyzer._is_local_ip(src_ip)
                            and self.analyzer._is_local_ip(dst_ip))
            # SMB/RDP brute forces são vetor primário de ransomware — mesmo
            # sem RST claro o número alto de tentativas já é critical. Idem
            # para MSSQL (sa account).
            always_critical = protocol in ('SMB', 'RDP', 'MSSQL')
            if always_critical or failed_count > self.threshold_attempts * 0.7:
                severity = 'critical'
            else:
                severity = 'high'
            pattern = 'credential_guessing'
            no_payload = (with_data == 0
                          and self.tracker.bytes_exchanged(
                              dst_ip, src_ip, dst_port) == 0)
            app_like = (
                with_data >= 0.8 * len(in_window)
                and failed_count < 0.3 * len(in_window)
                and (median_bytes >= 20_000
                     or (size_cv is not None and size_cv >= 0.6
                         and median_bytes >= 2_000))
            )
            if no_payload:
                # Nenhum byte de aplicação: o serviço nunca respondeu (retry
                # de cliente mal configurado, host fora do ar, varredura).
                # Sem troca de dados não há senha sendo testada.
                pattern = 'connection_retries'
                severity = 'medium' if external_src else 'low'
            elif app_like and not external_src:
                # Muitas conexões com volume grande/variável = pool de
                # conexões de aplicação, cliente de e-mail sincronizando,
                # automação (Ansible) — não um laço de login.
                pattern = 'application_traffic'
                severity = 'low'
            elif not external_src and size_cv is not None and size_cv >= 0.6:
                pattern = 'mixed'
                severity = 'medium'
            conn_status = self.tracker.status(dst_ip, src_ip, dst_port)
            bytes_exchanged = self.tracker.bytes_exchanged(
                dst_ip, src_ip, dst_port,
            )
            description = (
                f'O IP {src_ip} abriu {len(in_window)} conexões '
                f'ao {protocol} em {dst_ip} em {self.time_window}s '
                f'({failed_count} rejeitadas com RST)'
            )
            if pattern == 'connection_retries':
                description += (
                    '. Nenhuma conexão trocou dados de aplicação — parece '
                    'repetição de conexão a um serviço indisponível ou '
                    'varredura, não tentativa de login.'
                )
            elif pattern == 'application_traffic':
                description += (
                    f'. As conexões carregam volume grande/variável (mediana '
                    f'{median_bytes} B) — padrão de pool de conexões ou '
                    'aplicação, não de tentativas de senha.'
                )
            elif conn_status == 'established':
                description += (
                    '. As conexões completaram o handshake TCP — o serviço '
                    'está acessível; confira nos logs de autenticação se '
                    'alguma tentativa teve sucesso.'
                )
            alerts.append({
                'severity': severity,
                'category': 'brute_force',
                'title': f'Brute Force Attack Detected ({protocol})',
                'description': description,
                'ip': src_ip,
                'details': {
                    'source_ip': src_ip,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'target_ip': dst_ip,
                    'protocol': protocol,
                    'port': dst_port,
                    'total_attempts': len(in_window),
                    'failed_attempts': failed_count,
                    'time_window': self.time_window,
                    'duration': round(
                        in_window[-1]['timestamp']
                        - in_window[0]['timestamp'], 2,
                    ),
                    'first_ts': float(in_window[0]['timestamp']),
                    'last_ts': float(in_window[-1]['timestamp']),
                    'connection_status': conn_status,
                    'connection_established':
                        conn_status == 'established',
                    'bytes_exchanged': bytes_exchanged,
                    'pattern': pattern,
                    'connections_with_data': with_data,
                    'median_bytes_per_connection': median_bytes,
                    'bytes_size_cv': (round(size_cv, 3)
                                      if size_cv is not None else None),
                },
                'recommendation': self.RECOMMENDATIONS.get(
                    protocol,
                    f'Isto é um ataque de brute force ao {protocol}. '
                    f'Bloqueie o IP de origem {src_ip} imediatamente. '
                    f'Revise os logs de autenticação em {dst_ip}.',
                ),
            })
        return alerts


class PasswordSprayingStreamingDetector(StreamingDetector):
    """Detecta password spraying: 1-3 tentativas em N hosts/contas distintos.

    Brute force clássico = muitas tentativas no mesmo destino. Spraying inverte
    isso: poucas tentativas em muitos destinos (uma senha por conta) para
    burlar lockout. O pivot aqui é (src_ip, dst_port) e o sinal é o número de
    destinos distintos atingidos com pelo menos uma tentativa cada."""
    name = 'password_spraying'

    # Reusa o mesmo TARGET_PORTS do brute force.
    TARGET_PORTS = BruteForceStreamingDetector.TARGET_PORTS

    def __init__(self, analyzer):
        super().__init__(analyzer)
        # Default: mesmo IP atingiu >=15 destinos distintos na mesma porta
        # com pelo menos uma tentativa cada, dentro de 10 min.
        self.min_targets = self.thresholds.get('spray_min_targets', 15)
        self.time_window = self.thresholds.get('spray_time_window', 600)
        # (src, port) -> {dst -> [timestamps]}
        self.targets = defaultdict(lambda: defaultdict(list))
        # Observa todos os pacotes nas portas-alvo para reportar "alguma
        # tentativa pegou?" (alvo com TCP estabelecido = credencial válida).
        self.tracker = TcpFlowTracker()

    def update(self, pkt):
        if IP not in pkt:
            return
        if TCP in pkt:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if dport in self.TARGET_PORTS:
                self.tracker.observe_tcp(
                    dst_ip, src_ip, dport, pkt, sender_is_client=True,
                )
            elif sport in self.TARGET_PORTS:
                self.tracker.observe_tcp(
                    src_ip, dst_ip, sport, pkt, sender_is_client=False,
                )
            else:
                return
            flags = int(pkt[TCP].flags)
            if dport in self.TARGET_PORTS and (flags & 0x02) and not (flags & 0x10):
                # só SYN puro, não SYN-ACK
                self.targets[(src_ip, dport)][dst_ip].append(pkt.time)
            return
        if ICMP in pkt:
            self.tracker.observe_icmp_error(
                pkt, ports=self.TARGET_PORTS.keys(), create_missing=False,
            )

    def finalize(self):
        alerts = []
        for (src_ip, port), dst_map in self.targets.items():
            if len(dst_map) < self.min_targets:
                continue
            # Confere janela: pega a primeira tentativa de cada destino e
            # exige que >= min_targets caiam em uma mesma janela deslizante.
            first_ts = sorted(min(ts) for ts in dst_map.values())
            n = len(first_ts)
            best_count = 0
            best_start = 0.0
            best_end = 0.0
            j = 0
            for i in range(n):
                while j < n and first_ts[j] - first_ts[i] <= self.time_window:
                    j += 1
                count = j - i
                if count > best_count:
                    best_count = count
                    best_start = first_ts[i]
                    best_end = first_ts[j - 1] if j > i else first_ts[i]
            if best_count < self.min_targets:
                continue
            protocol = self.TARGET_PORTS[port]
            target_sample = sorted(dst_map.keys())[:20]
            # Spraying contra protocolos de domínio (SMB/WinRM/RDP) é vetor
            # típico de pré-comprometimento AD.
            severity = ('critical' if protocol in ('SMB', 'RDP', 'WinRM-HTTP',
                                                   'WinRM-HTTPS', 'MSSQL')
                        else 'high')
            # Agrega status TCP e bytes em todos os destinos do spray:
            # estabelecidos viram lista crítica (indício de credencial válida).
            established_targets = []
            total_bytes = 0
            for dst_ip in dst_map.keys():
                st = self.tracker.status(dst_ip, src_ip, port)
                if st == 'established':
                    established_targets.append(dst_ip)
                total_bytes += self.tracker.bytes_exchanged(
                    dst_ip, src_ip, port,
                )
            connection_status = (
                'established' if established_targets else 'scan_no_response'
            )
            # Context for internal sources. A management/backup/inventory
            # server (SCCM, Veeam, WSUS, PDQ, an admin script) also touches
            # dozens of hosts on 445/5985 — but it gets in everywhere and
            # moves real data, whereas a spray mostly fails with tiny auth
            # exchanges. External sources keep full severity: there is no
            # benign reason for the internet to fan out over our auth ports.
            pattern = 'spray'
            src_internal = self.analyzer._is_local_ip(src_ip)
            if src_internal:
                per_target_bytes = sorted(
                    self.tracker.bytes_exchanged(d, src_ip, port)
                    for d in dst_map.keys())
                median_tb = per_target_bytes[len(per_target_bytes) // 2]
                if (len(established_targets) >= 0.8 * len(dst_map)
                        and median_tb >= 50_000):
                    pattern = 'management'
                    severity = 'medium'
                elif total_bytes == 0:
                    # Nothing answered with data: a sweep of the port, not
                    # credential attempts (Horizontal Scan covers it).
                    pattern = 'sweep_no_auth'
                    severity = 'medium'
            description = (
                f'O IP {src_ip} tentou autenticação {protocol} contra '
                f'{best_count} hosts distintos em '
                f'{int(best_end - best_start)}s '
                f'(padrão de spraying — burla o lockout por conta).'
            )
            if pattern == 'management':
                description += (
                    f' Porém {len(established_targets)} alvo(s) tiveram sessão '
                    'estabelecida com volume de dados alto — perfil de servidor '
                    'de gerência/backup/inventário, não de tentativa de senha.'
                )
            elif pattern == 'sweep_no_auth':
                description += (
                    ' Nenhum alvo trocou dados — varredura da porta, sem '
                    'tentativa de autenticação observada.'
                )
            elif established_targets:
                description += (
                    f' {len(established_targets)} alvo(s) tiveram conexão '
                    'TCP estabelecida — verifique nos logs se alguma '
                    'autenticação teve sucesso.'
                )
            alerts.append({
                'severity': severity,
                'category': 'brute_force',
                'title': f'Password Spraying Detected ({protocol})',
                'description': description,
                'ip': src_ip,
                'details': {
                    'source_ip': src_ip,
                    'src_ip': src_ip,
                    'protocol': protocol,
                    'port': port,
                    'distinct_targets': best_count,
                    'total_targets': len(dst_map),
                    'time_window': int(best_end - best_start),
                    'target_sample': target_sample,
                    'first_ts': float(best_start),
                    'last_ts': float(best_end),
                    'connection_status': connection_status,
                    'connection_established': bool(established_targets),
                    'bytes_exchanged': total_bytes,
                    'established_targets': sorted(established_targets)[:10],
                    'established_target_count': len(established_targets),
                    'pattern': pattern,
                },
                'recommendation': (
                    f'Password spraying tipicamente precede movimento lateral '
                    f'no AD. Bloqueie {src_ip}, audite os eventos de logon '
                    f'falho em todos os {best_count} alvos e verifique se '
                    f'alguma conta teve um logon bem-sucedido logo após esta '
                    f'janela.'
                ),
            })
        return alerts


class DgaStreamingDetector(StreamingDetector):
    """Streaming de _detect_dga."""
    name = 'dga'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold = self.thresholds.get('dga_score_threshold', 0.7)
        self.min_length = self.thresholds.get('dga_min_label_length', 7)
        self.by_src = defaultdict(list)
        self.seen = set()

    def update(self, pkt):
        if DNS not in pkt or IP not in pkt:
            return
        if pkt[DNS].qr != 0 or DNSQR not in pkt:
            return
        try:
            query = pkt[DNSQR].qname
            if isinstance(query, bytes):
                query = query.decode('utf-8', errors='ignore')
            query = query.rstrip('.').lower()
            if not query:
                return
            label = self.analyzer._extract_dns_label(query)
            if not label or len(label) < self.min_length:
                return
            # Punycode (IDN) labels are ASCII-encoded Unicode — high entropy
            # by construction, not algorithmic generation.
            if label.startswith('xn--'):
                return
            src_ip = pkt[IP].src
            key = (src_ip, query)
            if key in self.seen:
                return
            self.seen.add(key)
            score = self.analyzer._dga_score(label)
            if score >= self.threshold:
                self.by_src[src_ip].append((query, score))
        except Exception:
            pass

    def finalize(self):
        alerts = []
        for src_ip, items in self.by_src.items():
            items.sort(key=lambda x: x[1], reverse=True)
            max_score = items[0][1]
            avg_score = sum(s for _, s in items) / len(items)
            # DGA malware cycles through MANY generated names (most answer
            # NXDOMAIN); one random-looking domain is usually an ad/tracking
            # or CDN brand. Severity grows with the number of distinct names
            # (the old ladder made a single 0.85 label critical).
            n_items = len(items)
            if n_items >= 5 or (n_items >= 3 and max_score >= 0.85):
                severity = 'critical'
            elif n_items >= 2 or max_score >= 0.9:
                severity = 'high'
            else:
                severity = 'medium'
            sample = [{'domain': d, 'score': round(s, 3)}
                      for d, s in items[:10]]
            # B.9 confidence: blends per-domain score strength with corpus
            # size. A single max-0.85 domain is suggestive (≈65); a host
            # spraying 20+ high-score domains is near-certain (≈95).
            confidence = int(40 + (max_score * 40) + min(20, len(items)))
            confidence = max(40, min(99, confidence))
            alerts.append({
                'severity': severity,
                'confidence': confidence,
                'category': 'dns',
                'title': 'Possible DGA Domain Activity',
                'description': (
                    f'O host {src_ip} consultou {len(items)} domínio(s) com '
                    f'aparência de gerado por algoritmo (score máx '
                    f'{max_score:.2f}, média {avg_score:.2f})'
                ),
                'ip': src_ip,
                'details': {
                    'domain_count': len(items),
                    'max_score': round(max_score, 3),
                    'avg_score': round(avg_score, 3),
                    'samples': sample,
                },
                'recommendation': (
                    'Nomes de domínio gerados por algoritmo são típicos de C2 '
                    'de malware. Investigue o host imediatamente e bloqueie os '
                    'domínios no DNS/firewall.'
                ),
            })
        return alerts


class FastFluxStreamingDetector(StreamingDetector):
    """Streaming de _detect_fast_flux."""
    name = 'fast_flux'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.min_ips = self.thresholds.get('fastflux_min_ips', 8)
        self.max_ttl = self.thresholds.get('fastflux_max_ttl', 300)
        self.domain_to_ips = defaultdict(set)
        self.domain_to_ttls = defaultdict(list)
        self.domain_client = {}

    def update(self, pkt):
        if DNS not in pkt:
            return
        d = pkt[DNS]
        if d.qr != 1 or not d.ancount or d.an is None:
            return
        try:
            ancount = int(d.ancount)
            for i in range(ancount):
                try:
                    rr = d.an[i]
                except Exception:
                    break
                if rr is None:
                    continue
                if int(getattr(rr, 'type', 0)) not in (1, 28):
                    continue
                name = getattr(rr, 'rrname', b'')
                if isinstance(name, bytes):
                    name = name.decode('utf-8', errors='ignore')
                name = name.rstrip('.').lower()
                if not name:
                    continue
                rdata = getattr(rr, 'rdata', None)
                if rdata is None:
                    continue
                if isinstance(rdata, bytes):
                    try:
                        rdata = rdata.decode('utf-8', errors='ignore')
                    except Exception:
                        continue
                self.domain_to_ips[name].add(str(rdata))
                self.domain_to_ttls[name].append(int(getattr(rr, 'ttl', 0)))
                if name not in self.domain_client and IP in pkt:
                    self.domain_client[name] = pkt[IP].dst
        except Exception:
            pass

    def finalize(self):
        alerts = []
        for domain, ips in self.domain_to_ips.items():
            if len(ips) < self.min_ips:
                continue
            ttls = [t for t in self.domain_to_ttls[domain] if t > 0]
            if not ttls:
                continue
            avg_ttl = sum(ttls) / len(ttls)
            if avg_ttl > self.max_ttl:
                continue
            from ..constants import (
                DNS_PROVIDER_OWNED_ZONES, hostname_suffix_match,
            )
            # CDNs and global load balancers (Akamai, CloudFront, Fastly,
            # Google, Microsoft) rotate many IPs with short TTLs by design —
            # that is the textbook fast-flux false positive.
            if hostname_suffix_match([domain], DNS_PROVIDER_OWNED_ZONES):
                continue
            # A flux botnet answers with compromised residential hosts
            # scattered across unrelated networks; a CDN/load balancer answers
            # from a few of its own prefixes. Diversity = distinct /16 (v4)
            # or /32 (v6) networks per answered IP.
            prefixes = set()
            for ip_s in ips:
                try:
                    ipo = ipaddress.ip_address(ip_s)
                except ValueError:
                    continue
                plen = 16 if ipo.version == 4 else 32
                prefixes.add(ipaddress.ip_network(
                    f'{ip_s}/{plen}', strict=False))
            diversity = len(prefixes) / len(ips) if ips else 0.0
            if len(prefixes) < 3:
                severity = 'low'
            elif diversity < 0.5:
                severity = 'medium'
            else:
                severity = ('critical'
                            if (len(ips) >= self.min_ips * 2 and avg_ttl <= 60)
                            else 'high')
            alerts.append({
                'severity': severity,
                'category': 'dns',
                'title': 'Fast-Flux Domain Suspected',
                'description': (
                    f"O domínio '{domain}' resolve para {len(ips)} IPs "
                    f"distintos com TTL médio de {avg_ttl:.0f}s"
                ),
                'ip': self.domain_client.get(domain, ''),
                'details': {
                    'domain': domain,
                    'unique_ips': len(ips),
                    'ips_sample': sorted(list(ips))[:10],
                    'avg_ttl_seconds': round(avg_ttl, 0),
                    'min_ttl_seconds': min(ttls),
                    'distinct_networks': len(prefixes),
                    'network_diversity': round(diversity, 3),
                },
                'recommendation': (
                    'Fast-flux é usado por botnets (ex.: Avalanche, variantes '
                    'do Mirai) para escapar de blocklists. Investigue a '
                    'reputação do domínio e bloqueie no DNS/firewall.'
                ),
            })
        return alerts


class NxdomainSpikeStreamingDetector(StreamingDetector):
    """Burst of NXDOMAIN answers to one client -> DGA probing.

    Counts DISTINCT failed names inside the window. The old rule counted
    responses, so one broken lookup retried by the resolver + A/AAAA pairs +
    DNS search-suffix expansion (name.corp.local, name.local, ...) inflated
    a single typo into a "spike". Reverse lookups (in-addr.arpa/ip6.arpa —
    loggers and monitoring resolve thousands of PTRs that do not exist),
    local zones and single-label names (Chrome's intranet-redirect probes,
    WPAD) are ignored. Severity rises when the failed names themselves look
    algorithmic.
    """
    name = 'nxdomain_spike'

    _IGNORED_SUFFIXES = ('.arpa', '.local', '.localdomain', '.lan', '.home',
                         '.internal', '.corp', '.home.arpa')
    MAX_EVENTS_PER_CLIENT = 100_000

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.threshold = self.thresholds.get('nxdomain_threshold', 20)
        self.window = self.thresholds.get('nxdomain_window', 60)
        self.dga_threshold = self.thresholds.get('dga_score_threshold', 0.7)
        # client -> [(ts, qname)]
        self.nxdomain_by_client = defaultdict(list)

    def update(self, pkt):
        if DNS not in pkt or IP not in pkt:
            return
        d = pkt[DNS]
        if d.qr != 1:
            return
        try:
            if int(d.rcode) != 3:
                return
            qname = ''
            if DNSQR in pkt:
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode('utf-8', errors='ignore')
                qname = (qname or '').rstrip('.').lower()
            if qname:
                if '.' not in qname:
                    return
                if qname.endswith(self._IGNORED_SUFFIXES) or \
                        qname.startswith(('wpad.', 'isatap.')):
                    return
            events = self.nxdomain_by_client[pkt[IP].dst]
            if len(events) < self.MAX_EVENTS_PER_CLIENT:
                events.append((float(pkt.time), qname or f'#{len(events)}'))
        except Exception:
            pass

    def finalize(self):
        alerts = []
        for client_ip, events in self.nxdomain_by_client.items():
            if len({q for _, q in events}) < self.threshold:
                continue
            events.sort()
            best_count = 0
            best_names = set()
            counts = Counter()
            distinct = 0
            j = 0
            n = len(events)
            for i in range(n):
                while j < n and events[j][0] - events[i][0] <= self.window:
                    if counts[events[j][1]] == 0:
                        distinct += 1
                    counts[events[j][1]] += 1
                    j += 1
                if distinct > best_count:
                    best_count = distinct
                    best_names = {q for q, c in counts.items() if c > 0}
                counts[events[i][1]] -= 1
                if counts[events[i][1]] == 0:
                    distinct -= 1
            if best_count < self.threshold:
                continue
            # How algorithmic are the failed names?
            scored = 0
            random_like = 0
            for q in best_names:
                if q.startswith('#'):
                    continue
                label = self.analyzer._extract_dns_label(q)
                if not label or len(label) < 6:
                    continue
                scored += 1
                if self.analyzer._dga_score(label) >= self.dga_threshold:
                    random_like += 1
            random_ratio = (random_like / scored) if scored else 0.0
            if best_count >= self.threshold * 2 and random_ratio >= 0.3:
                severity = 'critical'
            elif scored and random_ratio < 0.1:
                # Readable names failing (typos, decommissioned hosts,
                # broken app config) — noisy, not DGA.
                severity = 'medium'
            else:
                severity = 'high'
            alerts.append({
                'severity': severity,
                'category': 'dns',
                'title': 'NXDOMAIN Spike Detected',
                'description': (
                    f'O host {client_ip} recebeu NXDOMAIN para {best_count} '
                    f'nomes distintos em {self.window}s (total '
                    f'{len(events)} respostas na captura; '
                    f'{random_like} de {scored} nomes com aparência '
                    'algorítmica)'
                ),
                'ip': client_ip,
                'details': {
                    'client_ip': client_ip,
                    'nxdomain_in_window': best_count,
                    'window_seconds': self.window,
                    'total_nxdomain': len(events),
                    'random_looking_ratio': round(random_ratio, 3),
                    'names_sample': sorted(
                        q for q in best_names if not q.startswith('#'))[:10],
                    'first_ts': events[0][0],
                    'last_ts': events[-1][0],
                },
                'recommendation': (
                    'Um volume alto de NXDOMAIN frequentemente indica malware '
                    'DGA sondando por domínios de C2 ativos. Investigue o host '
                    'em busca de malware. Se os nomes forem legíveis (erros de '
                    'digitação, servidores desativados), corrija a '
                    'configuração da aplicação que os consulta.'
                ),
            })
        return alerts


class SuspiciousTldStreamingDetector(StreamingDetector):
    """Streaming de _detect_suspicious_tld."""
    name = 'suspicious_tld'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.suspicious_tlds = analyzer.SUSPICIOUS_TLDS
        self.by_src_tld = defaultdict(set)

    def update(self, pkt):
        if DNS not in pkt or IP not in pkt:
            return
        if pkt[DNS].qr != 0 or DNSQR not in pkt:
            return
        try:
            query = pkt[DNSQR].qname
            if isinstance(query, bytes):
                query = query.decode('utf-8', errors='ignore')
            query = query.rstrip('.').lower()
            parts = query.split('.')
            if len(parts) < 2:
                return
            tld = parts[-1]
            if tld in self.suspicious_tlds:
                self.by_src_tld[(pkt[IP].src, tld)].add(query)
        except Exception:
            pass

    def finalize(self):
        alerts = []
        for (src_ip, tld), domains in self.by_src_tld.items():
            sample = sorted(list(domains))[:5]
            # Plenty of legitimate sites live on .xyz/.top/.club/.online; one
            # or two lookups are browsing, many distinct names under a cheap
            # TLD is the malware/phishing-infrastructure pattern.
            if len(domains) >= 5:
                severity = 'high'
            elif len(domains) >= 3:
                severity = 'medium'
            else:
                severity = 'low'
            alerts.append({
                'severity': severity,
                'category': 'dns',
                'title': f'Queries to Suspicious TLD (.{tld})',
                'description': (
                    f'O host {src_ip} consultou {len(domains)} domínio(s) sob '
                    f'.{tld} (TLD comumente abusado)'
                ),
                'ip': src_ip,
                'details': {
                    'tld': tld,
                    'domain_count': len(domains),
                    'domains_sample': sample,
                },
                'recommendation': (
                    'TLDs baratos ou gratuitos de registrar são muito abusados '
                    'por malware e phishing. Valide a legitimidade destes '
                    'domínios.'
                ),
            })
        return alerts


class DotStreamingDetector(StreamingDetector):
    """Streaming de _detect_dot (DNS-over-TLS na porta 853)."""
    name = 'dot'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        self.known_resolvers = analyzer.KNOWN_PUBLIC_DNS_RESOLVERS
        self.seen_pairs = set()

    def update(self, pkt):
        if TCP not in pkt or IP not in pkt:
            return
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if dport != 853 and sport != 853:
            return
        if dport == 853:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        else:
            src_ip = pkt[IP].dst
            dst_ip = pkt[IP].src
        self.seen_pairs.add((src_ip, dst_ip))

    def finalize(self):
        alerts = []
        for src_ip, dst_ip in self.seen_pairs:
            is_known = dst_ip in self.known_resolvers
            note = ' (resolver público conhecido)' if is_known else ''
            alerts.append({
                # DoT to Google/Cloudflare/Quad9 is Android "Private DNS" or a
                # browser setting — a visibility/policy issue (low). DoT to an
                # unknown endpoint may be a private resolver or a tunnel.
                'severity': 'low' if is_known else 'medium',
                'category': 'dns',
                'title': 'DNS-over-TLS (DoT) Connection',
                'description': (
                    f'O host {src_ip} conectou-se a {dst_ip} na porta 853 (DoT)'
                    f'{note}'
                ),
                'ip': src_ip,
                'details': {
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'port': 853,
                    'protocol': 'DoT',
                    'known_public_resolver': is_known,
                },
                'recommendation': (
                    'O DoT contorna a visibilidade de DNS corporativo (sem '
                    'logs, sem filtragem). Se não for explicitamente aprovado, '
                    'bloqueie a porta 853 de saída e force o DNS pelo resolver '
                    'corporativo.'
                ),
            })
        return alerts


class PayloadEntropyCleartextStreamingDetector(StreamingDetector):
    """Streaming de _detect_payload_entropy_cleartext. Acumula até 64KB de
    payload por fluxo TCP cliente→servidor em portas claro; computa entropia
    no finalize."""
    name = 'payload_entropy'

    CLEARTEXT_PORTS = {
        80: 'HTTP', 21: 'FTP-Control', 23: 'Telnet', 25: 'SMTP',
        110: 'POP3', 143: 'IMAP', 8080: 'HTTP-Alt', 8000: 'HTTP-Alt',
    }
    HEADER_PREFIXES = (
        b'GET ', b'POST ', b'PUT ', b'HEAD ', b'OPTIONS ',
        b'DELETE ', b'PATCH ', b'HTTP/', b'HELO ', b'EHLO ',
        b'USER ', b'PASS ', b'MAIL ', b'RCPT ', b'DATA',
        b'STAT', b'LIST', b'RETR', b'a001 ', b'A001 ',
    )

    def __init__(self, analyzer):
        super().__init__(analyzer)
        t = self.thresholds
        self.min_bytes = int(t.get('payload_entropy_min_bytes', 4096))
        self.min_entropy = float(t.get('payload_entropy_min', 7.5))
        self.flows = defaultdict(
            lambda: {'chunks': [], 'size': 0, 'proto_seen': False})

    def update(self, pkt):
        if TCP not in pkt or IP not in pkt or Raw not in pkt:
            return
        dport = pkt[TCP].dport
        # Client -> server only (as documented). Server responses on 80/8080
        # are routinely gzip/brotli bodies, images, zip/installer downloads —
        # all near 8 bits/byte; including them (a capture starting mid-
        # download has no "HTTP/" header to exempt it) was a steady source of
        # "tunnel" false positives.
        if dport not in self.CLEARTEXT_PORTS:
            return
        proto = self.CLEARTEXT_PORTS[dport]
        key = (pkt[IP].src, pkt[IP].dst, dport, proto)
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return
        if not payload:
            return
        flow = self.flows[key]
        # Any segment that opens with a protocol verb means this client
        # speaks the protocol (an upload body after "POST ..." is legit
        # binary). Checked on every segment, not only the first captured.
        if not flow['proto_seen'] and \
                any(payload.startswith(p) for p in self.HEADER_PREFIXES):
            flow['proto_seen'] = True
        if flow['size'] < 65536:
            flow['chunks'].append(payload)
            flow['size'] += len(payload)

    def finalize(self):
        alerts = []
        for (src, dst, port, proto), flow in self.flows.items():
            if flow['size'] < self.min_bytes:
                continue
            if flow['proto_seen']:
                continue
            blob = b''.join(flow['chunks'])
            entropy = self.analyzer._calculate_entropy(blob)
            if entropy < self.min_entropy:
                continue
            severity = 'high' if entropy >= 7.8 else 'medium'
            alerts.append({
                'severity': severity,
                'category': 'exfil',
                'title': f'High-Entropy Payload on Cleartext Port ({proto})',
                'description': (
                    f'O fluxo {src} -> {dst}:{port} ({proto}) tem {flow["size"]} '
                    f'bytes de payload com entropia de Shannon de {entropy:.2f} '
                    f'bits/byte. Protocolos em texto claro normalmente medem '
                    f'4,5-6,5; >7,5 indica tráfego criptografado/comprimido.'
                ),
                'ip': src,
                'details': {
                    'src': src, 'dst': dst, 'port': port, 'proto': proto,
                    'bytes_sampled': flow['size'],
                    'entropy': round(entropy, 3),
                },
                'recommendation': (
                    'Entropia alta em uma porta de texto claro indica payload '
                    'criptografado ou comprimido — possível tunelamento (ex.: '
                    'TLS sobre 80, SSH sobre 25, dados codificados por malware). '
                    'Inspecione o destino e considere bloquear.'
                ),
            })
        return alerts


# === Onda 6 — B.7: Cobalt Strike DNS Beacon ===================================


class CobaltStrikeDnsBeaconStreamingDetector(StreamingDetector):
    """Onda 6 — B.7. Cobalt Strike DNS Beacons funnel C2 traffic through
    TXT/A/AAAA queries to a Team Server. Default malleable profiles use
    distinctive subdomain prefixes (`post.`, `api.`, `cs.`, `www.`, `cdn.`)
    followed by long base32-ish random labels that encode beacon metadata.

    A single hit isn't conclusive (legitimate APIs use api.* too) — we
    require the prefix + a long random subdomain label co-located. One alert
    is emitted per (src, parent_zone); severity is monotonic in evidence:
    1-2 matching queries = high (a lone hit can be an unlucky api.* label),
    3+ = critical (sustained encoded-label querying of one zone is the
    beacon-channel signature).
    """
    name = 'cs_dns_beacon'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        from ..constants import (
            COBALT_STRIKE_DNS_PREFIXES,
            COBALT_STRIKE_DNS_LABEL_MIN_LEN,
        )
        self._prefixes = COBALT_STRIKE_DNS_PREFIXES
        self._label_min = COBALT_STRIKE_DNS_LABEL_MIN_LEN
        # (src, parent_zone) -> {'first_ts': float, 'hits': int, 'qtypes': set}
        self._hits = {}

    @staticmethod
    def _parent_zone(parts):
        from ..constants import base_zone
        return base_zone(parts)

    def update(self, pkt):
        if DNS not in pkt or IP not in pkt:
            return
        d = pkt[DNS]
        if d.qr != 0 or DNSQR not in pkt:
            return
        try:
            q = pkt[DNSQR].qname
            if isinstance(q, bytes):
                q = q.decode('utf-8', errors='ignore')
            q = q.rstrip('.').lower()
            parts = q.split('.')
            if len(parts) < 3:
                return
            label = parts[0]
            # Must match prefix AND have a long random label below it.
            # CS DNS Beacons embed encoded data in subdomain labels; the
            # prefix is on the highest-order label (e.g. post.<longrnd>.<zone>).
            prefix_match = False
            for pref in self._prefixes:
                if q.startswith(pref):
                    prefix_match = True
                    break
            if not prefix_match:
                return
            # The label after the prefix (parts[1]) carries the encoded data.
            if len(parts) < 3:
                return
            encoded_label = parts[1]
            if len(encoded_label) < self._label_min:
                return
            zone = self._parent_zone(parts)
            # The encoded label must sit BELOW the registrable zone. For
            # `www.somelongbrandname.com` parts[1] IS the registered domain
            # (the site's own name), not beacon data — that shape fired on
            # any long www.* site.
            if len(parts) - (zone.count('.') + 1) < 2:
                return
            # Vendor-answered zones (CDN/cloud/AV reputation) cannot relay
            # queries to a Team Server.
            from ..constants import (
                DNS_PROVIDER_OWNED_ZONES, DNS_REPUTATION_LOOKUP_ZONES,
            )
            if zone in DNS_PROVIDER_OWNED_ZONES or \
                    zone in DNS_REPUTATION_LOOKUP_ZONES:
                return
            # Entropy check — CS encodes hex/base32, entropy of real label is
            # 3.5+ bits/symbol. Pronounceable words (api.mycompanyservices.*)
            # carry no digits and score low on the DGA heuristic.
            try:
                ent = self.analyzer._calculate_entropy(encoded_label)
            except Exception:
                ent = 0.0
            if ent < 3.0:
                return
            if not any(c.isdigit() for c in encoded_label) and \
                    self.analyzer._dga_score(encoded_label) < 0.7:
                return
            qtype = int(getattr(pkt[DNSQR], 'qtype', 0))
            key = (pkt[IP].src, zone)
            rec = self._hits.get(key)
            if rec is None:
                self._hits[key] = {
                    'first_ts': float(pkt.time),
                    'hits': 1,
                    'qtypes': {qtype},
                    'sample': q,
                    'first_prefix': next(
                        p.rstrip('.') for p in self._prefixes
                        if q.startswith(p)
                    ),
                }
            else:
                rec['hits'] += 1
                rec['qtypes'].add(qtype)
        except Exception:
            pass

    def finalize(self):
        alerts = []
        # qtype 16 = TXT, 1 = A, 28 = AAAA — most CS DNS profiles use TXT.
        qtype_name = {1: 'A', 28: 'AAAA', 16: 'TXT', 15: 'MX'}
        for (src, zone), rec in self._hits.items():
            qtypes_str = sorted(
                qtype_name.get(q, str(q)) for q in rec['qtypes']
            )
            # Monotonic in evidence — the pre-2026-07 ladder was inverted
            # (1 hit = critical, 3 hits = high), so the most FP-prone case
            # (one unlucky api.* label) outranked a sustained beacon.
            severity = 'critical' if rec['hits'] >= 3 else 'high'
            alerts.append({
                'severity': severity,
                'category': 'c2',
                'title': 'Cobalt Strike DNS Beacon pattern',
                'description': (
                    f'O host {src} consultou {rec["hits"]} subdomínio(s) com '
                    f'label longo e aleatório sob {zone} com prefixo estilo CS '
                    f'"{rec["first_prefix"]}". qtypes={qtypes_str}. '
                    f'Visto pela primeira vez em ts={rec["first_ts"]:.2f}. '
                    'Consistente com C2 via Cobalt Strike DNS Beacon.'
                ),
                'ip': src,
                'details': {
                    'src': src,
                    'parent_zone': zone,
                    'prefix': rec['first_prefix'],
                    'hits': rec['hits'],
                    'qtypes': qtypes_str,
                    'sample_query': rec['sample'],
                    'first_ts': rec['first_ts'],
                },
                'recommendation': (
                    'CS DNS Beacons são extremamente furtivos — costumam '
                    'operar quando a saída HTTP está bloqueada. Faça sinkhole '
                    'da zona-pai, preserve memória/disco no host de origem e '
                    'verifique se há hits simultâneos do lado HTTP do Cobalt '
                    'Strike.'
                ),
                'mitre_attack': {
                    'technique_id': 'T1071.004',
                    'technique_name': (
                        'Application Layer Protocol: DNS'
                    ),
                    'tactic_id': 'TA0011',
                    'tactic_name': 'Command and Control',
                    'url': 'https://attack.mitre.org/techniques/T1071/004/',
                    'software_id': 'S0154',
                    'software_name': 'Cobalt Strike',
                },
            })
        return alerts


# === Onda 5 — A.5/A.6/A.7: cobertura ampliada ================================


class ModernTunnelStreamingDetector(StreamingDetector):
    """A.5 — Tunneling moderno: DoQ, WireGuard/OpenVPN em portas não-padrão,
    GRE/IPIP/SIT para destinos externos. ECH (TLS ext 0xfe0d) é tratado pelo
    detector pós (EncryptedClientHelloDetector) usando _tls_info."""
    name = 'modern_tunnel'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        from .. import constants as _c
        self._c = _c
        # (src, dst, dport) -> sample dict
        self.doq_flows = {}
        self.wg_flows = {}
        self.openvpn_flows = {}
        self.ip_tunnel_flows = {}  # (src,dst,proto) -> count

    def update(self, pkt):
        analyzer = self.analyzer
        if IP not in pkt:
            return
        ip_proto = int(pkt[IP].proto) if hasattr(pkt[IP], 'proto') else None

        # IP-layer encapsulation (GRE / IPIP / SIT / EtherIP / L2TP)
        if ip_proto in self._c.IP_PROTO_TUNNELS:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if not analyzer._is_local_ip(dst) and not analyzer._is_local_ip(src):
                return
            # Apenas alertar quando UM lado é externo (tunnel para fora)
            if analyzer._is_local_ip(dst) and analyzer._is_local_ip(src):
                return
            key = (src, dst, ip_proto)
            rec = self.ip_tunnel_flows.setdefault(key, {'count': 0, 'ts': float(pkt.time)})
            rec['count'] += 1
            return

        if UDP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        # The UDP payload of an unrecognised protocol (WireGuard/OpenVPN init,
        # QUIC) is kept by PktView as the Raw layer — _UDPLayerView carries no
        # payload. Read it from Raw so the handshake-signature checks below see
        # the bytes on real captures.
        try:
            payload = bytes(pkt[Raw].load) if Raw in pkt else b''
        except Exception:
            payload = b''

        # DoQ (RFC 9250) — UDP/853 com payload que parece QUIC. O fluxo só
        # nasce ao ver um long header (bit alto do byte 0, RFC 9000 §17.2 —
        # todo handshake DoQ começa por um Initial assim); antes, QUALQUER
        # datagrama em 853 (DNS clássico mal-portado, DTLS, lixo) contava
        # como DoQ. Pacotes seguintes do mesmo fluxo (short header) somam.
        if (dport == self._c.DOQ_PORT or sport == self._c.DOQ_PORT) \
                and not analyzer._is_local_ip(dst):
            key = (src, dst, self._c.DOQ_PORT)
            rec = self.doq_flows.get(key)
            if rec is not None:
                rec['count'] += 1
            elif len(payload) >= 5 and (payload[0] & 0x80):
                self.doq_flows[key] = {'count': 1, 'ts': float(pkt.time)}

        # WireGuard handshake init: payload exatamente 148 bytes, type=0x01
        # nos primeiros 4 bytes (little-endian 0x00000001 — message_type=1,
        # reserved=0). Alertamos sempre que vemos um init fora da porta
        # default. Mesmo na porta default mantemos como info (registro).
        if len(payload) == self._c.WIREGUARD_HANDSHAKE_INIT_LEN \
                and payload[:4] == b'\x01\x00\x00\x00':
            non_standard = dport not in self._c.WIREGUARD_PORTS_BENIGN \
                and sport not in self._c.WIREGUARD_PORTS_BENIGN
            key = (src, dst, dport)
            rec = self.wg_flows.setdefault(key, {
                'count': 0, 'ts': float(pkt.time),
                'non_standard': non_standard,
                'sport': sport, 'dport': dport,
            })
            rec['count'] += 1

        # OpenVPN UDP: hard-resets são os "passwords-of-life" para identificar
        # OpenVPN mesmo sem conhecer a porta. O primeiro byte é comparado por
        # inteiro contra OPENVPN_RESET_FIRST_BYTES (opcode<<3 com key_id=0) —
        # olhar só os 5 bits altos multiplicava por 8 a colisão com payloads
        # aleatórios. Portas QUIC (443/80) são excluídas: o short header 1-RTT
        # começa em 0x40-0x47 e cada fluxo HTTP/3 virava um falso positivo.
        if len(payload) >= 14 \
                and payload[0] in self._c.OPENVPN_RESET_FIRST_BYTES \
                and dport not in self._c.OPENVPN_PORTS_BENIGN \
                and sport not in self._c.OPENVPN_PORTS_BENIGN \
                and dport not in self._c.OPENVPN_QUIC_COLLISION_PORTS \
                and sport not in self._c.OPENVPN_QUIC_COLLISION_PORTS:
            opcode = payload[0] >> 3
            key = (src, dst, dport)
            rec = self.openvpn_flows.setdefault(key, {
                'count': 0, 'ts': float(pkt.time),
                'sport': sport, 'dport': dport, 'opcodes': set(),
            })
            rec['count'] += 1
            rec['opcodes'].add(opcode)

    def finalize(self):
        alerts = []
        analyzer = self.analyzer

        for (src, dst, dport), rec in self.doq_flows.items():
            alerts.append({
                'severity': 'high',
                'category': 'tunneling',
                'title': 'DNS-over-QUIC (DoQ) to External Resolver',
                'description': (
                    f'O host {src} enviou {rec["count"]} pacotes DoQ para {dst}:{dport}. '
                    'O DoQ cega as detecções DNS do perímetro (DGA, NXDOMAIN, TLDs).'
                ),
                'ip': src,
                'details': {
                    'src': src, 'dst': dst, 'dport': dport, 'count': rec['count'],
                    'first_ts': rec['ts'],
                },
                'recommendation': (
                    'Bloquear UDP/853 saindo para resolvers públicos ou exigir '
                    'que o tráfego DNS passe pelo resolver corporativo. '
                    'Equivalente moderno do DoH.'
                ),
            })

        for (src, dst, dport), rec in self.wg_flows.items():
            # Default port = a declared VPN (inventory item, low); another
            # port = deliberate disguise (high).
            sev = 'high' if rec['non_standard'] else 'low'
            port_qual = 'non-standard' if rec['non_standard'] else 'default'
            alerts.append({
                'severity': sev,
                'category': 'tunneling',
                'title': f'WireGuard Handshake on {port_qual} port',
                'description': (
                    f'O host {src} iniciou um handshake WireGuard para '
                    f'{dst}:{dport} (init de 148B, type=1). '
                    + ('A porta não é a padrão do WireGuard (51820), '
                       'sugerindo evasão deliberada.' if rec['non_standard']
                       else 'Porta padrão — sinalizado apenas para conhecimento.')
                ),
                'ip': src,
                'details': {
                    'src': src, 'dst': dst,
                    'sport': rec['sport'], 'dport': rec['dport'],
                    'count': rec['count'], 'first_ts': rec['ts'],
                    'non_standard_port': rec['non_standard'],
                },
                'recommendation': (
                    'WireGuard provê VPN encriptada peer-to-peer. Em redes '
                    'corporativas sem política explícita, validar se há '
                    'autorização. Em porta não-padrão o uso quase sempre '
                    'indica evasão.'
                ),
            })

        for (src, dst, dport), rec in self.openvpn_flows.items():
            alerts.append({
                'severity': 'high',
                'category': 'tunneling',
                'title': 'OpenVPN on Non-Standard UDP Port',
                'description': (
                    f'O host {src} enviou opcodes OpenVPN Hard-Reset para '
                    f'{dst}:{dport} ({rec["count"]} pacotes, '
                    f'opcodes={sorted(rec["opcodes"])}). '
                    'A porta não é a padrão do OpenVPN (1194).'
                ),
                'ip': src,
                'details': {
                    'src': src, 'dst': dst,
                    'sport': rec['sport'], 'dport': rec['dport'],
                    'count': rec['count'],
                    'opcodes': sorted(rec['opcodes']),
                    'first_ts': rec['ts'],
                },
                'recommendation': (
                    'OpenVPN em porta não-padrão sugere evasão. Confrontar '
                    'com inventário de túneis autorizados.'
                ),
            })

        for (src, dst, ip_proto), rec in self.ip_tunnel_flows.items():
            proto_name = self._c.IP_PROTO_TUNNELS.get(ip_proto, str(ip_proto))
            alerts.append({
                'severity': 'medium',
                'category': 'tunneling',
                'title': f'IP Encapsulation: {proto_name}',
                'description': (
                    f'IP proto {ip_proto} ({proto_name}) entre {src} e {dst}, '
                    f'{rec["count"]} pacotes. Encapsulamento layer-3 atravessando '
                    'o perímetro.'
                ),
                'ip': src if not analyzer._is_local_ip(src) else dst,
                'details': {
                    'src': src, 'dst': dst,
                    'ip_proto': ip_proto, 'proto_name': proto_name,
                    'count': rec['count'], 'first_ts': rec['ts'],
                },
                'recommendation': (
                    f'Tráfego {proto_name} entre rede interna e IP externo. '
                    'Avaliar se é parte de uma topologia legítima (IPv6 '
                    'transition, MPLS, site-to-site) ou um túnel não-autorizado.'
                ),
            })

        return alerts


class IcsProtocolStreamingDetector(StreamingDetector):
    """A.6 — Presença de protocolos OT/ICS/IoT. Identifica via porta TCP e,
    para Modbus, parseia o function code para distinguir leitura de escrita.
    Write FC vindo de IP externo = critical."""
    name = 'ics_protocols'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        from .. import constants as _c
        self._c = _c
        # (proto, src_local, dst_local) → set de IPs / endpoints
        self.presence = defaultdict(lambda: {
            'count': 0, 'first_ts': None, 'samples': set(),
        })
        # Modbus FC writes: (src, dst) → set(fc_codes)
        self.modbus_writes_external = {}
        self.tracker = TcpFlowTracker()

    def update(self, pkt):
        analyzer = self.analyzer
        if IP not in pkt:
            return
        if ICMP in pkt and TCP not in pkt:
            self.tracker.observe_icmp_error(
                pkt, ports=self._c.ICS_PORTS.keys(), create_missing=False,
            )
            return
        if TCP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)

        # Portas ICS altas (20000/DNP3, 44818/EtherNet-IP, 47808/BACnet) caem
        # na faixa efêmera do SO: um cliente comum pode sortear uma delas como
        # porta de ORIGEM ao falar HTTPS/SSH etc., e o fluxo virava um falso
        # "ICS/OT Protocol Detected". Quando o outro lado do pacote é um
        # serviço conhecido (<1024 ou porta web), a interpretação correta é
        # "cliente de outro protocolo", não ICS — numa sessão ICS real o lado
        # oposto à porta ICS é sempre um efêmero alto arbitrário.
        def _other_side_is_known_service(port):
            return port < 1024 or port in self._c.ALPN_WEB_OK_PORTS

        ics_port = None
        if dport in self._c.ICS_PORTS:
            if _other_side_is_known_service(sport):
                return
            ics_port = dport
            direction_dst = dst
            direction_src = src
            self.tracker.observe_tcp(
                dst, src, dport, pkt, sender_is_client=True,
            )
        elif sport in self._c.ICS_PORTS:
            if _other_side_is_known_service(dport):
                return
            ics_port = sport
            direction_dst = src
            direction_src = dst
            self.tracker.observe_tcp(
                src, dst, sport, pkt, sender_is_client=False,
            )
        if ics_port is None:
            return

        proto_name = self._c.ICS_PORTS[ics_port][0]
        rec = self.presence[proto_name]
        rec['count'] += 1
        if rec['first_ts'] is None:
            rec['first_ts'] = float(pkt.time)
        rec['samples'].add((src, dst, ics_port))

        if ics_port != 502:
            return

        try:
            payload = bytes(pkt[Raw].load) if Raw in pkt else b''
        except Exception:
            payload = b''
        # Modbus/TCP MBAP header: 7 bytes (transaction, protocol, length, unit)
        # followed by function code byte. Protocol id (bytes 2-3) must be 0.
        if len(payload) < 8:
            return
        if payload[2] != 0 or payload[3] != 0:
            return
        fc = payload[7]
        if fc not in self._c.MODBUS_WRITE_FUNCTION_CODES:
            return
        if analyzer._is_local_ip(src):
            return
        key = (src, dst)
        wr = self.modbus_writes_external.setdefault(key, {
            'fcs': set(), 'count': 0, 'ts': float(pkt.time),
        })
        wr['fcs'].add(fc)
        wr['count'] += 1

    def finalize(self):
        STATUS_PRIORITY = (
            'established', 'open_no_ack', 'icmp_unreachable',
            'scan_rejected', 'scan_no_response',
        )
        alerts = []
        for proto_name, rec in self.presence.items():
            sample_list = sorted(rec['samples'])[:5]
            # Agrega status TCP nos flows desse protocolo (samples cobrem
            # múltiplos pares); melhor status vence.
            best_status = None
            total_bytes = 0
            for s, d, p in rec['samples']:
                st = (
                    self.tracker.status(d, s, p)
                    or self.tracker.status(s, d, p)
                )
                if st is not None:
                    try:
                        idx = STATUS_PRIORITY.index(st)
                    except ValueError:
                        idx = len(STATUS_PRIORITY)
                    try:
                        idx_best = (
                            STATUS_PRIORITY.index(best_status)
                            if best_status else len(STATUS_PRIORITY)
                        )
                    except ValueError:
                        idx_best = len(STATUS_PRIORITY)
                    if idx < idx_best:
                        best_status = st
                total_bytes += (
                    self.tracker.bytes_exchanged(d, s, p)
                    + self.tracker.bytes_exchanged(s, d, p)
                )
            alerts.append({
                'severity': 'medium',
                'category': 'ics',
                'title': f'ICS/OT Protocol Detected: {proto_name}',
                'description': (
                    f'{rec["count"]} pacotes {proto_name} observados envolvendo '
                    f'{len(rec["samples"])} pares src/dst. Tráfego industrial '
                    'em rede corporativa merece revisão.'
                ),
                'ip': sample_list[0][0] if sample_list else '',
                'details': {
                    'protocol': proto_name,
                    'packet_count': rec['count'],
                    'endpoint_count': len(rec['samples']),
                    'samples': [
                        {'src': s, 'dst': d, 'port': p}
                        for s, d, p in sample_list
                    ],
                    'first_ts': rec['first_ts'],
                    'connection_status':
                        best_status or 'scan_no_response',
                    'connection_established':
                        best_status == 'established',
                    'bytes_exchanged': total_bytes,
                },
                'recommendation': (
                    'Verifique se a presença de protocolo industrial '
                    f'({proto_name}) é esperada (segmento OT/IoT). Caso '
                    'contrário, segmente e bloqueie no perímetro de TI.'
                ),
            })

        for (src, dst), wr in self.modbus_writes_external.items():
            from .. import constants as _c
            fc_labels = sorted(
                f'{fc}={_c.MODBUS_WRITE_FUNCTION_CODES[fc]}'
                for fc in wr['fcs']
            )
            # Write Modbus requer payload → flow estabelecido por construção.
            conn_status = self.tracker.status(dst, src, 502) or 'established'
            bytes_exchanged = self.tracker.bytes_exchanged(dst, src, 502)
            alerts.append({
                'severity': 'critical',
                'category': 'ics',
                'title': 'Modbus Write Function from External IP',
                'description': (
                    f'IP externo {src} enviou {wr["count"]} requisições Modbus '
                    f'de escrita para {dst}:502 (FCs: {", ".join(fc_labels)}). '
                    'Controle remoto de PLC/RTU por entidade não-confiável.'
                ),
                'ip': src,
                'details': {
                    'src': src, 'dst': dst,
                    'src_ip': src, 'dst_ip': dst,
                    'function_codes': sorted(wr['fcs']),
                    'count': wr['count'],
                    'first_ts': wr['ts'],
                    'connection_status': conn_status,
                    'connection_established':
                        conn_status == 'established',
                    'bytes_exchanged': bytes_exchanged,
                },
                'recommendation': (
                    'CRÍTICO: PLC/RTU sendo escrito de IP externo. Bloquear '
                    'imediatamente; investigar autenticidade do controlador; '
                    'auditar mudanças recentes nos registradores.'
                ),
            })
        return alerts


class OperationalExposureStreamingDetector(StreamingDetector):
    """A.7 — Superfície operacional exposta: handshakes de DB visíveis a IP
    externo (TDS/Postgres/MySQL/etc) e DCERPC named-pipes clássicos de lateral
    movement (\\PIPE\\svcctl, atsvc, winreg, samr, ...) em flows SMB."""
    name = 'operational_exposure'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        from .. import constants as _c
        self._c = _c
        # (proto_label, internal_ip, external_ip, port) → {count, ts, handshake_seen}
        self.db_exposure = {}
        # (src, dst, pipe_name) → {count, ts}
        self.dcerpc_pipes = {}
        # Tracker para handshake TCP + bytes nos portos de DB expostos e SMB.
        # `handshake_seen` continua sinalizando handshake de protocolo (TDS,
        # Postgres, Mongo wire, ...); `connection_status` reflete o handshake
        # TCP cru. Ambos importam — TCP-up sem dados de DB = scan.
        self.tracker = TcpFlowTracker()
        self._tracked_ports = (
            set(self._c.EXPOSED_DB_PORTS.keys()) | {139, 445}
        )

    def _detect_db_handshake(self, port, payload):
        if not payload:
            return False
        # MSSQL TDS prelogin: type=0x12, status=0x01, length>=8
        if port in (1433, 1434):
            if len(payload) >= 8 and payload[0] == 0x12 and payload[1] in (0x00, 0x01):
                return True
        # MySQL: server greeting protocol_version=10 or 9 at offset 4
        # Handshake response client→server is opcode 0x0a... easier to detect
        # server packet: bytes 0-2 = length, byte 3 = seq, byte 4 = protocol_ver.
        if port == 3306:
            if len(payload) >= 5 and payload[3] == 0x00 and payload[4] in (0x09, 0x0a):
                return True
        # PostgreSQL: StartupMessage (length 4B BE) + protocol version 0x00030000
        if port == 5432:
            if len(payload) >= 8 and payload[4:8] == b'\x00\x03\x00\x00':
                return True
            if len(payload) >= 8 and payload[0] == ord('R'):  # AuthenticationRequest
                return True
        # MongoDB Wire OP_MSG header: messageLength(4) requestID(4) responseTo(4) opCode(4)
        if port == 27017:
            if len(payload) >= 16:
                opcode = int.from_bytes(payload[12:16], 'little')
                if opcode in (2013, 2012, 2010, 2004):
                    return True
        # Redis: RESP starts with "*", "+", "-", ":" or "$"
        if port == 6379:
            if payload[:1] in (b'*', b'+', b'-', b':', b'$'):
                return True
        # Elasticsearch / CouchDB / Memcached: HTTP-ish; fast win on GET/POST
        if port in (9200, 5984):
            if payload[:4] in (b'GET ', b'POST', b'PUT ', b'HEAD') \
                    or payload[:5] == b'HTTP/':
                return True
        if port == 11211:
            if payload[:4] in (b'STAT', b'STOR', b'GET ', b'gets') \
                    or payload[:6] == b'VALUE ':
                return True
        # Oracle TNS: byte 4-5 = packet type; type 1=connect, 2=accept
        if port == 1521:
            if len(payload) >= 6 and payload[4] in (0x01, 0x02, 0x06):
                return True
        return False

    def update(self, pkt):
        analyzer = self.analyzer
        if IP not in pkt:
            return
        # ICMP unreachable referenciando uma porta rastreada vai enriquecer
        # o status do flow (sem criar flows fantasmas).
        if ICMP in pkt and TCP not in pkt:
            self.tracker.observe_icmp_error(
                pkt, ports=self._tracked_ports, create_missing=False,
            )
            return
        if TCP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)

        # Tracker observa qualquer pacote TCP em portas relevantes (DB ou SMB).
        if dport in self._tracked_ports:
            self.tracker.observe_tcp(
                dst, src, dport, pkt, sender_is_client=True,
            )
        elif sport in self._tracked_ports:
            self.tracker.observe_tcp(
                src, dst, sport, pkt, sender_is_client=False,
            )

        # 1) DB handshake exposto: identificar internal/external e o sentido
        for port in (sport, dport):
            if port not in self._c.EXPOSED_DB_PORTS:
                continue
            # Same ephemeral-port trap as the ICS detector: 1433/1521/3306
            # sit inside legacy/NAT ephemeral ranges. When the OTHER side is
            # a well-known service (443, 22, 53...), the DB-looking number is
            # just a client's source port, not a database listening.
            other = dport if port == sport else sport
            if other < 1024 or other in self._c.ALPN_WEB_OK_PORTS:
                continue
            client_is_external = False
            server_ip = None
            client_ip = None
            if port == dport:
                server_ip = dst
                client_ip = src
            else:
                server_ip = src
                client_ip = dst
            if analyzer._is_local_ip(server_ip) and not analyzer._is_local_ip(client_ip):
                client_is_external = True
            if not client_is_external:
                continue
            label, desc = self._c.EXPOSED_DB_PORTS[port]
            key = (label, server_ip, client_ip, port)
            rec = self.db_exposure.setdefault(key, {
                'count': 0, 'ts': float(pkt.time), 'handshake_seen': False,
            })
            rec['count'] += 1
            if not rec['handshake_seen']:
                try:
                    payload = bytes(pkt[Raw].load) if Raw in pkt else b''
                except Exception:
                    payload = b''
                if self._detect_db_handshake(port, payload):
                    rec['handshake_seen'] = True
            break  # one port suffices

        # 2) DCERPC over SMB: identificar o named-pipe acessado.
        if dport in (445, 139) or sport in (445, 139):
            pname = None
            # SMB2/3: o nome do pipe é o filename (bare, ex. 'svcctl') de um
            # CREATE request — não há "\PIPE\" no fio (isso é SMB1). scapy
            # parseia SMB2 válido, então o Raw some; lê-se do CREATE parseado
            # exposto pelo pkt_view. Cobre PsExec/Impacket modernos.
            if SMB2_CREATE_LAYER is not None and SMB2_CREATE_LAYER in pkt:
                try:
                    nm = pkt[SMB2_CREATE_LAYER].name
                    if nm:
                        pname = nm.strip('\\').strip().lower()
                except Exception:
                    pname = None
            if pname:
                pname = pname.strip('\x00').strip()
                if pname in self._c.DCERPC_LATERAL_PIPES:
                    key = (src, dst, pname)
                    rec = self.dcerpc_pipes.setdefault(key, {
                        'count': 0, 'ts': float(pkt.time),
                    })
                    rec['count'] += 1
                return
            # SMB1 (e fallback bruto): varre o payload por "\PIPE\<name>".
            try:
                payload = bytes(pkt[Raw].load) if Raw in pkt else b''
            except Exception:
                payload = b''
            if not payload:
                return
            # Tanto ASCII (b'\\PIPE\\') quanto UTF-16LE (b'\\\x00P\x00I\x00P\x00E\x00\\\x00')
            ascii_idx = payload.find(b'\\PIPE\\')
            utf16_idx = payload.find(b'\\\x00P\x00I\x00P\x00E\x00\\\x00')
            if ascii_idx >= 0:
                tail = payload[ascii_idx + 6:ascii_idx + 6 + 32]
                end = 0
                while end < len(tail) and tail[end:end + 1] not in (b'\x00', b'\\'):
                    end += 1
                try:
                    pname = tail[:end].decode('ascii', errors='ignore').lower()
                except Exception:
                    pname = None
            elif utf16_idx >= 0:
                tail = payload[utf16_idx + 12:utf16_idx + 12 + 64]
                # decode UTF-16LE até NUL ou '\'
                chars = []
                i = 0
                while i + 1 < len(tail):
                    cu = tail[i] | (tail[i + 1] << 8)
                    if cu == 0 or cu == ord('\\'):
                        break
                    chars.append(chr(cu) if cu < 128 else '')
                    i += 2
                pname = ''.join(chars).lower()
            if not pname:
                return
            pname = pname.strip('\x00').strip()
            if pname in self._c.DCERPC_LATERAL_PIPES:
                key = (src, dst, pname)
                rec = self.dcerpc_pipes.setdefault(key, {
                    'count': 0, 'ts': float(pkt.time),
                })
                rec['count'] += 1

    def finalize(self):
        alerts = []
        for (label, server_ip, client_ip, port), rec in self.db_exposure.items():
            conn_status = self.tracker.status(server_ip, client_ip, port)
            if rec['handshake_seen']:
                sev = 'high'
            elif conn_status in ('established', 'open_no_ack'):
                # Port answered the internet (SYN-ACK): exposed, even if no
                # DB protocol bytes were captured.
                sev = 'medium'
            else:
                # RST / silence / ICMP: internet background scanning that
                # never reached a listening database.
                sev = 'low'
            bytes_exchanged = self.tracker.bytes_exchanged(
                server_ip, client_ip, port,
            )
            handshake_txt = (
                'Handshake de protocolo DB observado (não é só um SYN solto).'
                if rec['handshake_seen']
                else 'Apenas SYN/SYN-ACK, sem handshake de aplicação (pode ser scan).'
            )
            alerts.append({
                'severity': sev,
                'category': 'exposure',
                'title': f'Database Service Exposed: {label}',
                'description': (
                    f'Servidor interno {server_ip}:{port} ({label}) acessado '
                    f'pelo IP externo {client_ip} — {rec["count"]} pacotes. '
                    + handshake_txt
                ),
                'ip': server_ip,
                'details': {
                    'server_ip': server_ip, 'client_ip': client_ip,
                    'src_ip': client_ip, 'dst_ip': server_ip,
                    'port': port, 'protocol': label,
                    'packet_count': rec['count'],
                    'handshake_seen': rec['handshake_seen'],
                    'first_ts': rec['ts'],
                    'connection_status':
                        conn_status or 'scan_no_response',
                    'connection_established':
                        conn_status == 'established',
                    'bytes_exchanged': bytes_exchanged,
                },
                'recommendation': (
                    f'Banco {label} não deve estar exposto à internet. '
                    'Coloque atrás de bastion/VPN, restrinja por firewall, '
                    'e audite quem está autenticando da rede externa.'
                ),
            })

        # Pipe fan-out per source: distinct targets per pipe tier.
        fanout = defaultdict(set)
        for (src, dst, pname) in self.dcerpc_pipes:
            fanout[(src, self._pipe_tier(pname))].add(dst)
        for (src, dst, pname), rec in self.dcerpc_pipes.items():
            pipe_desc = self._c.DCERPC_LATERAL_PIPES.get(pname, pname)
            tier = self._pipe_tier(pname)
            n_targets = len(fanout[(src, tier)])
            severity = {'exec': 'high', 'admin': 'medium'}.get(tier, 'low')
            reason = None
            if not self.analyzer._is_local_ip(src):
                severity = 'critical'
                reason = 'origem externa à rede'
            elif tier == 'exec' and n_targets >= 3:
                severity = 'critical'
                reason = (f'execução remota em {n_targets} hosts '
                          '(onda de PsExec/SCM)')
            elif n_targets >= 5:
                severity = 'high' if tier != 'exec' else 'critical'
                reason = (f'mesmo pipe acessado em {n_targets} hosts '
                          '(enumeração em massa, ex.: BloodHound/SharpHound)')
            # SMB pipes podem rodar em 445 ou 139 — soma os dois lados.
            bytes_exchanged = (
                self.tracker.bytes_exchanged(dst, src, 445)
                + self.tracker.bytes_exchanged(dst, src, 139)
            )
            conn_status = (
                self.tracker.status(dst, src, 445)
                or self.tracker.status(dst, src, 139)
                or 'established'  # pipe access by definition requires session
            )
            description = (
                f'{src} → {dst} acessou named-pipe \\PIPE\\{pname} '
                f'({pipe_desc}) — {rec["count"]} request(s).'
            )
            if reason:
                description += f' Agravante: {reason}.'
            elif tier == 'routine':
                description += (
                    ' Este pipe é usado rotineiramente por membros do domínio '
                    '(logon, resolução de nomes, troca de senha, impressão, '
                    'listagem de compartilhamentos) — relevante apenas em '
                    'volume ou vindo de origem inesperada.'
                )
            alerts.append({
                'severity': severity,
                'category': 'lateral',
                'title': f'DCERPC Lateral-Movement Pipe: \\PIPE\\{pname}',
                'description': description,
                'ip': src,
                'details': {
                    'src': src, 'dst': dst,
                    'src_ip': src, 'dst_ip': dst,
                    'pipe': pname, 'pipe_description': pipe_desc,
                    'pipe_tier': tier,
                    'targets_for_tier': n_targets,
                    'count': rec['count'], 'first_ts': rec['ts'],
                    'connection_status': conn_status,
                    'connection_established':
                        conn_status == 'established',
                    'bytes_exchanged': bytes_exchanged,
                },
                'recommendation': (
                    f'Acesso a \\PIPE\\{pname} é assinatura clássica de '
                    'movimentação lateral (PsExec, schtasks, registry mining, '
                    'SAM dump). Correlacione com autenticação Kerberos / NTLM '
                    'do mesmo host e isole se não-autorizado.'
                ),
            })
        return alerts

    # Remote-execution pipes vs remote-admin vs pipes every domain member
    # uses all day (lsarpc name lookups, netlogon secure channel, samr
    # password changes, srvsvc share listing in Explorer, spoolss printing).
    # Treating all of them as "high lateral movement" flooded AD networks.
    _PIPE_TIERS = {
        'svcctl': 'exec', 'atsvc': 'exec',
        'winreg': 'admin', 'eventlog': 'admin',
    }

    @classmethod
    def _pipe_tier(cls, pname):
        return cls._PIPE_TIERS.get(pname, 'routine')


class DcerpcBindStreamingDetector(StreamingDetector):
    """Flag DCERPC binds to notorious RPC interfaces over ncacn_ip_tcp.

    Diferente do fan-out na 135 (InternalLateral), que só pega varredura ampla,
    este inspeciona o conteúdo: um bind/alter-context à abstract syntax de
    interfaces abusadas (MS-EFSR/PetitPotam, MS-RPRN/PrinterBug, MS-DRSR/DCSync,
    svcctl, Task Scheduler...) já é acionável mesmo num único alvo. O UUID da
    interface é extraído pelo pkt_view a partir do bind parseado pelo scapy.
    """
    name = 'dcerpc_bind'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        from .. import constants as _c
        self._c = _c
        # (src, dst, uuid) → {count, ts}
        self.binds = {}
        # Hosts answering Kerberos (port 88) = domain controllers. Lets
        # finalize recognise DC<->DC replication (MS-DRSR is DCSync only
        # when the caller is NOT a DC).
        self.kdcs = set()

    # Interfaces with a routine legitimate use that context can confirm.
    _DRSR = 'e3514235-4b06-11d1-ab04-00c04fc2dcd2'
    _PRINT = {'12345678-1234-abcd-ef00-0123456789ab',   # MS-RPRN
              '76f03f96-cdfd-44fc-a22c-64950a001209'}   # MS-PAR

    def update(self, pkt):
        if IP not in pkt:
            return
        # Server side of Kerberos -> DC. SYN/any TCP or UDP to 88.
        try:
            if (TCP in pkt and int(pkt[TCP].dport) == 88) or \
                    (UDP in pkt and int(pkt[UDP].dport) == 88):
                if len(self.kdcs) < 1000:
                    self.kdcs.add(pkt[IP].dst)
        except Exception:
            pass
        if TCP not in pkt:
            return
        if DCERPC_BIND_LAYER is None or DCERPC_BIND_LAYER not in pkt:
            return
        try:
            uuids = pkt[DCERPC_BIND_LAYER].uuids or []
        except Exception:
            return
        src, dst = pkt[IP].src, pkt[IP].dst
        for u in uuids:
            if u not in self._c.DCERPC_DANGEROUS_INTERFACES:
                continue
            key = (src, dst, u)
            rec = self.binds.get(key)
            if rec is None:
                self.binds[key] = {'count': 1, 'ts': float(pkt.time)}
            else:
                rec['count'] += 1

    def finalize(self):
        alerts = []
        clients_per_server = defaultdict(set)
        for (src, dst, u) in self.binds:
            clients_per_server[(dst, u)].add(src)
        for (src, dst, u), rec in self.binds.items():
            label, severity, tech_id, tech_name, tac_id, tac_name = \
                self._c.DCERPC_DANGEROUS_INTERFACES[u]
            context = None
            if not self.analyzer._is_local_ip(src):
                severity = 'critical'
                context = 'origem externa à rede'
            elif u == self._DRSR and src in self.kdcs and dst in self.kdcs:
                # Both ends serve Kerberos: DC-to-DC replication, the
                # everyday use of DRSUAPI. DCSync = a NON-DC calling it.
                severity = 'low'
                context = ('origem e destino são controladores de domínio '
                           '(replicação AD normal)')
            elif (u in self._PRINT and dst not in self.kdcs
                  and len(clients_per_server[(dst, u)]) >= 3):
                # Since the 2021 PrintNightmare hardening Windows clients
                # print over RPC/TCP: MS-RPRN to a print server that serves
                # many clients is printing. PrinterBug coerces a DC or a
                # server that is NOT a shared print server.
                severity = 'low'
                context = (f'destino atende {len(clients_per_server[(dst, u)])} '
                           'clientes nesta interface (servidor de impressão)')
            description = (
                f'{src} → {dst} fez bind na interface DCERPC {label} '
                f'(UUID {u}) sobre ncacn_ip_tcp — {rec["count"]} bind(s). '
                'Fazer bind nesta interface é uma primitiva de abuso conhecida.'
            )
            if context:
                description += f' Contexto: {context}.'
            alerts.append({
                'severity': severity,
                'category': 'lateral',
                'title': f'DCERPC Bind to High-Risk Interface: {label}',
                'description': description,
                'ip': src,
                'details': {
                    'context': context,
                    'src': src, 'dst': dst,
                    'src_ip': src, 'dst_ip': dst,
                    'interface': label,
                    'interface_uuid': u,
                    'bind_count': rec['count'],
                    'first_ts': rec['ts'],
                },
                'recommendation': (
                    'Confirme se este RPC é legítimo (ex.: replicação entre DCs '
                    'para MS-DRSR, spool de impressão para MS-RPRN). Binds a '
                    'MS-EFSR/MS-RPRN a partir de hosts não-DC indicam coerção '
                    'de autenticação (PetitPotam/PrinterBug); MS-DRSR fora de '
                    'um DC indica DCSync. Restrinja RPC por firewall e audite.'
                ),
                'mitre_attack': {
                    'technique_id': tech_id,
                    'technique_name': tech_name,
                    'tactic_id': tac_id,
                    'tactic_name': tac_name,
                    'url': (
                        'https://attack.mitre.org/techniques/'
                        + tech_id.replace('.', '/') + '/'
                    ),
                },
            })
        return alerts


# Registro de detectores migrados para streaming. Cada classe roda durante a
# passada única sobre o arquivo (em update(pkt)) e emite alertas em finalize().
# A versão legada do mesmo detector é pulada em _run_detections (set
# STREAMING_DETECTOR_NAMES) para evitar alertas duplicados.
STREAMING_DETECTORS = [
    PortScanStreamingDetector,
    SuspiciousPortsStreamingDetector,
    ArpSpoofingStreamingDetector,
    ArpHostDiscoveryStreamingDetector,
    NdpSpoofingStreamingDetector,
    DnsTunnelingStreamingDetector,
    DnsCumulativeExfilStreamingDetector,
    InsecureProtocolsStreamingDetector,
    CleartextCredentialsStreamingDetector,
    ExternalSmbStreamingDetector,
    PingSweepStreamingDetector,
    HorizontalScanStreamingDetector,
    SnmpWalkStreamingDetector,
    LlmnrNbtnsStreamingDetector,
    IcmpTunnelingStreamingDetector,
    VolumeExfiltrationStreamingDetector,
    SustainedExfilRatioStreamingDetector,
    InternalLateralStreamingDetector,
    BeaconingStreamingDetector,
    ConnectionBeaconingStreamingDetector,
    KerberosAbuseStreamingDetector,
    BruteForceStreamingDetector,
    PasswordSprayingStreamingDetector,
    DgaStreamingDetector,
    FastFluxStreamingDetector,
    NxdomainSpikeStreamingDetector,
    SuspiciousTldStreamingDetector,
    DotStreamingDetector,
    PayloadEntropyCleartextStreamingDetector,
    ModernTunnelStreamingDetector,
    IcsProtocolStreamingDetector,
    OperationalExposureStreamingDetector,
    DcerpcBindStreamingDetector,
    CobaltStrikeDnsBeaconStreamingDetector,
]
STREAMING_DETECTOR_NAMES = frozenset(c.name for c in STREAMING_DETECTORS)

