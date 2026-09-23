"""
Post-aggregator detectors.

Unlike StreamingDetector (which observes packets one at a time during the
single load pass), these detectors run AFTER all streaming aggregators have
finalized. They consume precomputed state on the analyzer:

    self._tls_info          (TlsInfoAggregator)
    self._http_info         (HttpInfoAggregator)
    self._tls_certs         (TlsCertAggregator)
    self.results['ip_mac_mapping']  (MacIpAggregator)

Each detector implements run() -> list[Alert]. The orchestrator iterates over
POST_DETECTORS and collects emitted alerts.

Extracted from pcap_analyzer/_core.py.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime, timezone


class PostDetector:
    """Base class for post-aggregator detectors."""
    name = 'base'

    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.settings = analyzer.settings

    def run(self):
        return []


class IpMacChangesDetector(PostDetector):
    """IP seen with several source MACs (possible spoofing or DHCP churn).

    Two very common benign shapes are separated from the interesting one:

      * **Routed / gateway MACs.** On a SPAN of several VLANs (or any capture
        that sees routed traffic) a host's packets appear once with its own
        MAC and again, after routing, with the ROUTER's MAC. A router MAC is
        the source MAC of many IPs at once. When every extra MAC of an IP is
        such a multi-IP ("gateway-like") MAC, the alert drops to low.
      * **External IPs** always arrive via a gateway; several MACs mean
        several routers/HSRP/load-balanced egress -> low, informational.

    What remains (two device MACs for one local IP) is medium: DHCP
    reassignment and NIC swaps still produce it, and active poisoning is
    judged by the ARP/NDP spoofing detectors with stronger evidence.
    """
    name = 'ip_mac_changes'

    # A MAC used as source by at least this many IPs behaves like a router.
    GATEWAY_MAC_MIN_IPS = 4

    def run(self):
        alerts = []
        analyzer = self.analyzer
        ip_mac_history = analyzer.results.get('ip_mac_mapping') or {}
        mac_ips = defaultdict(set)
        for ip, macs in ip_mac_history.items():
            for m in macs or ():
                if m:
                    mac_ips[str(m).lower()].add(ip)
        gateway_macs = {m for m, ips in mac_ips.items()
                        if len(ips) >= self.GATEWAY_MAC_MIN_IPS}
        for ip, macs in ip_mac_history.items():
            if len(macs) <= 1:
                continue
            is_local = analyzer._is_local_ip(ip)
            lowered = [str(m).lower() for m in macs if m]
            device_macs = [m for m in lowered if m not in gateway_macs]
            gw_seen = [m for m in lowered if m in gateway_macs]
            if is_local:
                if len(device_macs) >= 2:
                    severity = 'medium'
                    note = (
                        'Mais de um MAC de dispositivo para o mesmo IP: '
                        'reatribuição DHCP, troca de placa/equipamento ou '
                        'spoofing de IP. Correlacione com alertas de ARP.'
                    )
                else:
                    severity = 'low'
                    note = (
                        'Os MACs extras são de roteador/gateway (cada um '
                        'aparece como origem de vários IPs) — típico de '
                        'captura com tráfego roteado ou SPAN de várias VLANs.'
                    )
                alerts.append({
                    'severity': severity,
                    'category': 'mac',
                    'title': 'IP with Multiple MAC Addresses',
                    'description': (
                        f'O IP local {ip} foi visto com {len(macs)} endereços '
                        f'MAC diferentes. {note}'
                    ),
                    'ip': ip,
                    'details': {
                        'mac_addresses': macs,
                        'mac_count': len(macs),
                        'device_macs': device_macs,
                        'gateway_like_macs': gw_seen,
                        'ip_type': 'local',
                    },
                    'recommendation': (
                        'Isto pode indicar spoofing de MAC, envenenamento ARP '
                        'ou a substituição de um dispositivo. Verifique a '
                        'legitimidade de todos os endereços MAC.'
                    ),
                })
            else:
                alerts.append({
                    'severity': 'low',
                    'category': 'mac',
                    'title': 'External IP with Multiple MAC Addresses',
                    'description': (
                        f'O IP externo {ip} foi visto com {len(macs)} endereços '
                        'MAC diferentes (pode ser roteamento normal)'
                    ),
                    'ip': ip,
                    'details': {
                        'mac_addresses': macs,
                        'mac_count': len(macs),
                        'ip_type': 'external',
                    },
                    'recommendation': (
                        'Isto costuma ser normal para IPs externos devido a '
                        'mudanças de roteamento. Monitore se o comportamento '
                        'for inesperado.'
                    ),
                })
        return alerts


class OldTlsVersionDetector(PostDetector):
    """Detect use of SSLv3, TLS 1.0 or TLS 1.1."""
    name = 'old_tls'

    def run(self):
        analyzer = self.analyzer
        tls = analyzer._tls_info
        if not tls:
            return []

        seen = defaultdict(set)
        for ch in tls.get('client_hellos') or []:
            v = ch.get('effective_version', ch.get('client_version'))
            if v in analyzer.OLD_TLS_VERSIONS:
                seen[(ch['src'], ch['dst'], v)].add(ch.get('sni') or '')
        for sh in tls.get('server_hellos') or []:
            v = sh.get('effective_version', sh.get('server_version'))
            if v in analyzer.OLD_TLS_VERSIONS:
                seen[(sh['dst'], sh['src'], v)].add('(server-confirmed)')

        alerts = []
        for (src, dst, version), snis in seen.items():
            version_name = analyzer.TLS_VERSIONS.get(version, f'0x{version:04x}')
            # A ClientHello capped at an old version only proves the client
            # is willing; the risk is real once the server AGREES. Legacy
            # clients offering 1.0 to a modern server that refuses (or picks
            # a newer version seen under another key) are hygiene, not
            # exposure.
            server_confirmed = '(server-confirmed)' in snis
            if server_confirmed:
                severity = 'high' if version == 0x0300 else 'medium'
            else:
                severity = 'low'
            alerts.append({
                'severity': severity,
                'category': 'tls',
                'title': f'Obsolete TLS Version: {version_name}',
                'description': (
                    f'Conexão TLS {src} -> {dst} negociou {version_name}'
                    if server_confirmed else
                    f'O cliente {src} ofereceu {version_name} a {dst} '
                    '(o servidor não confirmou a versão na captura)'
                ),
                'ip': src,
                'details': {
                    'src': src, 'dst': dst,
                    'version': version_name,
                    'version_raw': version,
                    'server_confirmed': server_confirmed,
                    'snis': sorted([s for s in snis
                                    if s and s != '(server-confirmed)'])[:5],
                },
                'recommendation': (
                    f'{version_name} está obsoleto e tem fraquezas '
                    'criptográficas conhecidas (POODLE, BEAST, ataques de '
                    'downgrade). Desative em ambos os lados; exija TLS 1.2+.'
                ),
            })
        return alerts


class SuspiciousSniDetector(PostDetector):
    """Detect SNI with suspicious patterns or ClientHello without SNI to
    external destinations."""
    name = 'suspicious_sni'

    def run(self):
        analyzer = self.analyzer
        tls = analyzer._tls_info
        if not tls:
            return []

        alerts = []
        seen_sni = set()
        no_sni_external = set()

        for ch in tls.get('client_hellos') or []:
            sni = ch.get('sni')
            src = ch['src']
            dst = ch['dst']
            dport = ch.get('dport')

            if not sni:
                if not analyzer._is_local_ip(dst):
                    no_sni_external.add((src, dst, dport))
                continue

            key = (src, sni)
            if key in seen_sni:
                continue
            seen_sni.add(key)

            reasons = []
            try:
                ipaddress.ip_address(sni)
                reasons.append('SNI é um literal de IP')
            except ValueError:
                pass

            if len(sni) > 100:
                reasons.append(f'SNI excessivamente longo ({len(sni)} caracteres)')

            label = analyzer._extract_dns_label(sni.lower())
            if label and len(label) >= 7:
                score = analyzer._dga_score(label)
                if score >= 0.7:
                    reasons.append(f'label de SNI parecido com DGA (score {score:.2f})')

            parts = sni.lower().split('.')
            if len(parts) >= 2 and parts[-1] in analyzer.SUSPICIOUS_TLDS:
                reasons.append(f'TLD suspeito .{parts[-1]}')

            if reasons:
                # A lone cheap-TLD or IP-literal SNI is common in legit
                # traffic (IoT, self-hosted services, .xyz/.top startups);
                # DGA-shaped labels or several stacked reasons are the C2
                # signal.
                is_dga = any(r.startswith('label de SNI parecido com DGA')
                             for r in reasons)
                is_ip = 'SNI é um literal de IP' in reasons
                if is_dga or len(reasons) >= 2:
                    sev = 'high'
                elif is_ip or reasons[0].startswith('SNI excessivamente'):
                    sev = 'medium'
                else:
                    sev = 'low'
                alerts.append({
                    'severity': sev,
                    'category': 'tls',
                    'title': 'Suspicious TLS SNI',
                    'description': (
                        f'Conexão TLS {src} -> {dst} com SNI suspeito: '
                        f'{sni}'
                    ),
                    'ip': src,
                    'details': {
                        'sni': sni,
                        'src': src, 'dst': dst, 'dport': dport,
                        'reasons': reasons,
                        'ja3_md5': ch.get('ja3_md5'),
                    },
                    'recommendation': (
                        'SNIs que são literais de IP, parecidos com DGA ou '
                        'excessivamente longos são comuns em C2 de malware. '
                        'Investigue esta conexão TLS e verifique o fingerprint '
                        'JA3.'
                    ),
                })

        for src, dst, dport in no_sni_external:
            # Many legit non-browser clients (VPN agents, update services,
            # IP-configured apps) omit SNI; keep it as a pivot, not a finding.
            alerts.append({
                'severity': 'low',
                'category': 'tls',
                'title': 'TLS ClientHello Without SNI',
                'description': (
                    f'TLS externo {src} -> {dst}:{dport} não enviou extensão SNI'
                ),
                'ip': src,
                'details': {'src': src, 'dst': dst, 'dport': dport},
                'recommendation': (
                    'Clientes legítimos modernos quase sempre enviam SNI. A '
                    'ausência pode indicar malware antigo, cliente '
                    'customizado/não-navegador ou conexão de C2 direto por IP.'
                ),
            })
        return alerts


class KnownBadJa3Detector(PostDetector):
    """Compare ClientHello JA3 fingerprints against malicious-fingerprint lists
    (built-in, user-supplied, and the SSLBL feed)."""
    name = 'known_bad_ja3'

    def run(self):
        analyzer = self.analyzer
        tls = analyzer._tls_info
        if not tls:
            return []

        bad = dict(analyzer.KNOWN_MALICIOUS_JA3)
        user_bad = analyzer.settings.get('known_malicious_ja3', {}) or {}
        if isinstance(user_bad, dict):
            bad.update(user_bad)
        try:
            from threat_intel import load_sslbl_ja3
            sslbl = load_sslbl_ja3() or {}
            for md5, desc in sslbl.items():
                bad.setdefault(md5, f"SSLBL: {desc}")
        except Exception as e:
            print(f"[pcap_analyzer] SSLBL JA3 feed unavailable: {e}")

        # Server-side corroboration: a ServerHello whose JA3S is itself on the
        # bad list. Several JA3 values attributed to CS/TrickBot are simply
        # the Windows schannel defaults, so a lone JA3 match is a strong
        # pivot but not proof; the (client JA3 + server JA3S) pair is.
        from ..constants import KNOWN_MALICIOUS_JA3S
        bad_s = dict(KNOWN_MALICIOUS_JA3S)
        user_bad_s = analyzer.settings.get('known_malicious_ja3s') or {}
        if isinstance(user_bad_s, dict):
            bad_s.update(user_bad_s)
        bad_ja3s_pairs = set()
        for sh in tls.get('server_hellos') or []:
            if sh.get('ja3s_md5') in bad_s:
                # ServerHello: src=server, dst=client.
                bad_ja3s_pairs.add((sh.get('dst'), sh.get('src')))

        from . import _apply_known_service_downgrade

        alerts = []
        seen = set()
        for ch in tls.get('client_hellos') or []:
            h = ch.get('ja3_md5')
            if not h or h not in bad:
                continue
            key = (ch['src'], ch['dst'], h)
            if key in seen:
                continue
            seen.add(key)
            label = bad[h]
            details = {
                'ja3_md5': h,
                'matches': label,
                'src': ch['src'],
                'dst': ch['dst'],
                'dport': ch.get('dport'),
                'sni': ch.get('sni'),
            }
            corroborated = (ch['src'], ch['dst']) in bad_ja3s_pairs
            details['ja3s_corroborated'] = corroborated
            if corroborated:
                severity = 'critical'
            else:
                severity = _apply_known_service_downgrade(
                    analyzer, ch['dst'], 'high', details)
                if details.get('known_service'):
                    # A mainstream platform answering a schannel-default JA3
                    # is the textbook collision, not C2.
                    severity = 'low'
            alerts.append({
                'severity': severity,
                'category': 'tls',
                'title': 'Known Malicious JA3 Fingerprint',
                'description': (
                    f'O handshake TLS do host {ch["src"]} corresponde ao JA3 de {label}'
                ),
                'ip': ch['src'],
                'details': details,
                'recommendation': (
                    f'O JA3 {h} está associado a {label}. Isole o host '
                    'imediatamente, preserve memória e disco para forense e '
                    'bloqueie o IP de destino.'
                    if corroborated else
                    f'O JA3 {h} está associado a {label}, mas JA3 sozinho '
                    'colide com stacks TLS comuns (ex.: schannel do Windows). '
                    'Confirme pelo destino (reputação, JA3S/JARM, SNI) e pelo '
                    'processo de origem antes de isolar o host.'
                ),
            })
        return alerts


class KnownBadJa3sDetector(PostDetector):
    """Onda 6 — B.6. Server-side counterpart to KnownBadJa3Detector.

    Matches ServerHello JA3S md5 against a small built-in dictionary plus
    operator-supplied entries via ``settings['known_malicious_ja3s']``. JA3S
    is less stable than JA3 (server stacks rev quickly) so the built-in list
    is intentionally small and the value of this detector grows with the
    operator's own intel.
    """
    name = 'known_bad_ja3s'

    def run(self):
        analyzer = self.analyzer
        tls = analyzer._tls_info
        if not tls:
            return []
        from ..constants import KNOWN_MALICIOUS_JA3S
        bad = dict(KNOWN_MALICIOUS_JA3S)
        user_bad = analyzer.settings.get('known_malicious_ja3s') or {}
        if isinstance(user_bad, dict):
            bad.update(user_bad)
        if not bad:
            return []

        alerts = []
        seen = set()
        for sh in tls.get('server_hellos') or []:
            h = sh.get('ja3s_md5')
            if not h or h not in bad:
                continue
            # ServerHello: src=server, dst=client.
            server_ip = sh.get('src')
            client_ip = sh.get('dst')
            sport = sh.get('sport')
            key = (server_ip, sport, h)
            if key in seen:
                continue
            seen.add(key)
            label = bad[h]
            alerts.append({
                'severity': 'high',
                'category': 'tls',
                'title': 'Known Malicious JA3S Fingerprint',
                'description': (
                    f'O handshake TLS do servidor {server_ip}:{sport} '
                    f'corresponde ao JA3S de {label} (md5 {h}).'
                ),
                'ip': client_ip or server_ip,
                'details': {
                    'ja3s_md5': h,
                    'matches': label,
                    'server_ip': server_ip,
                    'client_ip': client_ip,
                    'sport': sport,
                    'ja4s': sh.get('ja4s'),
                },
                'recommendation': (
                    f'O JA3S {h} ({label}) sugere que o servidor é um framework '
                    'de C2 com stack TLS padrão. Combine com a reputação do '
                    'destino e quaisquer hits do lado JA3 antes de bloquear.'
                ),
            })
        return alerts


class KnownBadJa4Detector(PostDetector):
    """Match TLS JA4 (client) and JA4S (server) fingerprints against known-bad
    lists. JA4 (FoxIO) is the modern successor to JA3 — more stable across
    library versions, so operator-supplied intel ages better. Built-in lists
    are small; extend via settings['known_malicious_ja4'] / ['..._ja4s'].
    """
    name = 'known_bad_ja4'

    def run(self):
        analyzer = self.analyzer
        tls = analyzer._tls_info
        if not tls:
            return []
        from ..constants import KNOWN_MALICIOUS_JA4, KNOWN_MALICIOUS_JA4S

        bad_ja4 = dict(KNOWN_MALICIOUS_JA4)
        user_ja4 = analyzer.settings.get('known_malicious_ja4') or {}
        if isinstance(user_ja4, dict):
            bad_ja4.update(user_ja4)
        bad_ja4s = dict(KNOWN_MALICIOUS_JA4S)
        user_ja4s = analyzer.settings.get('known_malicious_ja4s') or {}
        if isinstance(user_ja4s, dict):
            bad_ja4s.update(user_ja4s)
        if not bad_ja4 and not bad_ja4s:
            return []

        alerts = []
        seen = set()

        for ch in tls.get('client_hellos') or []:
            h = ch.get('ja4')
            if not h or h not in bad_ja4:
                continue
            key = ('ja4', ch.get('src'), ch.get('dst'), h)
            if key in seen:
                continue
            seen.add(key)
            label = bad_ja4[h]
            alerts.append({
                'severity': 'critical',
                'category': 'tls',
                'title': 'Known Malicious JA4 Fingerprint',
                'description': (
                    f'O ClientHello TLS do host {ch.get("src")} corresponde ao '
                    f'JA4 de {label} (JA4 {h}).'
                ),
                'ip': ch.get('src'),
                'details': {
                    'ja4': h,
                    'matches': label,
                    'src': ch.get('src'),
                    'dst': ch.get('dst'),
                    'dport': ch.get('dport'),
                    'sni': ch.get('sni'),
                    'ja3_md5': ch.get('ja3_md5'),
                },
                'recommendation': (
                    f'O JA4 {h} está associado a {label}. Isole o host, '
                    'preserve memória/disco para forense e bloqueie o '
                    'destino. O JA4 é mais estável que o JA3, então este '
                    'casamento tem maior confiança do que um hit de JA3 sozinho.'
                ),
            })

        for sh in tls.get('server_hellos') or []:
            h = sh.get('ja4s')
            if not h or h not in bad_ja4s:
                continue
            server_ip = sh.get('src')
            client_ip = sh.get('dst')
            key = ('ja4s', server_ip, sh.get('sport'), h)
            if key in seen:
                continue
            seen.add(key)
            label = bad_ja4s[h]
            alerts.append({
                'severity': 'high',
                'category': 'tls',
                'title': 'Known Malicious JA4S Fingerprint',
                'description': (
                    f'O ServerHello TLS do servidor {server_ip}:{sh.get("sport")} '
                    f'corresponde ao JA4S de {label} (JA4S {h}).'
                ),
                'ip': client_ip or server_ip,
                'details': {
                    'ja4s': h,
                    'matches': label,
                    'server_ip': server_ip,
                    'client_ip': client_ip,
                    'sport': sh.get('sport'),
                    'ja3s_md5': sh.get('ja3s_md5'),
                },
                'recommendation': (
                    f'O JA4S {h} ({label}) sugere que o servidor roda um '
                    'framework de C2 com stack TLS padrão. Combine com a '
                    'reputação do destino e quaisquer hits de JA4 do lado '
                    'cliente antes de bloquear.'
                ),
            })
        return alerts


class AlpnPortInconsistencyDetector(PostDetector):
    """Onda 6 — B.6. ALPN-vs-port consistency.

    Legitimate HTTP/2 or HTTP/3 traffic lives on well-known web ports (80,
    443, 8080, 8443, ...). When a TLS handshake on, say, port 25, 53, 587,
    or 3306 advertises `h2` ALPN, that is anomalous and often a sign of
    protocol tunneling / C2-over-TLS through a port that the operator's
    egress rules treat as benign.
    """
    name = 'alpn_port_inconsistency'

    def run(self):
        analyzer = self.analyzer
        tls = analyzer._tls_info
        if not tls:
            return []
        from ..constants import (
            ALPN_HTTP_TOKENS,
            ALPN_WEB_OK_PORTS,
            ALPN_INCONSISTENCY_PORTS,
        )
        alerts = []
        seen = set()
        # Both ClientHello and ServerHello carry ALPN; ServerHello is the
        # ground truth (server-chosen). Fall back to ClientHello if needed.
        sh_by_flow = {}
        for sh in tls.get('server_hellos') or []:
            key = (sh.get('src'), sh.get('sport'),
                   sh.get('dst'), sh.get('dport'))
            sh_by_flow[key] = sh

        for ch in tls.get('client_hellos') or []:
            dport = ch.get('dport')
            if dport is None:
                continue
            if dport in ALPN_WEB_OK_PORTS:
                continue
            if dport not in ALPN_INCONSISTENCY_PORTS:
                continue
            # Prefer server-side ALPN if available.
            flow_key = (ch.get('dst'), dport, ch.get('src'), ch.get('sport'))
            chosen = sh_by_flow.get(flow_key, {}).get('alpn') or []
            client_alpn = ch.get('alpn') or []
            advertised = set(p.lower() for p in chosen) or set(
                p.lower() for p in client_alpn
            )
            hits = advertised & ALPN_HTTP_TOKENS
            if not hits:
                continue
            # Treat http/1.1 on mail-submission as benign noise (some MTAs do
            # send Upgrade-style hints) — require h2/h3 to fire.
            if hits == {'http/1.1'}:
                continue
            key = (ch['src'], ch['dst'], dport, frozenset(hits))
            if key in seen:
                continue
            seen.add(key)
            alerts.append({
                'severity': 'high',
                'category': 'tls',
                'title': 'ALPN/Port Inconsistency',
                'description': (
                    f'TLS {ch["src"]} -> {ch["dst"]}:{dport} negociou ALPN '
                    f'{sorted(hits)} em uma porta não-web. Possível tunelamento '
                    'de protocolo ou C2 sobre TLS.'
                ),
                'ip': ch['src'],
                'details': {
                    'src': ch['src'], 'dst': ch['dst'], 'dport': dport,
                    'alpn_chosen': chosen,
                    'alpn_offered': client_alpn,
                    'sni': ch.get('sni'),
                    'ja3_md5': ch.get('ja3_md5'),
                },
                'recommendation': (
                    'h2/h3 sobre uma porta de serviço não-web é altamente '
                    'incomum. Inspecione o destino, decodifique o payload se '
                    'possível e bloqueie na saída se não for justificado por '
                    'uma aplicação conhecida.'
                ),
            })
        return alerts


class ScannerUserAgentDetector(PostDetector):
    """Detect HTTP User-Agents of known scanners / offensive tools."""
    name = 'scanner_ua'

    # Exploitation / credential-attack tools.
    EXPLOIT_SIGS = frozenset({
        'sqlmap', 'havij', 'sqlninja', 'hydra', 'metasploit', 'wpscan',
        'nuclei',
    })
    # Vulnerability scanners and content brute-forcers.
    VULN_SIGS = frozenset({
        'nikto', 'nessus', 'acunetix', 'arachni', 'w3af', 'xspider',
        'paros', 'gobuster', 'dirb', 'dirbuster', 'wfuzz', 'feroxbuster',
    })
    # Fingerprinting / port-level recon.
    RECON_SIGS = frozenset({'nmap', 'masscan', 'zgrab', 'whatweb'})

    @classmethod
    def _tier(cls, sig):
        if sig in cls.EXPLOIT_SIGS:
            return 'exploit'
        if sig in cls.VULN_SIGS:
            return 'vuln'
        if sig in cls.RECON_SIGS:
            return 'recon'
        # Crawlers (mj12bot) and unknown/user-added signatures.
        return 'crawler' if sig.endswith('bot') else 'vuln'

    def run(self):
        analyzer = self.analyzer
        http = analyzer._http_info
        if not http:
            return []

        by_src = defaultdict(set)
        empty_ua_external = defaultdict(set)

        for req in http.get('requests') or []:
            ua = req.get('user_agent') or ''
            ua_lower = ua.lower()
            src = req['src']
            dst = req['dst']

            if not ua_lower:
                if not analyzer._is_local_ip(dst):
                    empty_ua_external[src].add(
                        (dst, req.get('host', ''), req.get('path', '')[:120]),
                    )
                continue

            for sig in analyzer.SCANNER_USER_AGENTS:
                if sig in ua_lower:
                    by_src[src].add((sig, ua))
                    break

        alerts = []
        for src, hits in by_src.items():
            sigs = sorted({h[0] for h in hits})
            sample_uas = sorted({h[1] for h in hits})[:5]
            # A UA string is a claim, not an exploit: the tool class and the
            # direction decide how loud it is. Internet-wide recon (zgrab,
            # masscan) hits every public IP daily; the same tool from an
            # internal host is internal reconnaissance.
            src_local = analyzer._is_local_ip(src)
            tiers = {self._tier(sig) for sig in sigs}
            if tiers & {'exploit', 'vuln'}:
                severity = 'high'
            elif 'recon' in tiers:
                severity = 'high' if src_local else 'medium'
            else:
                severity = 'low'
            alerts.append({
                'severity': severity,
                'category': 'http',
                'title': 'Security Scanner User-Agent',
                'description': (
                    f'O host {src} enviou requisições HTTP com UA(s) de '
                    f'scanner: {", ".join(sigs)}'
                ),
                'ip': src,
                'details': {
                    'src': src,
                    'matched_signatures': sigs,
                    'tool_classes': sorted(tiers),
                    'src_local': src_local,
                    'sample_user_agents': sample_uas,
                },
                'recommendation': (
                    'Scanner de vulnerabilidades detectado. Se não autorizado: '
                    'bloqueie a origem e revise os logs em busca de exploração '
                    'bem-sucedida. Se sancionado (pentest), confirme o escopo.'
                ),
            })

        for src, targets in empty_ua_external.items():
            sample = sorted(targets)[:5]
            alerts.append({
                'severity': 'medium',
                'category': 'http',
                'title': 'HTTP Request Without User-Agent',
                'description': (
                    f'O host {src} enviou requisição(ões) HTTP para destino '
                    'externo sem cabeçalho User-Agent'
                ),
                'ip': src,
                'details': {
                    'src': src,
                    'count': len(targets),
                    'samples': [
                        {'dst': d, 'host': h, 'path': p}
                        for d, h, p in sample
                    ],
                },
                'recommendation': (
                    'A maioria dos clientes legítimos envia um User-Agent. A '
                    'ausência frequentemente indica malware codificado sob '
                    'medida, sondagem manual ou ataques por script.'
                ),
            })
        return alerts


class ExploitPathsDetector(PostDetector):
    """Detect requests to sensitive paths or known exploit URLs."""
    name = 'exploit_paths'

    # Generic file names that SPAs / apps legitimately serve from asset
    # folders (/assets/config.json). Only the ROOT copy is the classic
    # secrets-leak probe.
    ROOT_ONLY = frozenset({'/config.json', '/config.yaml'})
    # File names that must end at a path boundary so '/web.config' does not
    # match '/web.configuration/'. A following '.', '~' or '%' is kept: those
    # are the backup-copy probes (wp-config.php.bak, wp-config.php~).
    _BOUNDARY_OK = frozenset('/?#;.~%')

    @classmethod
    def _path_hit(cls, ep, path_lower):
        if ep in cls.ROOT_ONLY:
            path_only = path_lower.split('?', 1)[0].split('#', 1)[0]
            return path_only == ep or (
                path_only.startswith(ep)
                and path_only[len(ep)] in cls._BOUNDARY_OK)
        start = path_lower.find(ep)
        if start < 0:
            return False
        # Directory / prefix probes (/.git/, /swagger, /jenkins) keep plain
        # substring semantics; only FILE names need a boundary.
        if ep.endswith('/') or '.' not in ep.rsplit('/', 1)[-1]:
            return True
        # Check every occurrence for a boundary after the match.
        while start >= 0:
            end = start + len(ep)
            if end == len(path_lower) or path_lower[end] in cls._BOUNDARY_OK:
                return True
            start = path_lower.find(ep, start + 1)
        return False

    def run(self):
        analyzer = self.analyzer
        http = analyzer._http_info
        if not http:
            return []

        by_src = defaultdict(
            lambda: {'high': set(), 'medium': set(), 'low': set()})
        for req in http.get('requests') or []:
            path = req.get('path', '')
            path_lower = path.lower()
            host = req.get('host', '')
            method = req.get('method', '')
            src = req['src']

            matched = False
            for ep in analyzer.EXPLOIT_PATHS_HIGH:
                if self._path_hit(ep, path_lower):
                    by_src[src]['high'].add((path[:200], host, method))
                    matched = True
                    break
            if matched:
                continue
            for ep in analyzer.EXPLOIT_PATHS_MEDIUM:
                if self._path_hit(ep, path_lower):
                    # An internal user opening /wp-admin/ or /phpmyadmin on
                    # an EXTERNAL site is most often administering their own
                    # hosted site, not attacking it.
                    outbound = (analyzer._is_local_ip(src)
                                and not analyzer._is_local_ip(req.get('dst')))
                    bucket = 'low' if outbound else 'medium'
                    by_src[src][bucket].add((path[:200], host, method))
                    break

        alerts = []
        for src, sev_map in by_src.items():
            for severity, hits in sev_map.items():
                if not hits:
                    continue
                sample = sorted(hits)[:5]
                alerts.append({
                    'severity': severity,
                    'category': 'http',
                    'title': 'HTTP Request to Sensitive/Exploit Path',
                    'description': (
                        f'O host {src} requisitou {len(hits)} caminho(s) '
                        'sensível(is)/de exploração'
                    ),
                    'ip': src,
                    'details': {
                        'src': src,
                        'severity_class': severity,
                        'count': len(hits),
                        'samples': [
                            {'method': m, 'host': h, 'path': p}
                            for p, h, m in sample
                        ],
                    },
                    'recommendation': (
                        'Esses caminhos miram vulnerabilidades conhecidas ou '
                        'recursos sensíveis (.env, .git, web shells, painéis de '
                        'admin). Verifique se é teste autorizado ou bloqueie a '
                        'origem e revise os logs do servidor por acesso '
                        'bem-sucedido.'
                    ),
                })
        return alerts


class UnusualHttpMethodDetector(PostDetector):
    """Detect rarely-legitimate HTTP methods (TRACE/TRACK/CONNECT/WebDAV)."""
    name = 'unusual_http_method'

    UNUSUAL_METHODS = {
        'TRACE', 'TRACK', 'CONNECT', 'PROPFIND', 'PROPPATCH',
        'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK',
    }

    def run(self):
        http = self.analyzer._http_info
        if not http:
            return []

        by = defaultdict(set)
        for req in http.get('requests') or []:
            method = req.get('method', '')
            if method in self.UNUSUAL_METHODS:
                by[(req['src'], method)].add(req.get('path', '')[:200])

        alerts = []
        for (src, method), paths in by.items():
            if method in ('TRACE', 'TRACK'):
                severity = 'high'
                tip = ('Usado em ataques de Cross-Site Tracing (XST). Desative '
                       'nos servidores web.')
            elif method == 'CONNECT':
                severity = 'high'
                tip = ('Pode indicar abuso de proxy / tentativa de open-relay '
                       'ou tunelamento.')
            else:
                severity = 'medium'
                tip = ('Métodos WebDAV são frequentemente explorados '
                       '(CVE-2017-7269 etc.). Desative se não forem necessários.')
            alerts.append({
                'severity': severity,
                'category': 'http',
                'title': f'Unusual HTTP Method: {method}',
                'description': (
                    f'O host {src} usou o método {method} '
                    f'({len(paths)} requisição(ões))'
                ),
                'ip': src,
                'details': {
                    'src': src,
                    'method': method,
                    'count': len(paths),
                    'paths_sample': sorted(paths)[:5],
                },
                'recommendation': tip,
            })
        return alerts


class HttpInjectionDetector(PostDetector):
    """Detect classic injection signatures (Log4Shell, SQLi, XSS, LFI,
    command injection) in HTTP path, headers or body."""
    name = 'http_injection'

    def run(self):
        analyzer = self.analyzer
        http = analyzer._http_info
        if not http:
            return []

        from . import _SEV_LADDER

        hits = defaultdict(lambda: defaultdict(set))
        for req in http.get('requests') or []:
            path = req.get('path', '') or ''
            headers = req.get('headers_sample', '') or ''
            body = req.get('body_sample', '') or ''
            head = path + ' \n ' + headers
            full = head + ' \n ' + body
            full_lower = full.lower()
            head_len = len(head)
            # Client -> external site: the internal host is the would-be
            # ATTACKER only if it is compromised or a pentest box; far more
            # often it is a browser/app sending odd-looking but benign data.
            outbound = (analyzer._is_local_ip(req['src'])
                        and not analyzer._is_local_ip(req.get('dst')))

            for pat, sev, label in analyzer.INJECTION_PATTERNS:
                # Markup in a request BODY is ordinary (CMS editors, webmail,
                # form posts with HTML); reflected XSS lives in the URL or
                # headers, so XSS patterns only count there.
                haystack = (full_lower[:head_len] if label == 'XSS'
                            else full_lower)
                idx = haystack.find(pat)
                if idx < 0:
                    continue
                excerpt = full[max(0, idx - 30):idx + len(pat) + 60]
                excerpt = excerpt.replace('\r', ' ').replace('\n', ' ')
                hits[(label, sev, outbound)][req['src']].add(excerpt[:200])

        alerts = []
        for (label, base_sev, outbound), src_map in hits.items():
            sev = base_sev
            if outbound and sev != 'critical' and sev in _SEV_LADDER:
                sev = _SEV_LADDER[max(1, _SEV_LADDER.index(sev) - 1)]
            for src, excerpts in src_map.items():
                sample = list(excerpts)[:3]
                alerts.append({
                    'severity': sev,
                    'category': 'http',
                    'title': f'HTTP Attack Pattern: {label}',
                    'description': (
                        f'O host {src} enviou {len(excerpts)} requisição(ões) '
                        f'HTTP correspondendo a {label}'
                    ),
                    'ip': src,
                    'details': {
                        'src': src,
                        'pattern_class': label,
                        'outbound': outbound,
                        'severity_original': base_sev,
                        'occurrences': len(excerpts),
                        'samples': sample,
                    },
                    'recommendation': (
                        f'Investigue {src} imediatamente. {label} indica '
                        'tentativa de exploração; preserve os logs do servidor, '
                        'verifique se houve resposta bem-sucedida (2xx/5xx) e '
                        'bloqueie a origem se for externa.'
                    ),
                })
        return alerts


class FileShareUploadDetector(PostDetector):
    """Detect connections to file-share / paste services via HTTP Host or
    TLS SNI."""
    name = 'file_share'

    def run(self):
        analyzer = self.analyzer
        by_src = defaultdict(set)

        if analyzer._http_info:
            for req in analyzer._http_info.get('requests') or []:
                host = (req.get('host') or '').lower().strip()
                if not host:
                    continue
                for fs in analyzer.FILE_SHARE_HOSTS:
                    if host == fs or host.endswith('.' + fs):
                        by_src[req['src']].add(
                            (host, 'http', req.get('method', '')),
                        )
                        break

        if analyzer._tls_info:
            for ch in analyzer._tls_info.get('client_hellos') or []:
                sni = (ch.get('sni') or '').lower().strip()
                if not sni:
                    continue
                for fs in analyzer.FILE_SHARE_HOSTS:
                    if sni == fs or sni.endswith('.' + fs):
                        by_src[ch['src']].add((sni, 'tls', ''))
                        break

        alerts = []
        for src, hits in by_src.items():
            sample = sorted(hits)[:5]
            # Visible upload verbs make it an exfil candidate; a bare TLS
            # connection (or a GET) is just someone opening a shared link.
            uploads = any(m.upper() in ('POST', 'PUT') for _h, _v, m in hits)
            alerts.append({
                'severity': 'medium' if uploads else 'low',
                'category': 'exfil',
                'title': 'Connection to File-Share / Paste Service',
                'description': (
                    f'O host {src} conectou-se a {len(hits)} serviço(s) de '
                    'compartilhamento/paste de arquivos'
                ),
                'ip': src,
                'details': {
                    'src': src,
                    'count': len(hits),
                    'upload_seen': uploads,
                    'samples': [
                        {'host': h, 'via': v, 'method': m}
                        for h, v, m in sample
                    ],
                },
                'recommendation': (
                    'Serviços de compartilhamento/paste de arquivos são canais '
                    'comuns de exfiltração. Verifique se o upload foi '
                    'autorizado e considere bloquear esses domínios via '
                    'DNS/proxy.'
                ),
            })
        return alerts


def _cert_matches_sni(cert, sni):
    """True if `sni` is covered by the cert's CN or any SAN (wildcards
    honored). Case-insensitive."""
    if not sni or not cert:
        return False
    sni = sni.lower().strip().rstrip('.')
    candidates = [cert.get('cn', '')] + list(cert.get('sans') or [])
    for name in candidates:
        if not name:
            continue
        n = name.lower().strip().rstrip('.')
        if not n:
            continue
        if n == sni:
            return True
        if n.startswith('*.'):
            # RFC 6125 §6.4.3: the wildcard covers exactly ONE label —
            # *.example.com matches a.example.com but NOT a.b.example.com
            # (fnmatch's '*' crossed dots, silently accepting deeper names
            # and hiding real mismatches).
            sni_parts = sni.split('.', 1)
            if len(sni_parts) == 2 and sni_parts[0] and sni_parts[1] == n[2:]:
                return True
    return False


def _cert_same_zone(cert, sni):
    """True if the SNI and some CN/SAN of the cert share the registrable
    zone (www.example.com vs api.example.com). That shape is almost always a
    virtual-host / cert-rotation misconfiguration of the SAME operator, not
    interception or fronting."""
    from ..constants import base_zone
    if not sni or not cert:
        return False
    sni_zone = base_zone(sni.lower().strip().rstrip('.').split('.'))
    for name in [cert.get('cn', '')] + list(cert.get('sans') or []):
        n = (name or '').lower().strip().rstrip('.')
        if n.startswith('*.'):
            n = n[2:]
        if n and base_zone(n.split('.')) == sni_zone:
            return True
    return False


def _parse_iso(ts):
    if not ts:
        return None
    try:
        # Python's fromisoformat handles "+00:00" but not trailing 'Z'.
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception:
        return None


class TlsCertificateDetector(PostDetector):
    """Inspect X.509 certificates collected by TlsInfoAggregator and emit
    alerts for self-signed certs to external IPs, CN×SNI mismatch, expired /
    not-yet-valid certs, and Let's Encrypt certs on DGA-looking SNIs."""
    name = 'tls_cert'

    def __init__(self, analyzer):
        super().__init__(analyzer)
        # Correlate by 5-tuple (server side): the server's src/sport identifies
        # the flow. For each ClientHello in the matching reverse direction we
        # can look up the SNI the client asked for.
        self._sni_by_server = None

    def _build_sni_index(self):
        idx = {}
        tls = self.analyzer._tls_info or {}
        for ch in tls.get('client_hellos') or []:
            sni = ch.get('sni')
            if not sni:
                continue
            # ClientHello src=client, dst=server. Match on (server_ip, port).
            key = (ch.get('dst'), ch.get('dport'))
            idx.setdefault(key, sni)
        self._sni_by_server = idx

    def _sni_for(self, cert_entry):
        if self._sni_by_server is None:
            self._build_sni_index()
        # Certificate src=server, sport=server_port.
        key = (cert_entry.get('src'), cert_entry.get('sport'))
        return self._sni_by_server.get(key)

    def run(self):
        analyzer = self.analyzer
        tls = analyzer._tls_info
        if not tls:
            return []
        cert_entries = tls.get('certificates') or []
        if not cert_entries:
            return []

        alerts = []
        seen_self_signed = set()
        seen_mismatch = set()
        seen_expired = set()
        seen_dga_le = set()

        now = datetime.now(timezone.utc)

        for entry in cert_entries:
            chain = entry.get('chain') or []
            if not chain:
                continue
            leaf = chain[0]
            server_ip = entry.get('src') or ''
            client_ip = entry.get('dst') or ''
            sni = self._sni_for(entry)

            # --- 1) Self-signed cert to external IP -------------------------
            if (leaf.get('self_signed')
                    and not analyzer._is_local_ip(server_ip)):
                key = (server_ip, leaf.get('fingerprint_sha256'))
                if key not in seen_self_signed:
                    seen_self_signed.add(key)
                    # Self-signed external certs are also routine on
                    # appliances, VPN concentrators and dev endpoints; the
                    # stronger C2 shapes (IP-only SAN, DGA SNI, bad JA3S) are
                    # judged by their own rules.
                    alerts.append({
                        'severity': 'medium',
                        'category': 'tls',
                        'title': 'Self-Signed TLS Certificate (external)',
                        'description': (
                            f'O servidor TLS externo {server_ip}'
                            f'{(":" + str(entry.get("sport"))) if entry.get("sport") else ""} '
                            f'apresentou um certificado autoassinado '
                            f'(CN={leaf.get("cn") or "?"})'
                        ),
                        'ip': client_ip or server_ip,
                        'details': {
                            'server_ip': server_ip,
                            'server_port': entry.get('sport'),
                            'client_ip': client_ip,
                            'sni': sni,
                            'cn': leaf.get('cn'),
                            'issuer_cn': leaf.get('issuer_cn'),
                            'sans': leaf.get('sans')[:10] if leaf.get('sans') else [],
                            'not_before': leaf.get('not_before'),
                            'not_after': leaf.get('not_after'),
                            'fingerprint_sha256': leaf.get('fingerprint_sha256'),
                        },
                        'recommendation': (
                            'Serviços expostos publicamente raramente '
                            'apresentam certificados autoassinados. Causas '
                            'comuns: C2 de malware com certificados '
                            'descartáveis, kits de phishing ou painéis de admin '
                            'mal configurados. Verifique o destino e bloqueie '
                            'se não for confiável.'
                        ),
                    })

            # --- 2) CN/SAN ↔ SNI mismatch ----------------------------------
            if sni and (leaf.get('cn') or leaf.get('sans')):
                if not _cert_matches_sni(leaf, sni):
                    key = (server_ip, sni, leaf.get('fingerprint_sha256'))
                    if key not in seen_mismatch:
                        seen_mismatch.add(key)
                        same_zone = _cert_same_zone(leaf, sni)
                        alerts.append({
                            'severity': 'medium' if same_zone else 'high',
                            'category': 'tls',
                            'title': 'TLS Certificate / SNI Mismatch',
                            'description': (
                                f'O cliente pediu o SNI "{sni}" mas o servidor '
                                f'{server_ip} apresentou um certificado para '
                                f'CN={leaf.get("cn") or "?"} '
                                f'(SANs: '
                                f'{", ".join((leaf.get("sans") or [])[:3]) or "nenhum"})'
                            ),
                            'ip': client_ip or server_ip,
                            'details': {
                                'server_ip': server_ip,
                                'client_ip': client_ip,
                                'sni': sni,
                                'cn': leaf.get('cn'),
                                'sans': leaf.get('sans')[:10] if leaf.get('sans') else [],
                                'same_registrable_zone': same_zone,
                                'fingerprint_sha256': leaf.get('fingerprint_sha256'),
                            },
                            'recommendation': (
                                'Uma divergência entre SNI e certificado pode '
                                'indicar domain fronting, um proxy de '
                                'interceptação ou uma CDN mal configurada. '
                                'Valide o destino; divergências inesperadas com '
                                'serviços externos merecem investigação.'
                            ),
                        })

            # --- 3) Expired or not-yet-valid -------------------------------
            # Validity is judged against the moment the certificate was SEEN
            # on the wire (packet timestamp), not the wall clock of the
            # analysis: re-analysing an old capture must not turn a cert that
            # was valid back then into an "expired" finding. Wall clock is only
            # the fallback when the entry carries no plausible timestamp
            # (devices without RTC write 1970-era stamps).
            seen_at = now
            try:
                ts = float(entry.get('ts') or 0)
                if ts >= 946684800:  # 2000-01-01
                    seen_at = datetime.fromtimestamp(ts, timezone.utc)
            except (TypeError, ValueError, OverflowError, OSError):
                pass
            nb = _parse_iso(leaf.get('not_before'))
            na = _parse_iso(leaf.get('not_after'))
            expired_reason = None
            if na and na < seen_at:
                expired_reason = f'expirou em {leaf.get("not_after")}'
            elif nb and nb > seen_at:
                expired_reason = (
                    f'ainda não é válido (começa em {leaf.get("not_before")})'
                )
            if expired_reason:
                key = (server_ip, leaf.get('fingerprint_sha256'))
                if key not in seen_expired:
                    seen_expired.add(key)
                    alerts.append({
                        'severity': 'medium',
                        'category': 'tls',
                        'title': 'Invalid TLS Certificate Validity Period',
                        'description': (
                            f'O servidor {server_ip} apresentou um certificado '
                            f'(CN={leaf.get("cn") or "?"}) que {expired_reason}'
                        ),
                        'ip': client_ip or server_ip,
                        'details': {
                            'server_ip': server_ip,
                            'client_ip': client_ip,
                            'sni': sni,
                            'cn': leaf.get('cn'),
                            'not_before': leaf.get('not_before'),
                            'not_after': leaf.get('not_after'),
                            'fingerprint_sha256': leaf.get('fingerprint_sha256'),
                        },
                        'recommendation': (
                            'Certificados fora da janela de validade aparecem '
                            'frequentemente em infraestrutura de C2 abandonada '
                            'ou em hosts com relógio/PKI quebrados. Investigue '
                            'e não coloque em whitelist.'
                        ),
                    })

            # --- 4b) Onda 6 (B.6): chain depth==1, SAN with only IP literals.
            # Real public services almost always ship a leaf + at least one
            # intermediate. A bare leaf whose only SAN is an IP literal is the
            # textbook profile of an opportunistic C2 cert (Sliver/MSF/...) or
            # an admin panel sitting unprotected on a raw IP. We require the
            # destination to be external — internal "depth=1 + IP-SAN" is
            # extremely common on home routers/printers/IPMI.
            if (len(chain) == 1
                    and not analyzer._is_local_ip(server_ip)
                    and (leaf.get('ip_sans') or [])
                    and not (leaf.get('sans') or [])):
                key = ('san_ip_depth1', server_ip,
                       leaf.get('fingerprint_sha256'))
                if key not in seen_self_signed:
                    seen_self_signed.add(key)
                    alerts.append({
                        'severity': 'high',
                        'category': 'tls',
                        'title': 'TLS Cert with IP-only SAN, no Intermediates',
                        'description': (
                            f'O servidor externo {server_ip} apresentou uma '
                            f'cadeia de certificado única (depth=1) cujas '
                            f'únicas entradas de SAN são literais de IP '
                            f'({", ".join(leaf.get("ip_sans") or [])[:120]}). '
                            'A PKI pública real raramente entrega folhas sem '
                            'intermediários; SANs só com IP são típicos de '
                            'defaults de frameworks de C2 (Sliver, Metasploit, '
                            'openssl req cru).'
                        ),
                        'ip': client_ip or server_ip,
                        'details': {
                            'server_ip': server_ip,
                            'client_ip': client_ip,
                            'sni': sni,
                            'cn': leaf.get('cn'),
                            'issuer_cn': leaf.get('issuer_cn'),
                            'ip_sans': leaf.get('ip_sans') or [],
                            'chain_depth': 1,
                            'fingerprint_sha256':
                                leaf.get('fingerprint_sha256'),
                        },
                        'recommendation': (
                            'Investigue o IP de destino em busca de '
                            'fingerprints de framework de C2 (JARM/JA3S, '
                            'banners padrão) e cruze com o seu inventário de '
                            'ativos. Bloqueie na saída se não for confiável.'
                        ),
                    })

            # --- 4) Let's Encrypt cert on DGA-looking SNI ------------------
            if leaf.get('is_lets_encrypt') and sni:
                label = analyzer._extract_dns_label(sni.lower())
                if label and len(label) >= 7:
                    score = analyzer._dga_score(label)
                    if score >= 0.7:
                        key = (sni, leaf.get('fingerprint_sha256'))
                        if key not in seen_dga_le:
                            seen_dga_le.add(key)
                            alerts.append({
                                'severity': 'high',
                                'category': 'tls',
                                'title': "Let's Encrypt Certificate on DGA-like Domain",
                                'description': (
                                    f'O servidor {server_ip} está usando um '
                                    f'certificado gratuito Let\'s Encrypt para '
                                    f'um SNI com aparência de gerado por '
                                    f'algoritmo "{sni}" (score DGA {score:.2f})'
                                ),
                                'ip': client_ip or server_ip,
                                'details': {
                                    'server_ip': server_ip,
                                    'client_ip': client_ip,
                                    'sni': sni,
                                    'dga_score': round(score, 3),
                                    'issuer_cn': leaf.get('issuer_cn'),
                                    'not_after': leaf.get('not_after'),
                                    'fingerprint_sha256': leaf.get('fingerprint_sha256'),
                                },
                                'recommendation': (
                                    "CAs gratuitas e de curta duração como a "
                                    "Let's Encrypt são rotineiramente abusadas "
                                    'por operadores de malware em domínios DGA '
                                    '/ descartáveis. Combine com dados de '
                                    'reputação do IP de destino antes de '
                                    'colocar em whitelist.'
                                ),
                            })

        return alerts


class HighVolumeQuicNewDestDetector(PostDetector):
    """Raise a medium-severity alert when a local host shipped a meaningful
    volume of QUIC bytes to an external destination that has never been
    observed in prior scans.

    QUIC traffic is encrypted from the first byte — there is no SNI, no
    cleartext certificate, and most flow-based detection is blind to it.
    Combining "first time we see this server" with "non-trivial volume"
    surfaces the case where commodity / unsanctioned services start being
    reached over HTTP/3, which is what melhorias.md C.10 explicitly asks
    for: "Pelo menos detectar 'alto volume QUIC para destino novo'".

    Thresholds come from settings.thresholds and tolerate absence:
        quic_high_volume_bytes      (default 5 MiB)
        quic_high_volume_packets    (default 200)
        quic_new_dest_max_alerts    (default 10)

    Cross-scan newness is read from the artifact_seen table — the same
    mechanism correlation.detect_new_artifacts uses, keyed under
    'quic_dest'. On day 1 (no prior scans) we still emit alerts because the
    "first-seen alone" guard already lives in correlation.py for the new-
    artifact card; here the signal is volume-driven and we don't want to
    swallow it just because the install is fresh.
    """
    name = 'quic_high_volume_new_dest'

    def run(self):
        analyzer = self.analyzer
        flows = (analyzer.results.get('quic_flows') or [])
        if not flows:
            return []

        thresholds = (self.settings.get('thresholds') or {})
        min_bytes = int(thresholds.get('quic_high_volume_bytes', 5 * 1024 * 1024))
        min_packets = int(thresholds.get('quic_high_volume_packets', 200))
        max_alerts = int(thresholds.get('quic_new_dest_max_alerts', 10))

        try:
            import database as db
            known = db.get_known_artifact_keys(types=['quic_dest'])
        except Exception as e:
            print(f"[quic_high_volume_new_dest] DB lookup failed: {e}")
            known = set()

        # Aggregate by destination IP (the same external server can be hit
        # by multiple local clients — we report one alert per server).
        per_dest = {}
        for flow in flows:
            dst = flow.get('dst')
            if not dst or flow.get('is_local_dst'):
                continue
            rec = per_dest.setdefault(dst, {
                'bytes': 0,
                'packets': 0,
                'sources': set(),
                'versions': set(),
            })
            rec['bytes'] += int(flow.get('bytes') or 0)
            rec['packets'] += int(flow.get('packets') or 0)
            if flow.get('src'):
                rec['sources'].add(flow['src'])
            for v in flow.get('versions') or []:
                rec['versions'].add(v)

        candidates = []
        for dst, rec in per_dest.items():
            if rec['bytes'] < min_bytes and rec['packets'] < min_packets:
                continue
            if ('quic_dest', dst) in known:
                continue
            candidates.append((dst, rec))

        from . import _apply_known_service_downgrade

        candidates.sort(key=lambda kv: kv[1]['bytes'], reverse=True)
        alerts = []
        for dst, rec in candidates[:max_alerts]:
            sources = sorted(rec['sources'])
            primary_src = sources[0] if sources else None
            details = {
                'destination': dst,
                'bytes': rec['bytes'],
                'packets': rec['packets'],
                'sources': sources,
                'versions': sorted(rec['versions']),
                'threshold_bytes': min_bytes,
                'threshold_packets': min_packets,
            }
            # YouTube/Google/Meta/Cloudflare-fronted HTTP/3 is the bulk of
            # QUIC volume; a destination named (via DNS/SNI) as a known
            # platform drops to low, annotated, instead of vanishing.
            severity = _apply_known_service_downgrade(
                analyzer, dst, 'medium', details)
            alerts.append({
                'severity': severity,
                'category': 'quic_high_volume_new_dest',
                'title': 'High-volume QUIC to new destination',
                'description': (
                    f"{rec['bytes']:,} bytes ({rec['packets']:,} pacotes) de "
                    f"tráfego QUIC/HTTP3 para o servidor {dst}, nunca visto "
                    f"antes, de {len(sources)} host(s) local(is). O QUIC é "
                    f"opaco para a maioria da inspeção de fluxo — volume para "
                    f"um destino novo merece um olhar mais atento."
                ),
                'ip': primary_src or dst,
                'details': details,
                'recommendation': (
                    "Identifique o domínio resolvido (correlacione com DNS / "
                    "SNI de fluxos TCP concomitantes), confirme se o "
                    "destino é um serviço aprovado (Cloudflare, "
                    "Google, Akamai, Microsoft 365) e considere uma "
                    "política que rebaixe QUIC não sancionado para TCP/443 "
                    "para que a inspeção continue funcionando."
                ),
                'mitre_attack': {
                    'technique_id': 'T1071.001',
                    'technique_name': 'Application Layer Protocol: Web Protocols',
                    'tactic_id': 'TA0011',
                    'tactic_name': 'Command and Control',
                    'url': 'https://attack.mitre.org/techniques/T1071/001/',
                },
            })
        return alerts


class DohDetector(PostDetector):
    """Detect DNS-over-HTTPS (DoH, RFC 8484) usage.

    DoH tunnels DNS resolution inside a regular TLS connection on port 443,
    making it invisible to every DNS-aware detector this analyzer ships
    (DGA, NXDOMAIN spike, suspicious TLD, fast-flux, tunneling). The point
    of this detector is to surface *that DoH is happening* so the operator
    can decide whether to allow it or force resolution through corporate
    DNS where the other detectors regain visibility.

    Signals, in order of confidence:
      1. ClientHello SNI matches a known DoH provider hostname (or its
         apex). Strongest signal — the SNI is what the client explicitly
         asked for.
      2. JA3 fingerprint in settings['known_doh_ja3'] (operator-supplied)
         or in the built-in (initially empty) KNOWN_DOH_JA3 map. Useful
         against malware that uses DoH with no/forged SNI.
      3. TLS connection to a known DoH provider IP on port 443 with no
         SNI. Lower confidence because the IP also serves general web
         traffic for some providers (e.g. Cloudflare 1.1.1.1 has a
         dashboard) — only emitted when SNI is absent.
      4. Plaintext HTTP(/1.1) request to a /dns-query path on a host
         matching DOH_HOSTS. Rare but valid (RFC 8484 §4.1 GET form).
    """
    name = 'doh'

    DOH_PORTS = {443}
    DOH_PATH_HINTS = ('/dns-query', '/resolve')

    def _user_doh_hosts(self):
        extra = self.settings.get('doh_hosts') or []
        if isinstance(extra, (list, tuple, set)):
            return {str(h).lower().strip().rstrip('.') for h in extra if h}
        return set()

    def _user_doh_ja3(self):
        extra = self.settings.get('known_doh_ja3') or {}
        if isinstance(extra, dict):
            return {str(k).lower(): str(v) for k, v in extra.items() if k}
        return {}

    @staticmethod
    def _host_matches(host, hosts):
        if not host:
            return None
        h = host.lower().strip().rstrip('.')
        if h in hosts:
            return h
        # Suffix match: x.cloudflare-dns.com → cloudflare-dns.com
        for known in hosts:
            if h.endswith('.' + known):
                return known
        return None

    def run(self):
        analyzer = self.analyzer
        tls = analyzer._tls_info or {}
        http = analyzer._http_info or {}

        known_hosts = set(analyzer.DOH_HOSTS) | self._user_doh_hosts()
        known_ips = set(analyzer.DOH_PROVIDER_IPS)
        known_ja3 = dict(analyzer.KNOWN_DOH_JA3)
        known_ja3.update(self._user_doh_ja3())

        alerts = []
        # Dedup by (src, server_endpoint, signal) so multiple ClientHellos in
        # the same flow collapse into one alert.
        seen = set()

        for ch in tls.get('client_hellos') or []:
            src = ch.get('src') or ''
            dst = ch.get('dst') or ''
            dport = ch.get('dport')
            sni = (ch.get('sni') or '').lower().strip().rstrip('.')
            ja3 = (ch.get('ja3_md5') or '').lower()

            if dport not in self.DOH_PORTS:
                # DoH is defined on 443; non-443 is out of scope and would
                # only add noise.
                continue

            signals = []
            matched_host = self._host_matches(sni, known_hosts)
            if matched_host:
                signals.append(('sni', matched_host))

            if ja3 and ja3 in known_ja3:
                signals.append(('ja3', known_ja3[ja3]))

            if not signals and not sni and dst in known_ips:
                signals.append(('ip_no_sni', dst))

            if not signals:
                continue

            method, evidence = signals[0]
            key = (src, dst, dport, method, evidence)
            if key in seen:
                continue
            seen.add(key)

            # Browsers and Windows 11 ship DoH to the big resolvers by
            # default: an SNI hit is a policy/visibility finding (low). A
            # provider IP reached WITHOUT SNI is not a browser shape (medium);
            # an operator-listed DoH JA3 is explicit intel (high).
            if method == 'sni':
                severity = 'low'
                desc = (
                    f'ClientHello TLS de {src} para {dst}:{dport} com SNI '
                    f'"{sni}" corresponde ao provedor DoH "{evidence}"'
                )
            elif method == 'ja3':
                severity = 'high'
                desc = (
                    f'ClientHello TLS de {src} para {dst}:{dport} corresponde '
                    f'ao JA3 de cliente DoH conhecido ({evidence})'
                )
            else:  # ip_no_sni
                severity = 'medium'
                desc = (
                    f'ClientHello TLS de {src} para {dst}:{dport} sem '
                    f'SNI; o IP de destino é um provedor DoH conhecido '
                    f'({evidence})'
                )

            alerts.append({
                'severity': severity,
                'category': 'dns',
                'title': 'DNS-over-HTTPS (DoH) Connection',
                'description': desc,
                'ip': src,
                'details': {
                    'src': src, 'dst': dst, 'dport': dport,
                    'sni': sni or None,
                    'ja3_md5': ch.get('ja3_md5'),
                    'signal': method,
                    'matched': evidence,
                    'provider_host': matched_host,
                },
                'recommendation': (
                    'O DoH contorna a visibilidade de DNS corporativo — os '
                    'detectores de DGA, pico de NXDOMAIN, fast-flux e '
                    'tunelamento ficam cegos à resolução que acontece dentro '
                    'deste fluxo TLS. Se o uso de DoH não for explicitamente '
                    'aprovado, bloqueie a saída para endpoints DoH públicos na '
                    '443 (por SNI ou IP) e force os clientes pelo resolver '
                    'corporativo. Navegadores (Firefox / Chrome / Edge) e o '
                    'DoH em nível de SO (Windows 11) suportam fallback para o '
                    'DNS do sistema.'
                ),
                'mitre_attack': {
                    'technique_id': 'T1071.004',
                    'technique_name': 'Application Layer Protocol: DNS',
                    'tactic_id': 'TA0011',
                    'tactic_name': 'Command and Control',
                    'url': 'https://attack.mitre.org/techniques/T1071/004/',
                },
            })

        # Plaintext HTTP DoH (rare): GET /dns-query?dns=... to a DoH host.
        for req in http.get('requests') or []:
            host = (req.get('host') or '').lower().strip().rstrip('.')
            path = (req.get('path') or '').lower()
            if not host or not path:
                continue
            matched_host = self._host_matches(host, known_hosts)
            if not matched_host:
                continue
            if not any(hint in path for hint in self.DOH_PATH_HINTS):
                continue
            src = req.get('src') or ''
            dst = req.get('dst') or ''
            key = (src, dst, 'http_path', matched_host)
            if key in seen:
                continue
            seen.add(key)
            alerts.append({
                'severity': 'high',
                'category': 'dns',
                'title': 'DNS-over-HTTPS (DoH) Connection',
                'description': (
                    f'O host {src} enviou um HTTP {req.get("method", "GET")} em '
                    f'texto claro para o endpoint DoH '
                    f'{host}{req.get("path", "")[:80]}'
                ),
                'ip': src,
                'details': {
                    'src': src, 'dst': dst,
                    'host': host, 'path': req.get('path', '')[:200],
                    'method': req.get('method'),
                    'signal': 'http_path',
                    'matched': matched_host,
                },
                'recommendation': (
                    'DoH em texto claro (HTTP, não HTTPS) é incomum — é ou um '
                    'cliente mal configurado ou um proxy deliberado. Inspecione '
                    'o host solicitante e force o DNS pelo resolver '
                    'corporativo.'
                ),
                'mitre_attack': {
                    'technique_id': 'T1071.004',
                    'technique_name': 'Application Layer Protocol: DNS',
                    'tactic_id': 'TA0011',
                    'tactic_name': 'Command and Control',
                    'url': 'https://attack.mitre.org/techniques/T1071/004/',
                },
            })

        return alerts


class CobaltStrikeDetector(PostDetector):
    """Detect Cobalt Strike malleable C2 default profiles.

    Cobalt Strike's Team Server, when staging beacons over HTTP, generates
    two URIs whose path characters sum (mod 256) to 92 (x86 stager) or
    93 (x64 stager) — the so-called *checksum8* trick. Because the actual
    URI strings are randomized per Team Server boot, signature-based
    blocklists miss them; the checksum is the invariant. Public reverse-
    engineering writeups (Cobalt Strike documentation §"Malleable C2",
    multiple Sophos/Trend/CISA reports) and the leaked 4.x source confirm
    this behavior.

    Beyond the stager checksum, this detector also flags:
      * Literal URI paths copy-pasted from public malleable profiles
        (jquery, amazon, gmail, havex, default) — see
        COBALT_STRIKE_DEFAULT_URIS.
      * Default User-Agent strings used by stock profiles.
      * Cobalt Strike JA3 fingerprints already labelled in
        KNOWN_MALICIOUS_JA3 — the KnownBadJa3 detector emits its own alert,
        but here we surface the *correlation* between a CS-labelled JA3
        and an HTTP request from the same host with checksum8 / UA hits,
        which is the more actionable signal.

    Confidence escalates with the number of independent signals on the
    same (src, dst) pair:
      1 signal  → medium
      2 signals → high
      3+        → critical
    MITRE ATT&CK: S0154 (Cobalt Strike), T1071.001, T1568.002.
    """
    name = 'cobalt_strike'

    # Stager URIs generated by the Team Server are short single-segment
    # random strings (default 4 alphanumeric chars). ~0.8% of ALL paths sum
    # to 92/93 mod 256, so without a shape gate a big capture of normal
    # browsing throws critical FPs; a directory, an extension dot, or a
    # long path means it is not a generated stager URI.
    _CHECKSUM8_MAX_LEN = 8

    @classmethod
    def _checksum8(cls, path):
        # Strip leading '/' and query string; sum char codes mod 256.
        # CS only checksums the path segment, not the query.
        if not path:
            return None
        p = path.split('?', 1)[0].split('#', 1)[0]
        if p.startswith('/'):
            p = p[1:]
        if not p:
            return None
        if '/' in p or '.' in p or len(p) > cls._CHECKSUM8_MAX_LEN:
            return None
        # CS uses 8-bit sum of all printable chars in the path. Empirically
        # the literature matches "sum of ord(c) for c in path % 256".
        return sum(ord(c) for c in p) & 0xFF

    def _cs_ja3_by_src(self):
        """Map src_ip → set of (ja3_md5, label) where the label calls out
        Cobalt Strike. Used to enrich HTTP-side findings."""
        out = defaultdict(set)
        tls = self.analyzer._tls_info or {}
        # Build a JA3 → label lookup, prioritizing built-in then user.
        bad = dict(self.analyzer.KNOWN_MALICIOUS_JA3)
        user_bad = self.settings.get('known_malicious_ja3') or {}
        if isinstance(user_bad, dict):
            bad.update(user_bad)
        for ch in tls.get('client_hellos') or []:
            h = ch.get('ja3_md5')
            if not h or h not in bad:
                continue
            label = bad[h]
            if 'cobalt' in label.lower() or label.lower() == 'beacon':
                out[ch.get('src') or ''].add((h, label))
        return out

    def run(self):
        analyzer = self.analyzer
        http = analyzer._http_info or {}
        requests = http.get('requests') or []
        if not requests and not (analyzer._tls_info or {}).get('client_hellos'):
            return []

        default_uris = {u.lower() for u in analyzer.COBALT_STRIKE_DEFAULT_URIS}
        cs_user_agents = analyzer.COBALT_STRIKE_USER_AGENTS
        cookie_hints = analyzer.COBALT_STRIKE_COOKIE_HINTS
        checksums = analyzer.COBALT_STRIKE_CHECKSUMS

        # Per (src, dst) bucket of signals so we can score combined evidence.
        # signals[(src,dst)] = {
        #   'checksum_hits': [(path, arch)],
        #   'uri_hits': [(path, host)],
        #   'ua_hits': [(ua_substr, ua)],
        #   'cookie_hits': [(snippet,)],
        # }
        signals = defaultdict(lambda: {
            'checksum_hits': [],
            'uri_hits': [],
            'ua_hits': [],
            'cookie_hits': [],
        })

        # Onda 6 — track the earliest timestamp of any checksum8 hit per
        # (src, dst) so the alert details surface the *first-seen* moment.
        # This is the most actionable forensic anchor: from the first
        # checksum8 callout you can walk lateral movement / persistence.
        first_checksum_ts = {}

        for req in requests:
            src = req.get('src') or ''
            dst = req.get('dst') or ''
            method = req.get('method') or ''
            path = req.get('path') or ''
            host = req.get('host') or ''
            ua = (req.get('user_agent') or '').lower()
            headers = (req.get('headers_sample') or '').lower()
            if not src or not path:
                continue

            key = (src, dst)
            rec = signals[key]

            # (1) checksum8 — only on GET to root-relative paths
            if method == 'GET':
                cs = self._checksum8(path)
                if cs in checksums:
                    rec['checksum_hits'].append((path[:200], checksums[cs]))
                    ts = req.get('ts') or req.get('first_ts') or 0.0
                    try:
                        ts_f = float(ts)
                    except (TypeError, ValueError):
                        ts_f = 0.0
                    if ts_f and (key not in first_checksum_ts
                                 or ts_f < first_checksum_ts[key]):
                        first_checksum_ts[key] = ts_f

            # (2) literal default URI (case-insensitive, exact path match;
            # query string stripped so /submit.php?id=... still matches the
            # default /submit.php).
            path_only = path.split('?', 1)[0].lower()
            if path_only in default_uris:
                rec['uri_hits'].append((path[:200], host))

            # (3) default User-Agent
            if ua:
                for sig in cs_user_agents:
                    if sig in ua:
                        rec['ua_hits'].append((sig, req.get('user_agent', '')))
                        break

            # (4) cookie hints in request headers
            if 'cookie:' in headers:
                # Pull the cookie line for evidence
                for line in headers.split('\n'):
                    ll = line.strip()
                    if not ll.startswith('cookie:'):
                        continue
                    for hint in cookie_hints:
                        if hint in ll:
                            rec['cookie_hits'].append(ll[:200])
                            break
                    break

        ja3_by_src = self._cs_ja3_by_src()

        alerts = []
        for (src, dst), rec in signals.items():
            n_distinct = sum(1 for k in (
                'checksum_hits', 'uri_hits', 'ua_hits', 'cookie_hits',
            ) if rec[k])
            ja3_hits = sorted(ja3_by_src.get(src, set()))
            if ja3_hits:
                n_distinct += 1

            # Don't fire on a single "default URI" alone — far too generic
            # (jquery URIs, /load, /ca all appear in legitimate traffic).
            # Require either a checksum8 hit or at least 2 independent signals.
            if not rec['checksum_hits'] and n_distinct < 2:
                continue

            if rec['checksum_hits'] and n_distinct >= 3:
                severity = 'critical'
            elif rec['checksum_hits'] or n_distinct >= 3:
                severity = 'critical' if rec['checksum_hits'] else 'high'
            elif n_distinct >= 2:
                severity = 'high'
            else:
                severity = 'medium'

            evidence_parts = []
            if rec['checksum_hits']:
                evidence_parts.append(
                    f'{len(rec["checksum_hits"])} URI(s) de stager checksum8'
                )
            if rec['uri_hits']:
                evidence_parts.append(
                    f'{len(rec["uri_hits"])} URI(s) de perfil padrão'
                )
            if rec['ua_hits']:
                evidence_parts.append('User-Agent padrão')
            if rec['cookie_hits']:
                evidence_parts.append('padrão de Cookie padrão')
            if ja3_hits:
                evidence_parts.append(f'CS JA3 ({ja3_hits[0][1]})')

            alerts.append({
                'severity': severity,
                'category': 'c2',
                'title': 'Cobalt Strike Malleable C2 Profile',
                'description': (
                    f'O host {src} → {dst}: '
                    + ', '.join(evidence_parts)
                    + '. Consistente com o perfil de C2 malleable '
                    'padrão/vazado do Cobalt Strike.'
                ),
                'ip': src,
                'details': {
                    'src': src,
                    'dst': dst,
                    'signal_count': n_distinct,
                    'first_checksum_ts': first_checksum_ts.get((src, dst)),
                    # Hoist first checksum8 timestamp to details.first_ts so
                    # the analyzer's timestamp-policy pass converts it to
                    # alert['timestamp'] for kill-chain ordering.
                    'first_ts': first_checksum_ts.get((src, dst)),
                    'checksum_hits': [
                        {'path': p, 'arch': a}
                        for p, a in rec['checksum_hits'][:5]
                    ],
                    'uri_hits': [
                        {'path': p, 'host': h}
                        for p, h in rec['uri_hits'][:5]
                    ],
                    'ua_hits': [
                        {'matched': m, 'ua': u}
                        for m, u in rec['ua_hits'][:3]
                    ],
                    'cookie_hits': rec['cookie_hits'][:3],
                    'ja3_hits': [
                        {'md5': h, 'label': l} for h, l in ja3_hits[:3]
                    ],
                },
                'recommendation': (
                    'O Cobalt Strike é o framework de pós-exploração de fato '
                    'nas intrusões modernas. Isole o host de origem, preserve '
                    'memória e disco para forense, bloqueie o destino no '
                    'firewall/proxy, procure por movimento lateral '
                    '(SMB/WinRM/RPC) e inspecione alertas de beaconing '
                    'simultâneos para o mesmo host. Se a equipe estiver '
                    'rodando um exercício de red-team autorizado, confirme o '
                    'escopo antes de remediar.'
                ),
                'mitre_attack': {
                    'technique_id': 'T1071.001',
                    'technique_name': (
                        'Application Layer Protocol: Web Protocols'
                    ),
                    'tactic_id': 'TA0011',
                    'tactic_name': 'Command and Control',
                    'url': 'https://attack.mitre.org/techniques/T1071/001/',
                    'software_id': 'S0154',
                    'software_name': 'Cobalt Strike',
                },
            })
        return alerts


import re as _re

# Compiled once at import for the ExploitPayloadDetector.
# Cloud metadata endpoints. A request whose OWN destination is one of these
# is the VM talking to its hypervisor (normal); SSRF is the address showing up
# inside a request aimed at some other server.
_METADATA_HOSTS = frozenset({
    '169.254.169.254', '169.254.170.2', '100.100.100.200',
    'metadata.google.internal', 'metadata.aliyuncs.com',
})

# Each entry: (name, severity, MITRE technique-id, MITRE technique-name, compiled regex)
# Patterns são intencionalmente largos para cobrir variantes ofuscadas — o
# evaluator de Log4Shell normaliza ${lower:j}, ${::-j}, ${env:VAR:-j} etc.
# para 'j', então procuramos por 'jndi' precedido por '${' a até 60 chars.
_EXPLOIT_PATTERNS = [
    (
        'Log4Shell (CVE-2021-44228)',
        'critical',
        'T1190',
        'Exploit Public-Facing Application',
        _re.compile(
            r'(\$\{[^}]{0,80}jndi\s*:|%24%7[Bb][^%]{0,80}jndi%3[Aa]'
            r'|%24%7[Bb]jndi)',
            _re.IGNORECASE,
        ),
    ),
    (
        'Spring4Shell (CVE-2022-22965)',
        'critical',
        'T1190',
        'Exploit Public-Facing Application',
        _re.compile(
            r'class\.module\.classLoader'
            r'|class%2Emodule%2EclassLoader'
            r'|class\[\s*module\s*\]\[\s*classLoader\s*\]',
            _re.IGNORECASE,
        ),
    ),
    (
        'ProxyShell/ProxyLogon Exchange exploit (CVE-2021-26855 / 34473)',
        'critical',
        'T1190',
        'Exploit Public-Facing Application',
        _re.compile(
            # Plain /autodiscover/autodiscover.json is every Outlook client
            # looking up its mailbox; the exploit is the SSRF shape with an
            # '@' right after the query mark, or autodiscover smuggled in the
            # Email=/schema= parameter.
            r'/autodiscover/autodiscover\.json\?[^\s&]*@'
            r'|(?:Email|schema)=[^&\s]*autodiscover(?:/|%2f)autodiscover'
            r'|/ecp/[^?\s]+\?.*(?:Email|schema)=[^&\s]*autodiscover',
            _re.IGNORECASE,
        ),
    ),
    (
        'Confluence OGNL Injection (CVE-2022-26134 / 2023-22515)',
        'critical',
        'T1190',
        'Exploit Public-Facing Application',
        _re.compile(
            r'\$\{[^}]{0,80}@java\.lang\.Runtime'
            r'|/\$\{[^}]{0,80}\}|/setup/setupadministrator\.action',
            _re.IGNORECASE,
        ),
    ),
    (
        'Generic Command Injection',
        'high',
        'T1059',
        'Command and Scripting Interpreter',
        _re.compile(
            r'(?:[;|`]\s*(?:cat|wget|curl|nc|bash|sh)\s'
            r'|/bin/(?:sh|bash)\b'
            r'|(?:%3[Bb]|%7[Cc])(?:wget|curl|nc)\b)',
            _re.IGNORECASE,
        ),
    ),
    (
        'SQLi UNION/SLEEP pattern',
        'high',
        'T1190',
        'Exploit Public-Facing Application',
        _re.compile(
            r'(?:union\s+select|union\s+all\s+select'
            r'|sleep\s*\(\s*\d+\s*\)'
            r'|benchmark\s*\(\s*\d+\s*,'
            r'|or\s+1\s*=\s*1\b)',
            _re.IGNORECASE,
        ),
    ),
    (
        'SSRF probe to cloud metadata endpoint',
        'high',
        'T1190',
        'Exploit Public-Facing Application',
        _re.compile(
            r'169\.254\.169\.254|metadata\.google\.internal'
            r'|100\.100\.100\.200|metadata\.aliyuncs\.com'
            r'|169\.254\.170\.2',
        ),
    ),
    (
        'Webshell-style RCE parameter',
        'high',
        'T1505.003',
        'Server Software Component: Web Shell',
        _re.compile(
            r'[?&](?:cmd|exec|c|command|run|code|do|action)=(?:php://|data://|'
            r'eval\(|exec\(|system\(|passthru\(|shell_exec\(|`)',
            _re.IGNORECASE,
        ),
    ),
]


_SSRF_IMDS_IDX = next(
    i for i, p in enumerate(_EXPLOIT_PATTERNS)
    if p[0] == 'SSRF probe to cloud metadata endpoint')


class ExploitPayloadDetector(PostDetector):
    """Detect known-exploit payload patterns in HTTP requests.

    Varre `self._http_info['requests']` casando URI, headers e body amostrado
    contra regex compiladas para Log4Shell, Spring4Shell, ProxyShell,
    Confluence OGNL, SSRF a metadata IMDS, SQLi/cmd injection, webshell RCE.
    Emite até 1 alerta por (src, pattern_name); samples truncados.
    """
    name = 'exploit_payload'

    # Limite de matches únicos por (src, pattern) listados no alert para evitar
    # blob enorme em captures com milhares de tentativas.
    MAX_SAMPLES = 5
    # Trunca cada campo varrido para evitar regex catastrophic backtracking.
    SCAN_FIELD_CAP = 4096

    def run(self):
        http = getattr(self.analyzer, '_http_info', None) or {}
        requests_list = http.get('requests') or []
        if not requests_list:
            return []
        # (src, pattern_idx) -> list[(path_sample, host, method)]
        hits = defaultdict(list)
        for req in requests_list:
            src = req.get('src')
            if not src:
                continue
            path = (req.get('path') or '')[:self.SCAN_FIELD_CAP]
            host = req.get('host') or ''
            headers = (req.get('headers_sample') or '')[:self.SCAN_FIELD_CAP]
            body = (req.get('body_sample') or '')[:self.SCAN_FIELD_CAP]
            # Concatenamos com separadores que não interferem nas regexes —
            # patterns olham trechos próprios. Varrer uma única vez evita
            # custo de N matches por request.
            blob = '\n'.join((path, host, headers, body))
            host_only = host.lower().split(':', 1)[0].strip().rstrip('.')
            direct_metadata = (req.get('dst') in _METADATA_HOSTS
                               or host_only in _METADATA_HOSTS)
            outbound = (self.analyzer._is_local_ip(src)
                        and not self.analyzer._is_local_ip(req.get('dst')))
            for idx, (_name, _sev, _tid, _tname, regex) in enumerate(
                _EXPLOIT_PATTERNS,
            ):
                if idx == _SSRF_IMDS_IDX and direct_metadata:
                    continue
                if regex.search(blob):
                    key = (src, idx, outbound)
                    if len(hits[key]) < self.MAX_SAMPLES:
                        hits[key].append({
                            'method': req.get('method', ''),
                            'host': host,
                            'path': path[:200],
                        })
        alerts = []
        from . import _SEV_LADDER
        for (src, idx, outbound), samples in hits.items():
            name, base_sev, tid, tname, _regex = _EXPLOIT_PATTERNS[idx]
            severity = base_sev
            # Local client -> external server: our host is the sender, which
            # is far more often an app with odd query strings than an
            # attacker. Critical (Log4Shell & co.) stays critical.
            if outbound and severity != 'critical':
                severity = _SEV_LADDER[max(1, _SEV_LADDER.index(severity) - 1)]
            alerts.append({
                'severity': severity,
                'category': 'http',
                'title': f'Exploit Payload Detected: {name}',
                'description': (
                    f'O host {src} enviou requisições HTTP correspondendo ao '
                    f'padrão {name}. Assinatura em nível de payload — pode ser '
                    f'tentativa real de exploração ou scan automatizado.'
                ),
                'ip': src,
                'details': {
                    'src': src,
                    'pattern': name,
                    'outbound': outbound,
                    'severity_original': base_sev,
                    'match_count': len(samples),
                    'samples': samples,
                },
                'recommendation': (
                    'Confirme se o destino é vulnerável e se a tentativa teve '
                    'sucesso (busque por respostas 200/500 com payload '
                    'inesperado). Patche o serviço, bloqueie o IP de origem '
                    'em WAF/firewall e revise logs do servidor.'
                ),
                'mitre_attack': {
                    'technique_id': tid,
                    'technique_name': tname,
                    'tactic_id': 'TA0001',
                    'tactic_name': 'Initial Access',
                    'url': (
                        'https://attack.mitre.org/techniques/'
                        + tid.replace('.', '/') + '/'
                    ),
                },
            })
        return alerts


class EncryptedClientHelloDetector(PostDetector):
    """A.5 — Sinaliza TLS ClientHello com extensão Encrypted Client Hello
    (ext 0xfe0d). Mantido separado de SuspiciousSniDetector ("SNI ausente")
    porque ECH é cegueira deliberada e moderna, não falta acidental do SNI."""
    name = 'tls_ech'

    def run(self):
        analyzer = self.analyzer
        tls = analyzer._tls_info
        if not tls:
            return []
        alerts = []
        seen = set()
        for ch in tls.get('client_hellos') or []:
            if not ch.get('has_ech'):
                continue
            src = ch['src']
            dst = ch['dst']
            dport = ch.get('dport')
            if analyzer._is_local_ip(dst):
                continue
            key = (src, dst, dport)
            if key in seen:
                continue
            seen.add(key)
            sni = ch.get('sni') or '(none)'
            # Default-on in Chrome/Firefox against Cloudflare-fronted sites:
            # a visibility note for the defender, not an indicator.
            alerts.append({
                'severity': 'low',
                'category': 'tls',
                'title': 'TLS Encrypted Client Hello (ECH)',
                'description': (
                    f'O handshake TLS {src} -> {dst}:{dport} contém a '
                    f'extensão encrypted_client_hello (0xfe0d). SNI externo={sni}.'
                ),
                'ip': src,
                'details': {
                    'src': src, 'dst': dst, 'dport': dport,
                    'outer_sni': ch.get('sni'),
                    'ja3_md5': ch.get('ja3_md5'),
                    'ja4': ch.get('ja4'),
                },
                'recommendation': (
                    'ECH encripta o inner ClientHello (incluindo o SNI real). '
                    'É privacidade no usuário e cegueira no defensor. Em rede '
                    'corporativa avalie política de bloqueio TLS ext 0xfe0d ou '
                    'inspeção via proxy. Browsers Chrome/Firefox modernos usam '
                    'ECH com Cloudflare por padrão quando o DNS HTTPS RR está '
                    'disponível, então pode haver FP legítimo.'
                ),
            })
        return alerts


class GreyNoiseRiotDetector(PostDetector):
    """Onda 6 — B.4. Opt-in benign-scanner enrichment.

    Reads ``analyzer._port_scan_sources`` (populated by
    PortScanStreamingDetector) and queries GreyNoise's community API for each
    source IP. Emits an *informational* (low severity) alert when the IP is
    classified RIOT (Real IoT / known benign scanner — Shodan, Censys,
    Project Sonar, BinaryEdge, etc.) or `benign`. This does NOT suppress the
    original port-scan alert; it adds a separate counter-signal so analysts
    can de-prioritize cleanly.

    No-op when `settings['api_keys']['greynoise']` is absent — mirrors the
    VT/AbuseIPDB/MalwareBazaar pattern.
    """
    name = 'greynoise_riot'

    def run(self):
        analyzer = self.analyzer
        scan_sources = getattr(analyzer, '_port_scan_sources', None) or {}
        if not scan_sources:
            return []
        api_keys = analyzer.settings.get('api_keys') or {}
        if not api_keys.get('greynoise'):
            return []
        try:
            from threat_intel import check_greynoise
        except Exception:
            return []
        from ..constants import GREYNOISE_BENIGN_CLASSIFICATIONS
        alerts = []
        for src_ip, scan_info in scan_sources.items():
            try:
                gn = check_greynoise(src_ip, analyzer.settings)
            except Exception:
                gn = None
            if not gn:
                continue
            is_riot = bool(gn.get('riot'))
            classification = (gn.get('classification') or '').lower()
            is_benign = classification in GREYNOISE_BENIGN_CLASSIFICATIONS
            if not (is_riot or is_benign):
                continue
            label = gn.get('name') or classification or 'benign-scanner'
            alerts.append({
                'severity': 'low',
                'category': 'scan',
                'title': 'Scanner classified BENIGN by GreyNoise',
                'description': (
                    f'O IP {src_ip} (que disparou um alerta de port-scan) é '
                    f'marcado pela GreyNoise como {label} '
                    f'(riot={is_riot}, classificação={classification or "—"}). '
                    'Isto normalmente é um scanner de escala mundial (Shodan, '
                    'Censys, Project Sonar) — apenas informativo.'
                ),
                'ip': src_ip,
                'details': {
                    'src': src_ip,
                    'riot': is_riot,
                    'classification': classification,
                    'name': gn.get('name'),
                    'message': gn.get('message'),
                    'scan_type': scan_info.get('scan_type'),
                    'nmap_fingerprint': scan_info.get('nmap_like'),
                },
                'recommendation': (
                    'Se a política permitir scanners benignos da internet, '
                    'você pode despriorizar com segurança o alerta de Port '
                    'Scan relacionado. Caso contrário, bloqueie no perímetro '
                    'como de costume.'
                ),
            })
        return alerts


# CVE pattern reused by the KEV enricher — shared with alert_schema so the
# canonical `cves` field and KEV matching extract the exact same token set.
from ..alert_schema import CVE_RE as _CVE_RE  # noqa: E402


class KevEnricherDetector(PostDetector):
    """Cross-reference existing alerts with the CISA KEV catalog.

    Walks `results['alerts']` looking for CVE-YYYY-NNNN references in title,
    description, and details. When a CVE is found in the KEV catalog:
      * Annotates the existing alert with `details.kev` (vendor/product/
        date_added/ransomware) and a `kev_matches` list.
      * If the original severity was below 'critical' AND the KEV entry has
        `ransomware=True`, bumps severity to 'critical' (with the previous
        value recorded as `details.severity_original`).
      * Emits one summary informational/high alert per (ip, cve) pair so KEV
        coverage surfaces in dashboards even when the originating alert is
        category-specific (HTTP exploit, payload, etc).

    Silent no-op when the KEV catalog fails to load.
    """
    name = 'kev_enricher'

    # Track previously seen CVE strings in details, to avoid emitting summary
    # alerts twice when several heuristics match the same payload.
    def run(self):
        try:
            import threat_intel as _ti
            catalog = _ti.load_cisa_kev()
        except Exception as exc:
            print(f"[kev_enricher] catalog load failed: {exc}")
            return []
        if not catalog:
            return []

        analyzer = self.analyzer
        # POST_DETECTORS run before results['alerts'] is finalized; the
        # in-flight list is exposed as analyzer._pending_alerts by _core.
        all_alerts = (getattr(analyzer, '_pending_alerts', None)
                      or analyzer.results.get('alerts') or [])
        if not all_alerts:
            return []

        new_alerts = []
        seen_pairs = set()  # (ip, cve)

        for alert in all_alerts:
            blob_parts = [
                alert.get('title') or '',
                alert.get('description') or '',
            ]
            details = alert.get('details') or {}
            for key in ('pattern', 'sample', 'name', 'cve', 'cves',
                        'msg', 'rule', 'reference'):
                v = details.get(key)
                if isinstance(v, str):
                    blob_parts.append(v)
                elif isinstance(v, (list, tuple)):
                    blob_parts.extend(str(x) for x in v if isinstance(x, str))
            for sample in details.get('samples', []) or []:
                if isinstance(sample, dict):
                    for k in ('path', 'host', 'msg'):
                        s = sample.get(k)
                        if isinstance(s, str):
                            blob_parts.append(s)

            blob = '\n'.join(blob_parts)
            kev_hits = []
            for m in _CVE_RE.finditer(blob):
                cve = f"CVE-{m.group(1)}-{m.group(2)}".upper()
                info = catalog.get(cve)
                if info and cve not in {h['cve'] for h in kev_hits}:
                    kev_hits.append(info)

            if not kev_hits:
                continue

            # Annotate the alert in place.
            details = dict(details)
            details['kev_matches'] = [
                {
                    'cve': h['cve'],
                    'vendor': h['vendor'],
                    'product': h['product'],
                    'name': h['name'],
                    'date_added': h['date_added'],
                    'ransomware': h['ransomware'],
                } for h in kev_hits
            ]
            ransomware_match = any(h['ransomware'] for h in kev_hits)
            if (ransomware_match and alert.get('severity') != 'critical'):
                details['severity_original'] = alert.get('severity')
                details['severity_reason'] = (
                    'Promovido a critical: corresponde a uma entrada do CISA '
                    'KEV com uso conhecido em campanhas de ransomware.'
                )
                alert['severity'] = 'critical'
            alert['details'] = details

            # Emit one summary alert per (ip, cve) pair.
            ip_for_summary = alert.get('ip') or details.get('src') or details.get('dst')
            for hit in kev_hits:
                pair = (ip_for_summary, hit['cve'])
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                sev = 'critical' if hit['ransomware'] else 'high'
                new_alerts.append({
                    'severity': sev,
                    'category': 'threat-intel',
                    'title': (
                        f"CISA KEV match: {hit['cve']} "
                        f"({hit['vendor']} {hit['product']})".strip()
                    ),
                    'description': (
                        f"Um alerta referenciando {hit['cve']} corresponde ao "
                        f"catálogo CISA de Vulnerabilidades Exploradas "
                        f"Conhecidas (KEV). "
                        f"{hit['name'] or hit['short_description']}"
                    ),
                    'ip': ip_for_summary,
                    'details': {
                        'cve':         hit['cve'],
                        'vendor':      hit['vendor'],
                        'product':     hit['product'],
                        'name':        hit['name'],
                        'date_added':  hit['date_added'],
                        'due_date':    hit['due_date'],
                        'ransomware':  hit['ransomware'],
                        'source_alert_title': alert.get('title'),
                    },
                    'recommendation': (
                        hit['required_action']
                        or 'Aplique o patch imediatamente; este CVE está sendo '
                           'ativamente explorado segundo a CISA. Procure por '
                           'atividade de pós-exploração.'
                    ),
                    'mitre_attack': {
                        'technique_id':   'T1190',
                        'technique_name': 'Exploit Public-Facing Application',
                        'tactic_id':      'TA0001',
                        'tactic_name':    'Initial Access',
                        'url': 'https://attack.mitre.org/techniques/T1190/',
                    },
                })
        return new_alerts


# Ordering constraint: KevEnricherDetector MUST stay last. It reads
# analyzer._pending_alerts — the shared in-flight list that _run_detections
# extends after each post-detector — so any detector placed after it would
# have its CVE references invisible to KEV matching. The rest are
# order-independent (guarded by test_engine_contract).
class HostMultipleAddressesDetector(PostDetector):
    """A machine (MAC) holding more addresses than a normal host does.

    Normal dual-stack host: ONE IPv4 plus several IPv6 addresses (one
    link-local fe80::, plus global / temporary privacy addresses that rotate
    daily). So the rule is per address TYPE, not per family:

      * 2+ IPv4 at the SAME time      -> medium (secondary IP / alias / spoof)
      * 2+ IPv4 at different times    -> low    (DHCP handed out a new lease)
      * 2+ IPv6 link-local            -> medium (one per interface is normal)
      * any number of global IPv6     -> no alert

    Router-like MACs (gateways legitimately own many interface addresses)
    and addresses the USER bound by hand are left out. Manual bindings the
    capture contradicts are reported here too.
    """
    name = 'host_multiple_addresses'

    def run(self):
        analyzer = self.analyzer
        alerts = []
        for host in (analyzer.results.get('hosts') or []):
            if host.get('gateway_like'):
                continue
            auto = [a for a in host.get('addresses') or []
                    if a.get('binding') == 'auto']
            v4 = [a for a in auto if a.get('scope') in ('v4_private', 'v4_public')]
            ll6 = [a for a in auto if a.get('scope') == 'v6_link_local']
            if len(v4) >= 2:
                alerts.append(self._v4_alert(host, v4))
            if len(ll6) >= 2:
                alerts.append(self._ll6_alert(host, ll6))
        for c in getattr(analyzer, '_host_conflicts', None) or []:
            alerts.append(self._conflict_alert(c))
        return alerts

    @staticmethod
    def _label(host):
        name = host.get('discovered_name')
        mac = host.get('mac') or host.get('host_key')
        return f'{name} ({mac})' if name else mac

    @staticmethod
    def _overlapping(addrs):
        for i, a in enumerate(addrs):
            for b in addrs[i + 1:]:
                if None in (a.get('first_ts'), a.get('last_ts'),
                            b.get('first_ts'), b.get('last_ts')):
                    continue
                if a['first_ts'] <= b['last_ts'] and b['first_ts'] <= a['last_ts']:
                    return True
        return False

    @staticmethod
    def _base_details(host, addrs):
        return {
            'host_key': host.get('host_key'),
            'host_mac': host.get('mac'),
            'mac_address': host.get('mac'),
            'host_name': host.get('discovered_name'),
            'addresses': [
                {'ip': a['ip'], 'first_ts': a.get('first_ts'),
                 'last_ts': a.get('last_ts'), 'sources': a.get('sources')}
                for a in addrs
            ],
            'address_count': len(addrs),
            'first_ts': min((a['first_ts'] for a in addrs
                             if a.get('first_ts') is not None), default=None),
            'last_ts': max((a['last_ts'] for a in addrs
                            if a.get('last_ts') is not None), default=None),
        }

    def _v4_alert(self, host, v4):
        overlapping = self._overlapping(v4)
        ips = [a['ip'] for a in v4]
        details = self._base_details(host, v4)
        details['simultaneous'] = overlapping
        if overlapping:
            severity = 'medium'
            note = ('Os endereços foram usados AO MESMO TEMPO: IP secundário '
                    'configurado na placa, alias, ou uma máquina se passando '
                    'por outra (spoofing).')
        else:
            severity = 'low'
            note = ('Os endereços foram usados em momentos diferentes — '
                    'típico de o DHCP ter entregue um novo IP à máquina.')
        return {
            'severity': severity,
            'category': 'mac',
            'title': 'Host with Multiple IPv4 Addresses',
            'description': (
                f'A máquina {self._label(host)} usou {len(ips)} endereços '
                f'IPv4 ({", ".join(ips[:5])}). {note}'
            ),
            'ip': ips[0],
            'details': details,
            'recommendation': (
                'Confirme se a máquina tem IP secundário configurado ou '
                'reserva de DHCP. Se não houver explicação, correlacione com '
                'alertas de ARP spoofing no mesmo período. Se for esperado, '
                'associe os IPs manualmente à máquina para silenciar este '
                'alerta.'
            ),
        }

    def _ll6_alert(self, host, ll6):
        ips = [a['ip'] for a in ll6]
        return {
            'severity': 'medium',
            'category': 'mac',
            'title': 'Host with Multiple IPv6 Link-Local Addresses',
            'description': (
                f'A máquina {self._label(host)} usou {len(ips)} endereços '
                f'IPv6 link-local ({", ".join(ips[:5])}). Cada interface tem '
                'um único endereço fe80:: — mais de um no mesmo MAC indica '
                'interfaces virtuais/bridge, reconfiguração da pilha ou '
                'spoofing de NDP.'
            ),
            'ip': ips[0],
            'details': self._base_details(host, ll6),
            'recommendation': (
                'Verifique se a máquina roda VMs/containers em bridge ou teve '
                'a pilha IPv6 reiniciada. Sem explicação, correlacione com '
                'alertas de NDP spoofing.'
            ),
        }

    @staticmethod
    def _conflict_alert(c):
        return {
            'severity': 'medium',
            'category': 'mac',
            'title': 'Manual Host Binding Conflict',
            'description': (
                f'O IP {c["ip"]} foi associado manualmente à máquina de MAC '
                f'{c.get("expected_mac")}, mas nesta captura ele aparece com o '
                f'MAC {c.get("observed_mac")}. Para não misturar duas máquinas, '
                'o tráfego deste IP NÃO foi somado à máquina associada.'
            ),
            'ip': c['ip'],
            'details': {
                'host_key': c.get('host_key'),
                'expected_mac': c.get('expected_mac'),
                'observed_mac': c.get('observed_mac'),
                'mac_address': c.get('observed_mac'),
            },
            'recommendation': (
                'Provavelmente o DHCP entregou este IP a outra máquina. '
                'Revise a associação manual (ou crie uma reserva de DHCP). Se '
                'o MAC observado não for conhecido, investigue spoofing.'
            ),
        }


POST_DETECTORS = [
    IpMacChangesDetector,
    HostMultipleAddressesDetector,
    OldTlsVersionDetector,
    SuspiciousSniDetector,
    KnownBadJa3Detector,
    KnownBadJa3sDetector,
    KnownBadJa4Detector,
    AlpnPortInconsistencyDetector,
    TlsCertificateDetector,
    ScannerUserAgentDetector,
    ExploitPathsDetector,
    ExploitPayloadDetector,
    UnusualHttpMethodDetector,
    HttpInjectionDetector,
    FileShareUploadDetector,
    HighVolumeQuicNewDestDetector,
    DohDetector,
    CobaltStrikeDetector,
    EncryptedClientHelloDetector,
    GreyNoiseRiotDetector,
    KevEnricherDetector,
]
