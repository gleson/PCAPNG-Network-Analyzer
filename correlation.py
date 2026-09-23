"""
Cross-scan and intra-scan correlation.

Two layers:

1. **First-seen artifact tracking** (cross-scan): reads results
   ['observed_artifacts'], compares against historical artifact_seen, emits
   "new artifact on the network" alerts. Persistence happens later in
   db.save_scan.

2. **Intra-scan rule correlation**: reads results['alerts'], groups by
   source IP, checks for chains of detections that together represent an
   incident kill-chain (port scan -> brute force -> lateral, etc.), and
   emits a single high-severity "incident" alert per matching chain.

Runs after analyze_behavioral_baseline so per-scan + behavioral alerts
are already in place; we extend the same alerts list.
"""
from collections import defaultdict
from datetime import datetime
import ipaddress
import database as db
from mitre_attack import _t


# Don't run on day 1: until we have at least this many historical scans,
# nothing is "known" and every artifact would alert.
MIN_HISTORY_SCANS = 3

# Cap alerts per artifact type so a fresh capture full of new TLS clients
# doesn't drown the operator. Tuned for SOC fatigue, not completeness.
DEFAULT_CAPS = {
    "mac": 10,
    "ja3": 15,
    "ja3s": 10,
    "ja4": 15,
    "ja4s": 10,
    "ja4h": 15,
    "hassh": 10,
    "hassh_server": 10,
    "sni": 20,
    "http_host": 20,
    "quic_dest": 20,
}

# Severity per artifact type: MAC has the highest signal (new device on the
# wire usually means rogue or BYOD). JA3 is medium because new TLS clients
# on managed hosts are unusual. SNI / HTTP host are noisy on user
# workstations so we keep them low by default.
SEVERITY = {
    "mac": "medium",
    "ja3": "medium",
    "ja3s": "low",
    "ja4": "medium",
    "ja4s": "low",
    "ja4h": "medium",
    "hassh": "medium",
    "hassh_server": "low",
    "sni": "low",
    "http_host": "low",
    "quic_dest": "low",
}

TITLE = {
    "mac": "New MAC Address on Network",
    "ja3": "New JA3 (TLS Client Fingerprint)",
    "ja3s": "New JA3S (TLS Server Fingerprint)",
    "ja4": "New JA4 (TLS Client Fingerprint)",
    "ja4s": "New JA4S (TLS Server Fingerprint)",
    "ja4h": "New JA4H (HTTP Client Fingerprint)",
    "hassh": "New HASSH (SSH Client Fingerprint)",
    "hassh_server": "New HASSH-Server (SSH Server Fingerprint)",
    "sni": "New TLS SNI Observed",
    "http_host": "New HTTP Host Observed",
    "quic_dest": "New QUIC/HTTP3 Destination",
}

RECOMMENDATION = {
    "mac": (
        "Um dispositivo com este MAC nunca foi visto nesta rede. "
        "Confirme que é um ativo autorizado (provisionamento, BYOD, "
        "fornecedor) antes de deixá-lo permanecer. MACs desconhecidos são "
        "frequentemente o primeiro sinal de access points não autorizados, "
        "implantes plantados por atacante ou pivôs laterais via VPN."
    ),
    "ja3": (
        "O JA3 faz fingerprint de stacks TLS de cliente (navegadores, "
        "bibliotecas, loaders de malware). Um JA3 nunca visto significa "
        "que uma nova ferramenta cliente está falando com a rede. Valide "
        "via feeds de threat-intel (SSLBL) e correlacione com o host de "
        "origem."
    ),
    "ja3s": (
        "O JA3S faz fingerprint do lado servidor do TLS. Um novo JA3S pode "
        "significar que um host está se conectando a um serviço que nunca "
        "alcançou antes, ou que um serviço existente foi reconfigurado."
    ),
    "sni": (
        "Primeira observação deste domínio via TLS. Cruze com DNS, threat "
        "intel (URLhaus, abuse.ch) e o host de origem."
    ),
    "http_host": (
        "Primeira observação deste hostname sobre HTTP em texto claro. "
        "Confirme se o host e o caminho são esperados; HTTP em claro para "
        "domínios novos é um canal frequente de staging de downloaders."
    ),
    "quic_dest": (
        "Primeira observação de um host externo alcançado via QUIC/HTTP3. "
        "O QUIC contorna a maior parte da inspeção em nível de TCP (sem "
        "SNI, sem JA3 por padrão, handshake criptografado). Correlacione "
        "com as resoluções DNS do mesmo cliente e verifique se o destino é "
        "um serviço sancionado (Google, Cloudflare, Akamai)."
    ),
    "ja4": (
        "O JA4 é o sucessor moderno do JA3 — mesma família de sinal "
        "(identidade da stack TLS do cliente), mas resistente ao embaralhar "
        "do ClientHello e granular quanto a versão do TLS / presença de SNI "
        "/ ALPN. Um novo JA4 significa que uma nova ferramenta cliente "
        "apareceu. Cruze com bancos públicos de JA4 (FoxIO) e a stack de "
        "software esperada do host de origem."
    ),
    "ja4s": (
        "O JA4S faz fingerprint da stack TLS do servidor. Um novo JA4S pode "
        "significar que um host está se conectando a um serviço que nunca "
        "alcançou antes, que o serviço foi reconfigurado ou — no pior caso "
        "— que um serviço legítimo está sendo personificado por um endpoint "
        "controlado por atacante."
    ),
    "ja4h": (
        "O JA4H faz fingerprint de clientes HTTP pela forma da requisição "
        "(método, versão, ordem dos cabeçalhos, cookies). Um novo JA4H "
        "normalmente sinaliza uma nova biblioteca HTTP, scraper ou implante "
        "customizado fazendo beacon sobre HTTP em claro. Correlacione com "
        "o User-Agent e o Host."
    ),
    "hassh": (
        "O HASSH faz fingerprint de clientes SSH por suas preferências de "
        "algoritmo no KEXINIT. Um novo HASSH de um host que já tinha "
        "atividade SSH aponta para um cliente SSH trocado (build de OpenSSH "
        "diferente, cliente por script como libssh/paramiko ou ferramenta "
        "de atacante)."
    ),
    "hassh_server": (
        "O HASSH-Server faz fingerprint de daemons SSH. Um novo "
        "HASSH-Server em um IP que antes era um servidor SSH conhecido "
        "sugere que o daemon foi reconfigurado, atualizado ou substituído. "
        "Em um host inesperado, pode indicar um listener não autorizado."
    ),
}


def detect_new_artifacts(results, settings=None):
    """
    Add first-seen artifact alerts to results['alerts']. Idempotent — calling
    twice on the same results doesn't double-fire because the second call
    sees the same `observed_artifacts` and the same DB state.

    Returns the (possibly mutated) results dict.
    """
    if not results:
        return results

    history = db.get_total_scan_count()
    if history < MIN_HISTORY_SCANS:
        return results

    observed = results.get("observed_artifacts") or {}
    if not observed:
        return results

    settings = settings or {}
    thresholds = settings.get("thresholds") or {}

    types = list(TITLE.keys())
    known = db.get_known_artifact_keys(types=types)

    # Bucket new artifacts per type
    new_by_type = {t: [] for t in types}
    for typ in types:
        for v in observed.get(typ, []) or []:
            if (typ, v) not in known:
                new_by_type[typ].append(v)

    if not any(new_by_type.values()):
        return results

    now_iso = datetime.now().isoformat()
    alerts_out = []

    for typ, values in new_by_type.items():
        if not values:
            continue
        cap = int(thresholds.get(f"first_seen_{typ}_max_alerts", DEFAULT_CAPS[typ]))
        for v in sorted(values)[:cap]:
            description = (
                f"{TITLE[typ]}: {v} (sem registro em {history} scan(s) anterior(es))"
            )
            alerts_out.append({
                "severity": SEVERITY[typ],
                "category": "first-seen",
                "title": TITLE[typ],
                "description": description,
                "details": {
                    "artifact_type": typ,
                    "artifact_value": v,
                    "historical_scans_checked": history,
                },
                "recommendation": RECOMMENDATION[typ],
                "timestamp": now_iso,
            })

    if not alerts_out:
        return results

    # Annotate with MITRE; degrade silently if mitre_attack import fails.
    try:
        from mitre_attack import annotate_alerts
        annotate_alerts(alerts_out)
    except Exception as e:
        print(f"[correlation] MITRE annotation failed: {e}")

    results.setdefault("alerts", []).extend(alerts_out)
    return results


# ============================================================================
# Intra-scan rule correlation
# ============================================================================
#
# A "rule" is a list of triggers. Each trigger is a set of alert titles
# (prefix match) OR alert categories. To fire, the rule needs at least one
# matching alert from EACH trigger set, all sharing the same source IP.
#
# We deliberately keep the rule set small and high-signal — a chain that
# describes a textbook kill-chain. Single-trigger detections are noisy by
# design (port scans alone are everywhere on the public Internet); the
# value of correlation is precisely to surface combinations.

def _alert_matches_trigger(alert, trigger):
    """trigger is a dict with optional `titles` (prefixes) or `categories`."""
    title = (alert.get("title") or "")
    category = (alert.get("category") or "")
    if "titles" in trigger:
        for prefix in trigger["titles"]:
            if title.startswith(prefix):
                return True
    if "categories" in trigger:
        if category in trigger["categories"]:
            return True
    return False


# Rule schema:
#   id, name, severity, description_template, recommendation,
#   triggers: list of trigger dicts, ordered (we use the order in the
#             description but don't enforce temporal ordering — the rule
#             fires if all trigger sets match anywhere in the scan).
CORRELATION_RULES = [
    {
        "id": "recon_to_exploitation",
        "name": "Reconnaissance followed by Exploitation",
        "severity": "high",
        # The source host is the ACTOR driving the kill-chain (the attacker).
        "source_role": "attacker",
        "mitre": _t('T1190', 'Exploit Public-Facing Application', 'TA0001'),
        "triggers": [
            {"titles": ["Port Scan Detected", "Horizontal Port Scan", "ICMP Ping Sweep", "SNMP Walk Detected"]},
            {"titles": [
                "Brute Force Attack Detected",
                "HTTP Request to Sensitive/Exploit Path",
                "HTTP Attack Pattern",
                "Security Scanner User-Agent",
            ]},
        ],
        "recommendation": (
            "Um único host varreu a rede e em seguida tentou exploração. "
            "Trate como ataque direcionado: isole a origem, capture os pacotes "
            "completos para forense e audite qualquer autenticação "
            "bem-sucedida a partir deste IP."
        ),
    },
    {
        "id": "intrusion_to_lateral",
        "name": "Intrusion followed by Lateral Movement",
        "severity": "critical",
        "source_role": "attacker",
        "mitre": _t('T1021', 'Remote Services', 'TA0008'),
        "triggers": [
            {"titles": ["Brute Force Attack Detected", "HTTP Attack Pattern", "HTTP Request to Sensitive/Exploit Path"]},
            {"titles": ["Internal Lateral Movement Suspected"]},
        ],
        "recommendation": (
            "Possível comprometimento: um atacante explorou um serviço e agora "
            "está pivoteando lateralmente. Coloque a origem em quarentena, "
            "troque as credenciais do segmento afetado e revise os logs de "
            "autenticação SMB/RDP/WinRM."
        ),
    },
    {
        "id": "c2_to_exfil",
        "name": "C2 Beaconing followed by Data Exfiltration",
        "severity": "critical",
        # The source host is the COMPROMISED victim/bot. The adversary is the
        # remote C2 / exfil destination surfaced in `peer_ips`.
        "source_role": "compromised_host",
        "mitre": _t('T1041', 'Exfiltration Over C2 Channel', 'TA0010'),
        "triggers": [
            {"titles": ["Beaconing Behavior Detected"]},
            {"titles": [
                "Possible Data Exfiltration",
                "Connection to File-Share / Paste Service",
                "Possible ICMP Tunneling",
                "High-Entropy Payload on Cleartext Port",
            ]},
        ],
        "recommendation": (
            "Beacon seguido de exfil é a cadeia de C2 clássica. Faça um "
            "snapshot do host, bloqueie os destinos no perímetro e assuma que "
            "o dispositivo está comprometido até a análise forense."
        ),
    },
    {
        "id": "dga_to_c2",
        "name": "DGA Domains followed by C2 Activity",
        "severity": "critical",
        "source_role": "compromised_host",
        "mitre": _t('T1568', 'Dynamic Resolution', 'TA0011'),
        "triggers": [
            {"titles": ["Possible DGA Domain Activity", "NXDOMAIN Spike Detected", "Fast-Flux Domain Suspected"]},
            {"titles": [
                "Beaconing Behavior Detected",
                "Known Malicious JA3 Fingerprint",
                "Suspicious TLS SNI",
                "Connection to File-Share / Paste Service",
            ]},
        ],
        "recommendation": (
            "Resolução de domínios no estilo DGA combinada com indicadores de "
            "C2 sugere fortemente uma família de malware ativa. Identifique o "
            "malware via JA3/threat-intel, isole o host e colete uma imagem de "
            "memória."
        ),
    },
    {
        "id": "credential_to_lateral",
        "name": "Credential Theft followed by Lateral Movement",
        "severity": "critical",
        "source_role": "attacker",
        "mitre": _t('T1557', 'Adversary-in-the-Middle', 'TA0006'),
        "triggers": [
            {"titles": [
                "LLMNR/NBT-NS Response Activity",
                "ARP Spoofing Detected",
                "Insecure Protocol: Telnet",
                "Insecure Protocol: FTP",
            ]},
            {"titles": ["Internal Lateral Movement Suspected", "External IP Accessing SMB"]},
        ],
        "recommendation": (
            "O mesmo host envenenou respostas de credencial (ou farejou texto "
            "claro) e pivoteou internamente. Trate como atividade AitM/"
            "Responder confirmada. Desative LLMNR/NetBIOS, troque quaisquer "
            "credenciais expostas ao segmento e isole a origem."
        ),
    },
    {
        "id": "behavioral_chain",
        "name": "Behavioral Anomaly followed by Suspicious Egress",
        "severity": "high",
        "source_role": "compromised_host",
        "mitre": _t('T1048', 'Exfiltration Over Alternative Protocol', 'TA0010'),
        "triggers": [
            {"titles": [
                "First-Seen External Destination",
                "New Protocol on Known Host",
                "Activity in Unusual Time Window",
                "Outbound Volume Surge vs Baseline",
            ]},
            {"titles": [
                "Beaconing Behavior Detected",
                "Possible Data Exfiltration",
                "Connection to File-Share / Paste Service",
                "High-Entropy Payload on Cleartext Port",
            ]},
        ],
        "recommendation": (
            "Um host desviou do seu baseline E apresentou um padrão de saída "
            "suspeito. Cada sinal isolado é ruidoso; a combinação é um "
            "candidato de triagem de alta prioridade. Valide contra mudanças "
            "de negócio antes de assumir comprometimento."
        ),
    },
]


def _bucket_alerts_by_source(alerts):
    """
    Bucket each alert under the source IP it implicates. We try a few common
    fields in priority order: details.src, details.source_ip, ip,
    details.src_ip. Alerts without any source-like field are skipped (they
    can't be attributed to a host so correlation can't chain them).
    """
    buckets = defaultdict(list)
    for alert in alerts:
        details = alert.get("details") or {}
        candidates = (
            details.get("src"),
            details.get("source_ip"),
            details.get("src_ip"),
            alert.get("ip"),
        )
        src = next((c for c in candidates if c), None)
        if not src:
            continue
        buckets[src].append(alert)
    return buckets


def _summarize_alerts(alerts, max_n=4):
    """Short title list for the incident description."""
    titles = []
    seen = set()
    for a in alerts:
        t = a.get("title") or "?"
        if t in seen:
            continue
        seen.add(t)
        titles.append(t)
        if len(titles) >= max_n:
            break
    return titles


# Keys under which detectors stash the *remote* end of a connection. We probe
# these on each constituent so the incident can name the adversary
# infrastructure instead of collapsing everything onto the local host.
_PEER_IP_KEYS = ('destination_ip', 'dst', 'dst_ip', 'remote_ip', 'server_ip')
_PEER_IP_LIST_KEYS = ('ips_sample', 'destination_ips')
_PEER_DOMAIN_KEYS = ('domain', 'sni', 'http_host')
_PEER_DOMAIN_LIST_KEYS = ('samples', 'domains')
_PEER_PORT_KEYS = ('destination_port', 'dst_port', 'dport')


def _looks_like_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _is_private_ip(value):
    """True for RFC1918 / loopback / link-local — i.e. an internal host."""
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


def _extract_peers(alert):
    """Return (ips, domains, ports) describing the remote counterpart(s) of a
    constituent alert — i.e. who the source host was actually talking to.

    Detectors store the far end under many different keys, so we probe the
    common ones. `src`/`source*` keys are deliberately ignored: those are the
    local host, not the counterpart.
    """
    details = alert.get('details') or {}
    ips, domains, ports = set(), set(), set()

    for k in _PEER_IP_KEYS:
        v = details.get(k)
        if v and _looks_like_ip(v):
            ips.add(str(v))
    for k in _PEER_IP_LIST_KEYS:
        for v in details.get(k) or []:
            if v and _looks_like_ip(v):
                ips.add(str(v))
    for k in _PEER_DOMAIN_KEYS:
        v = details.get(k)
        if v and not _looks_like_ip(v):
            domains.add(str(v))
    for k in _PEER_DOMAIN_LIST_KEYS:
        for v in details.get(k) or []:
            if isinstance(v, dict):
                v = v.get('domain') or v.get('host')
            if v and not _looks_like_ip(v):
                domains.add(str(v))
    for k in _PEER_PORT_KEYS:
        v = details.get(k)
        if v not in (None, ''):
            ports.add(str(v))
    # Detectors that list connections as [{host/dst, ...}, ...].
    for list_key in ('matches', 'hosts', 'connections', 'services'):
        for entry in details.get(list_key) or []:
            if isinstance(entry, dict):
                h = entry.get('host') or entry.get('dst') or entry.get('destination_ip')
                if h:
                    (ips if _looks_like_ip(h) else domains).add(str(h))

    return ips, domains, ports


def _join_capped(items, n=4):
    """Comma-join up to *n* items, summarising the rest as '(+K more)'."""
    shown = list(items)[:n]
    extra = len(items) - len(shown)
    text = ", ".join(shown)
    if extra > 0:
        text += f" (+{extra} more)"
    return text


def correlate_intra_scan(results, settings=None):
    """
    Walk results['alerts'], group by source, and emit incident-level alerts
    for any kill-chain rule whose trigger sets all match. Idempotent: an
    incident alert produced on a previous call won't itself satisfy a rule
    (rules don't include "Incident:" titles).

    Returns the (possibly mutated) results dict.
    """
    if not results:
        return results
    alerts = results.get("alerts") or []
    if not alerts:
        return results

    buckets = _bucket_alerts_by_source(alerts)
    if not buckets:
        return results

    now_iso = datetime.now().isoformat()
    incidents = []

    for src, src_alerts in buckets.items():
        for rule in CORRELATION_RULES:
            triggers = rule["triggers"]
            matched_per_trigger = []
            ok = True
            for trigger in triggers:
                matches = [a for a in src_alerts if _alert_matches_trigger(a, trigger)]
                if not matches:
                    ok = False
                    break
                matched_per_trigger.append(matches)
            if not ok:
                continue

            # Flatten constituent alerts (deduped)
            constituents = []
            seen_ids = set()
            for matches in matched_per_trigger:
                for a in matches:
                    key = (a.get("title"), a.get("description"))
                    if key in seen_ids:
                        continue
                    seen_ids.add(key)
                    constituents.append(a)

            constituent_titles = _summarize_alerts(constituents)

            # Lift the remote counterpart(s) out of the constituents so the
            # incident names the adversary infrastructure — without this the
            # alert collapses onto the local host and an analyst can't tell
            # who the attacker is.
            peer_ips, peer_domains, peer_ports = set(), set(), set()
            for a in constituents:
                pi, pd, pp = _extract_peers(a)
                peer_ips |= pi
                peer_domains |= pd
                peer_ports |= pp
            peer_ips.discard(src)  # the source is never its own peer
            peer_ips = sorted(peer_ips)
            peer_domains = sorted(peer_domains)
            peer_ports = sorted(peer_ports, key=lambda p: (len(p), p))

            # source_role tells us whether `src` is the attacker driving the
            # chain or the compromised victim acting under attacker control.
            role = rule.get("source_role", "attacker")
            src_is_internal = _is_private_ip(src)

            peer_bits = []
            if peer_ips:
                peer_bits.append(_join_capped(peer_ips))
            if peer_domains:
                peer_bits.append(_join_capped(peer_domains))
            peers_text = ("; ".join(peer_bits) if peer_bits
                          else "(nenhuma contraparte externa resolvida a partir dos constituintes)")

            if role == "compromised_host":
                src_label = (f"Host comprometido {src} (interno)"
                             if src_is_internal else f"Host comprometido {src}")
                description = (
                    f"{src_label} é a VÍTIMA da kill-chain "
                    f"'{rule['name']}' — está agindo sob controle do atacante. "
                    f"O adversário é a contraparte externa: {peers_text}. "
                    f"Detecções constituintes: " + "; ".join(constituent_titles)
                )
            else:
                description = (
                    f"O atacante {src} executou a kill-chain '{rule['name']}' "
                    f"contra o(s) alvo(s): {peers_text}. Detecções "
                    f"constituintes: " + "; ".join(constituent_titles)
                )

            incident = {
                "severity": rule["severity"],
                "category": "incident",
                "title": f"Incident: {rule['name']}",
                "description": description,
                "ip": src,
                "details": {
                    "rule_id": rule["id"],
                    "source_ip": src,
                    # Who `src` is in this chain: 'attacker' or
                    # 'compromised_host' (a victim/bot). The actual adversary
                    # in a compromised_host incident is in peer_ips.
                    "source_role": role,
                    "peer_ips": peer_ips,
                    "peer_domains": peer_domains,
                    "peer_ports": peer_ports,
                    "constituent_count": len(constituents),
                    "constituent_titles": constituent_titles,
                    "constituent_severities": sorted(
                        {a.get("severity") for a in constituents if a.get("severity")}
                    ),
                },
                "recommendation": rule["recommendation"],
                "timestamp": now_iso,
            }
            # Pin the kill-chain's real MITRE technique so annotate_alerts
            # doesn't fall back to the generic 'incident' placeholder.
            if rule.get("mitre"):
                incident["mitre_attack"] = dict(rule["mitre"])
            incidents.append(incident)

    if not incidents:
        return results

    try:
        from mitre_attack import annotate_alerts
        annotate_alerts(incidents)
    except Exception as e:
        print(f"[correlation] MITRE annotation failed (incidents): {e}")

    results.setdefault("alerts", []).extend(incidents)
    return results
