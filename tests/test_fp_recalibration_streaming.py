"""Regression cover for the 2026-09 false-positive recalibration of the
streaming detectors (see PENDENCIAS_ANALISE_2026-09.md).

Each test pins one benign shape that used to raise a loud alert AND, next to
it, the malicious shape that must still fire — the recalibration is
"downgrade/annotate, don't suppress", so both halves matter.
"""

import random
import uuid

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw
from scapy.layers.dcerpc import (
    DceRpc5, DceRpc5Bind, DceRpc5Context, DceRpc5AbstractSyntax,
)
from scapy.layers.llmnr import LLMNRResponse
from scapy.layers.netbios import NBTSession
from scapy.layers.smb2 import SMB2_Header, SMB2_Create_Request

from conftest import LOCAL_IP, LOCAL_IP_2, EXTERNAL_IP, find_alerts, has_alert


def _t(pkts, start=1_000_000.0, step=0.01):
    """Stamp packets with increasing timestamps (explicit, not conftest's)."""
    t = start
    for p in pkts:
        p.time = t
        t += step
    return pkts


def _handshake(client, server, sport, dport, t0, data=b""):
    """SYN / SYN-ACK / ACK (+ optional client data) for one TCP connection."""
    pkts = [
        IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="S", seq=100),
        IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="SA", seq=500, ack=101),
        IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=501),
    ]
    if data:
        pkts.append(IP(src=client, dst=server)
                    / TCP(sport=sport, dport=dport, flags="PA", seq=101, ack=501)
                    / Raw(data))
    for i, p in enumerate(pkts):
        p.time = t0 + i * 0.001
    return pkts


# --- Suspicious port: listener vs. ephemeral source port -------------------

def test_suspicious_number_as_ephemeral_source_port_does_not_fire(analyze):
    # HTTPS client that happened to draw sport=65000.
    pkts = _handshake(LOCAL_IP, EXTERNAL_IP, 65000, 443, 1_000_000.0,
                      data=b"\x16\x03\x01" + b"\x00" * 60)
    results = analyze(pkts)
    assert not has_alert(results, title="Suspicious Port 65000")


def test_real_listener_on_4444_fires_critical(analyze):
    pkts = _handshake(EXTERNAL_IP, LOCAL_IP, 51515, 4444, 1_000_000.0,
                      data=b"hello from the handler")
    results = analyze(pkts)
    hits = find_alerts(results, title="Suspicious Port 4444")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["dst_ip"] == LOCAL_IP


# --- Cleartext credentials: server-advertised STARTTLS ---------------------

def test_server_starttls_advert_does_not_mask_cleartext_auth(analyze):
    pkts = _t([
        IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=25, dport=40000, flags="PA")
        / Raw(b"250-mail.example.com\r\n250-STARTTLS\r\n250 AUTH LOGIN PLAIN\r\n"),
        IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=40000, dport=25, flags="PA")
        / Raw(b"AUTH LOGIN\r\n"),
    ])
    results = analyze(pkts)
    hits = find_alerts(results, title="Cleartext Credentials (SMTP)")
    assert hits
    assert hits[0]["severity"] == "critical"


def test_client_starttls_command_suppresses_later_auth(analyze):
    pkts = _t([
        IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=40000, dport=25, flags="PA")
        / Raw(b"STARTTLS\r\n"),
        IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=40000, dport=25, flags="PA")
        / Raw(b"AUTH LOGIN\r\n"),
    ])
    results = analyze(pkts)
    assert not has_alert(results, title="Cleartext Credentials")


# --- Brute force: retries / connection pool / real guessing ----------------

def _conns(client, server, dport, sizes, t0=1_000_000.0, step=1.0):
    pkts = []
    for i, size in enumerate(sizes):
        data = (b"x" * size) if size else b""
        pkts += _handshake(client, server, 50000 + i, dport, t0 + i * step, data=data)
    return pkts


def test_brute_force_syn_only_internal_is_low(analyze):
    pkts = []
    t = 1_000_000.0
    for i in range(12):
        p = IP(src=LOCAL_IP, dst=LOCAL_IP_2) / TCP(sport=50000 + i, dport=22, flags="S")
        p.time = t + i
        pkts.append(p)
    results = analyze(pkts)
    hits = find_alerts(results, title="Brute Force Attack Detected (SSH)")
    assert hits
    assert hits[0]["severity"] == "low"
    assert hits[0]["details"].get("pattern") == "connection_retries"


def test_brute_force_internal_connection_pool_is_low(analyze):
    sizes = [500, 2500, 9000, 3000, 12000, 800, 4000, 15000, 2200, 6000, 700, 20000]
    results = analyze(_conns(LOCAL_IP, LOCAL_IP_2, 5432, sizes))
    hits = find_alerts(results, title="Brute Force Attack Detected (PostgreSQL)")
    assert hits
    assert hits[0]["severity"] == "low"
    assert hits[0]["details"].get("pattern") == "application_traffic"


def test_brute_force_ssh_uniform_sizes_external_stays_high(analyze):
    results = analyze(_conns(EXTERNAL_IP, LOCAL_IP, 22, [900] * 12))
    hits = find_alerts(results, title="Brute Force Attack Detected (SSH)")
    assert hits
    assert hits[0]["severity"] in ("high", "critical")


def test_brute_force_ssh_uniform_sizes_internal_stays_high(analyze):
    results = analyze(_conns(LOCAL_IP, LOCAL_IP_2, 22, [900] * 12))
    hits = find_alerts(results, title="Brute Force Attack Detected (SSH)")
    assert hits
    assert hits[0]["severity"] in ("high", "critical")


# --- Port scan: per (source, target) --------------------------------------

def test_many_peers_one_port_each_is_not_a_port_scan(analyze):
    # P2P / VoIP / NAT: 25 different peers, each on its own port.
    pkts = []
    t = 1_000_000.0
    for i in range(25):
        p = IP(src=LOCAL_IP, dst=f"203.0.113.{i + 1}") / TCP(sport=40000 + i, dport=20000 + i, flags="S")
        p.time = t + i * 0.1
        pkts.append(p)
    results = analyze(pkts)
    assert not has_alert(results, title="Port Scan Detected")


def test_many_ports_on_one_target_is_a_port_scan(analyze):
    pkts = []
    t = 1_000_000.0
    for i in range(25):
        p = IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=40000, dport=1000 + i, flags="S")
        p.time = t + i * 0.1
        pkts.append(p)
    results = analyze(pkts)
    hits = find_alerts(results, title="Port Scan Detected")
    assert hits
    assert hits[0]["details"]["dst_ip"] == LOCAL_IP


# ===========================================================================
# DNS family
# ===========================================================================

_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"


def _rand_label(rng, n):
    return "".join(rng.choice(_ALNUM) for _ in range(n))


def _q(qname, src=LOCAL_IP, dst=EXTERNAL_IP):
    return IP(src=src, dst=dst) / UDP(sport=33333, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))


def _resp(qname, answers=(), rcode=0, ttl=30):
    an = None
    for ip in answers:
        rr = DNSRR(rrname=qname, type="A", rdata=ip, ttl=ttl)
        an = rr if an is None else an / rr
    return (IP(src=EXTERNAL_IP, dst=LOCAL_IP) / UDP(sport=53, dport=33333)
            / DNS(qr=1, rcode=rcode, qd=DNSQR(qname=qname), an=an))


def _tunnel_severity(analyze, n_names):
    rng = random.Random(7)
    pkts = _t([_q(f"{_rand_label(rng, 60)}.tun.example.com") for _ in range(n_names)])
    hits = find_alerts(analyze(pkts), title="DNS Tunneling Suspected")
    assert hits
    return hits[0]["severity"]


def test_dns_tunneling_severity_scales_with_distinct_names(analyze):
    assert _tunnel_severity(analyze, 1) == "medium"
    assert _tunnel_severity(analyze, 3) == "high"
    assert _tunnel_severity(analyze, 10) == "critical"


def test_dns_tunneling_ignores_av_reputation_zone(analyze):
    rng = random.Random(3)
    pkts = _t([_q(f"{_rand_label(rng, 60)}.v2.sophosxl.net") for _ in range(10)])
    assert not has_alert(analyze(pkts), title="DNS Tunneling")


def test_dns_tunneling_detects_payload_split_across_labels(analyze):
    # dnscat2/iodine style: no single label > 50, but the concatenation is long.
    rng = random.Random(11)
    q = ".".join(_rand_label(rng, 40) for _ in range(3)) + ".c2.example.com"
    hits = find_alerts(analyze([_q(q)]), title="DNS Tunneling Suspected")
    assert hits


def test_fast_flux_concentrated_ips_is_low(analyze):
    ips = [f"45.1.10.{i}" for i in range(1, 11)]  # one /16
    hits = find_alerts(analyze([_resp("lb.example.com", ips)]), title="Fast-Flux")
    assert hits
    assert hits[0]["severity"] == "low"


def test_fast_flux_ignores_known_cdn(analyze):
    ips = [f"{23 + i}.{i}.10.{i}" for i in range(1, 11)]
    results = analyze([_resp("e1234.dscx.akamaiedge.net", ips)])
    assert not has_alert(results, title="Fast-Flux")


def test_nxdomain_retries_of_same_name_do_not_fire(analyze):
    pkts = _t([_resp("typo.example.com", rcode=3) for _ in range(30)], step=0.5)
    assert not has_alert(analyze(pkts), title="NXDOMAIN Spike")


def test_nxdomain_ptr_lookups_are_ignored(analyze):
    pkts = _t([_resp(f"{i}.2.0.192.in-addr.arpa", rcode=3) for i in range(30)], step=0.5)
    assert not has_alert(analyze(pkts), title="NXDOMAIN Spike")


# ===========================================================================
# LLMNR / NBT-NS
# ===========================================================================

def _llmnr_responses(names, count):
    pkts = []
    for i in range(count):
        name = names[i % len(names)]
        pkts.append(
            IP(src=LOCAL_IP, dst="10.0.0.100")
            / UDP(sport=5355, dport=50000 + i)
            / LLMNRResponse(qr=1, qdcount=1, ancount=1,
                            qd=DNSQR(qname=name),
                            an=DNSRR(rrname=name, rdata=LOCAL_IP))
        )
    return _t(pkts, step=0.5)


def test_llmnr_host_answering_its_own_name_is_low(analyze):
    hits = find_alerts(analyze(_llmnr_responses(["fileserver01"], 14)), title="LLMNR")
    assert hits
    assert hits[0]["severity"] == "low"


def test_llmnr_answering_many_names_is_critical(analyze):
    names = ["wpad", "fileshare", "printsrv", "intranet", "sqlprod", "backup"]
    hits = find_alerts(analyze(_llmnr_responses(names, 14)), title="LLMNR")
    assert hits
    assert hits[0]["severity"] == "critical"


# ===========================================================================
# ICMP tunneling
# ===========================================================================

def _pings(payload_fn, count=12):
    return _t([
        IP(src=LOCAL_IP, dst=EXTERNAL_IP) / ICMP(type=8, id=1, seq=i) / Raw(payload_fn(i))
        for i in range(count)
    ], step=1.0)


def test_icmp_large_ping_with_windows_filler_is_low(analyze):
    filler = (b"abcdefghijklmnopqrstuvwabcdefghi" * 40)[:1000]
    hits = find_alerts(analyze(_pings(lambda i: filler)), title="Possible ICMP Tunneling")
    assert hits
    assert hits[0]["severity"] == "low"


def test_icmp_random_payload_is_critical(analyze):
    rng = random.Random(5)
    hits = find_alerts(
        analyze(_pings(lambda i: bytes(rng.getrandbits(8) for _ in range(700)))),
        title="Possible ICMP Tunneling")
    assert hits
    assert hits[0]["severity"] == "critical"


# ===========================================================================
# Internal lateral movement: shared servers
# ===========================================================================

def _syns(src, dsts, dport, t0=1_000_000.0):
    return _t([IP(src=src, dst=d) / TCP(sport=45000 + i, dport=dport, flags="S")
               for i, d in enumerate(dsts)], start=t0, step=0.2)


def test_lateral_fanout_to_shared_servers_is_excluded(analyze):
    servers = [f"10.0.1.{i}" for i in range(1, 6)]
    pkts = _syns(LOCAL_IP, servers, 445)
    # Three OTHER workstations use the same servers -> infrastructure.
    for k, other in enumerate(("10.0.0.21", "10.0.0.22", "10.0.0.23")):
        pkts += _syns(other, servers, 445, t0=1_000_100.0 + k * 10)
    assert not has_alert(analyze(pkts), title="Internal Lateral Movement")


def test_lateral_fanout_to_private_peers_fires(analyze):
    peers = [f"10.0.2.{i}" for i in range(1, 6)]
    hits = find_alerts(analyze(_syns(LOCAL_IP, peers, 445)),
                       title="Internal Lateral Movement Suspected (SMB)")
    assert hits
    assert hits[0]["details"]["target_count"] == 5


# ===========================================================================
# SMB named pipes: tiered
# ===========================================================================

def _smb2_create(name, src, dst, sport=40000):
    p = (IP(src=src, dst=dst) / TCP(sport=sport, dport=445, flags="PA")
         / NBTSession() / SMB2_Header(Command=5)
         / SMB2_Create_Request(Buffer=[("Name", name)]))
    p.time = 1_000_000.0 + sport / 1000.0
    return p


def _pipe_hits(results, pipe):
    return [a for a in results["alerts"]
            if a.get("category") == "lateral" and a["details"].get("pipe") == pipe]


def test_internal_lsarpc_pipe_is_low(analyze):
    hits = _pipe_hits(analyze([_smb2_create("lsarpc", LOCAL_IP, LOCAL_IP_2)]), "lsarpc")
    assert hits
    assert hits[0]["severity"] == "low"


def test_svcctl_on_three_hosts_is_critical(analyze):
    pkts = [_smb2_create("svcctl", LOCAL_IP, f"10.0.3.{i}", sport=40000 + i)
            for i in range(1, 4)]
    hits = _pipe_hits(analyze(pkts), "svcctl")
    assert len(hits) == 3
    assert all(h["severity"] == "critical" for h in hits)


def test_single_svcctl_internal_is_high(analyze):
    hits = _pipe_hits(analyze([_smb2_create("svcctl", LOCAL_IP, LOCAL_IP_2)]), "svcctl")
    assert hits and hits[0]["severity"] == "high"


# ===========================================================================
# DCERPC bind: context-aware
# ===========================================================================

_DRSUAPI = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
_MS_RPRN = "12345678-1234-abcd-ef00-0123456789ab"


def _bind(uuid_str, src, dst, sport=40000):
    absyn = DceRpc5AbstractSyntax(if_uuid=uuid.UUID(uuid_str), if_version=1)
    ctx = DceRpc5Context(context_id=0, abstract_syntax=absyn)
    b = DceRpc5Bind(n_context_elem=1, context_elem=[ctx])
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=135, flags="PA") / DceRpc5(ptype=11) / b
    p.time = 1_000_010.0 + sport / 1000.0
    return p


def _kerberos_to(dc, sport):
    p = IP(src="10.0.0.99", dst=dc) / TCP(sport=sport, dport=88, flags="S")
    p.time = 1_000_000.0
    return p


def test_drsr_between_domain_controllers_is_low(analyze):
    pkts = [_kerberos_to(LOCAL_IP, 30001), _kerberos_to(LOCAL_IP_2, 30002),
            _bind(_DRSUAPI, LOCAL_IP, LOCAL_IP_2)]
    hits = find_alerts(analyze(pkts), title="DCERPC Bind")
    assert hits
    assert hits[0]["severity"] == "low"


def test_drsr_from_non_dc_stays_critical(analyze):
    pkts = [_kerberos_to(LOCAL_IP_2, 30002), _bind(_DRSUAPI, LOCAL_IP, LOCAL_IP_2)]
    hits = find_alerts(analyze(pkts), title="DCERPC Bind")
    assert hits and hits[0]["severity"] == "critical"


def test_rprn_to_shared_print_server_is_low(analyze):
    printsrv = "10.0.5.10"
    pkts = [_bind(_MS_RPRN, f"10.0.0.{30 + i}", printsrv, sport=41000 + i) for i in range(3)]
    hits = find_alerts(analyze(pkts), title="DCERPC Bind")
    assert len(hits) == 3
    assert all(h["severity"] == "low" for h in hits)


def test_rprn_single_client_keeps_base_severity(analyze):
    hits = find_alerts(analyze([_bind(_MS_RPRN, LOCAL_IP, "10.0.5.10")]), title="DCERPC Bind")
    assert hits and hits[0]["severity"] != "low"


# ===========================================================================
# SNMP polling / ping monitoring
# ===========================================================================

def test_recurring_snmp_polling_is_low(analyze):
    pkts = []
    for burst in range(3):
        t0 = 1_000_000.0 + burst * 300
        for i in range(60):
            p = IP(src=LOCAL_IP, dst="10.0.0.200") / UDP(sport=40000 + i, dport=161)
            p.time = t0 + i * 0.1
            pkts.append(p)
    hits = find_alerts(analyze(pkts), title="SNMP Walk")
    assert hits and hits[0]["severity"] == "low"


def test_single_snmp_walk_is_high(analyze):
    pkts = _t([IP(src=LOCAL_IP, dst="10.0.0.200") / UDP(sport=40000 + i, dport=161)
               for i in range(60)], step=0.1)
    hits = find_alerts(analyze(pkts), title="SNMP Walk")
    assert hits and hits[0]["severity"] == "high"


def test_monitoring_ping_pattern_is_low(analyze):
    targets = [f"10.0.4.{i}" for i in range(1, 17)]
    pkts = []
    for rnd in range(5):  # 5 rounds, 100 s apart -> 400 s, 5 echoes per target
        for k, dst in enumerate(targets):
            p = IP(src=LOCAL_IP, dst=dst) / ICMP(type=8, id=1, seq=rnd)
            p.time = 1_000_000.0 + rnd * 100 + k * 0.1
            pkts.append(p)
    hits = find_alerts(analyze(pkts), title="ICMP Ping Sweep")
    assert hits and hits[0]["severity"] == "low"


def test_discovery_ping_sweep_is_high(analyze):
    pkts = _t([IP(src=LOCAL_IP, dst=f"10.0.4.{i}") / ICMP(type=8) for i in range(1, 21)],
              step=0.1)
    hits = find_alerts(analyze(pkts), title="ICMP Ping Sweep")
    assert hits and hits[0]["severity"] == "high"


# ===========================================================================
# Multicast is not "external" (no slow-drip exfil to SSDP/mDNS)
# ===========================================================================

_DRIP = {"thresholds": {"sustained_exfil_min_bytes": 20_000,
                        "sustained_exfil_min_duration": 300.0}}


def _udp_drip(dst):
    return _t([IP(src=LOCAL_IP, dst=dst) / UDP(sport=1900, dport=1900) / Raw(b"M" * 1000)
               for _ in range(40)], step=10.0)


def test_multicast_ssdp_is_not_sustained_exfil(analyze):
    results = analyze(_udp_drip("239.255.255.250"), _DRIP)
    assert not has_alert(results, title="Sustained Exfiltration")


def test_unicast_external_drip_is_sustained_exfil(analyze):
    results = analyze(_udp_drip(EXTERNAL_IP), _DRIP)
    assert has_alert(results, title="Sustained Exfiltration")


def test_multicast_is_not_external():
    from pcap_analyzer import PCAPAnalyzer
    for ip in ("239.255.255.250", "224.0.0.251", "ff02::fb", "169.254.1.1",
               "100.64.3.4", "127.0.0.1"):
        assert PCAPAnalyzer._is_local_ip(ip), ip
    assert not PCAPAnalyzer._is_local_ip("8.8.8.8")


# ===========================================================================
# DNS answers feed _hostname_index
# ===========================================================================

def test_dns_answers_populate_hostname_index(tmp_path):
    from pcap_analyzer import PCAPAnalyzer
    from conftest import build_pcap

    pkt = _resp("updates.example-vendor.com", ["198.51.100.7"])
    pkt.time = 1_000_000.0
    path = tmp_path / "dns.pcap"
    build_pcap([pkt], str(path))
    analyzer = PCAPAnalyzer(str(path), {})
    analyzer.analyze()
    names = analyzer._hostname_index().get("198.51.100.7") or set()
    assert "updates.example-vendor.com" in names
