"""Positive tests for the scan / reconnaissance detector family.

Each test builds the minimal traffic that crosses the detector's default
threshold (see the detector __init__ in pcap_analyzer/detectors/__init__.py).
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert


def test_port_scan_fires(analyze):
    # Default: >=20 distinct ports within a 30s window from one source.
    packets = []
    t = 1_000_000.0
    for port in range(20, 50):  # 30 ports
        pk = IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=44444, dport=port, flags="S")
        pk.time = t
        t += 0.01
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Port Scan", category="scan")
    assert hits, "expected a Port Scan alert"
    assert hits[0]["ip"] == EXTERNAL_IP
    assert hits[0]["details"]["ports_count"] >= 20


def test_ping_sweep_fires(analyze):
    # Default: ICMP echo (type 8) to >=15 distinct hosts within 60s.
    packets = []
    t = 1_000_000.0
    for host in range(1, 25):  # 24 hosts
        pk = IP(src=LOCAL_IP, dst=f"10.0.0.{host}") / ICMP(type=8)
        pk.time = t
        t += 0.1
        packets.append(pk)
    results = analyze(packets)
    assert has_alert(results, title="Ping Sweep", category="scan")


def test_horizontal_scan_fires(analyze):
    # Default: SYN to one port across >=20 distinct hosts, low answer ratio.
    # Use a non-web port (445) so internal-only filtering does not apply.
    packets = []
    t = 1_000_000.0
    for host in range(1, 30):  # 29 hosts, no SYN-ACK replies
        pk = IP(src=LOCAL_IP, dst=f"10.0.50.{host}") / TCP(sport=51000, dport=445, flags="S")
        pk.time = t
        t += 0.1
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Horizontal Port Scan")
    assert hits
    # No handshakes completed -> critical.
    assert hits[0]["severity"] == "critical"


def test_snmp_walk_fires(analyze):
    # Default: >=50 UDP/161 queries to one host within a 30s window.
    packets = []
    t = 1_000_000.0
    for i in range(60):
        pk = IP(src=LOCAL_IP, dst="10.0.0.200") / UDP(sport=40000 + i, dport=161)
        pk.time = t
        t += 0.1
        packets.append(pk)
    results = analyze(packets)
    assert has_alert(results, title="SNMP Walk", category="scan")


def test_arp_host_discovery_fires(analyze):
    # Default: >=10 distinct ARP who-has targets from a non-gateway source.
    # Source must not end in .1/.254 (heuristic gateway filter).
    packets = []
    t = 1_000_000.0
    for host in range(2, 20):  # 18 targets
        pk = Ether() / ARP(op=1, psrc="10.0.0.50", pdst=f"10.0.0.{host}")
        pk.time = t
        t += 0.1
        packets.append(pk)
    results = analyze(packets)
    assert has_alert(results, category="scan") or has_alert(results, title="ARP")


def test_single_port_probe_does_not_fire(analyze):
    # Below threshold: only 5 ports -> no Port Scan alert.
    packets = []
    t = 1_000_000.0
    for port in (22, 80, 443, 3389, 8080):
        pk = IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=44444, dport=port, flags="S")
        pk.time = t
        t += 0.01
        packets.append(pk)
    results = analyze(packets)
    assert not has_alert(results, title="Port Scan")
