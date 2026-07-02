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


def test_port_scan_inbound_external_is_critical(analyze):
    # external source -> internal host: attacker mapping our attack surface.
    packets = []
    t = 1_000_000.0
    for port in range(20, 50):
        pk = IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=44444, dport=port, flags="S")
        pk.time = t
        t += 0.01
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Port Scan", category="scan")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["direction"] == "inbound"


def test_port_scan_outbound_local_is_medium(analyze):
    # internal host -> external host: local box scanning the internet
    # (tool/misconfig/compromise) — suspicious but not auto-critical.
    packets = []
    t = 1_000_000.0
    for port in range(20, 50):
        pk = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=44444, dport=port, flags="S")
        pk.time = t
        t += 0.01
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Port Scan", category="scan")
    assert hits
    assert hits[0]["severity"] == "medium"
    assert hits[0]["details"]["direction"] == "outbound"


def test_port_scan_internal_to_internal_is_high(analyze):
    # internal -> internal: lateral recon.
    packets = []
    t = 1_000_000.0
    for port in range(20, 50):
        pk = IP(src=LOCAL_IP, dst="10.0.0.200") / TCP(sport=44444, dport=port, flags="S")
        pk.time = t
        t += 0.01
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Port Scan", category="scan")
    assert hits
    assert hits[0]["severity"] == "high"
    assert hits[0]["details"]["direction"] == "internal"


def test_port_scan_outbound_with_nmap_fingerprint_bumped_to_high(analyze):
    # outbound (medium) + nmap fingerprint -> bumped one notch to high.
    packets = []
    t = 1_000_000.0
    for port in range(20, 50):
        pk = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(
            sport=44444, dport=port, flags="S", window=1024,
            options=[("MSS", 1460), ("SAckOK", b"")],
        )
        pk.time = t
        t += 0.01
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Port Scan", category="scan")
    assert hits
    assert hits[0]["details"]["nmap_fingerprint"] is True
    assert hits[0]["severity"] == "high"


def test_port_scan_nmap_fingerprint_fires(analyze):
    # nmap -sS default profile: window=1024, options MSS+SAckOK, never
    # Timestamp/WScale. Regression: PktView dropped window/options, so the
    # fingerprint heuristic silently never fired on real captures.
    packets = []
    t = 1_000_000.0
    for port in range(20, 50):
        pk = IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(
            sport=44444, dport=port, flags="S", window=1024,
            options=[("MSS", 1460), ("SAckOK", b"")],
        )
        pk.time = t
        t += 0.01
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Port Scan", category="scan")
    assert hits
    assert hits[0]["details"]["nmap_fingerprint"] is True
    assert "nmap fingerprint" in hits[0]["title"]
    assert hits[0]["details"]["syn_window"] == 1024


def test_port_scan_real_stack_has_no_nmap_fingerprint(analyze):
    # A real OS stack sends Timestamp/WScale — must NOT be tagged as nmap.
    packets = []
    t = 1_000_000.0
    for port in range(20, 50):
        pk = IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(
            sport=44444, dport=port, flags="S", window=64240,
            options=[("MSS", 1460), ("SAckOK", b""),
                     ("Timestamp", (100, 0)), ("WScale", 7)],
        )
        pk.time = t
        t += 0.01
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Port Scan", category="scan")
    assert hits
    assert hits[0]["details"]["nmap_fingerprint"] is False


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


def _syn_ack(src, dst, sport, dport, t):
    pk = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="SA")
    pk.time = t
    return pk


def test_horizontal_scan_one_sided_capture_capped_high(analyze):
    # 29 hosts on 445, NO SYN-ACK anywhere in the capture (asymmetric/
    # egress-only tap). The old code called this critical purely because
    # answer_ratio was 0; with no return-path visibility it is now capped at
    # high and annotated, so a benign server polling many hosts on a one-sided
    # tap isn't auto-critical.
    packets = []
    t = 1_000_000.0
    for host in range(1, 30):  # 29 hosts < slow_multiplier*threshold (60)
        pk = IP(src=LOCAL_IP, dst=f"10.0.50.{host}") / TCP(sport=51000, dport=445, flags="S")
        pk.time = t
        t += 0.1
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Horizontal Port Scan")
    assert hits
    assert hits[0]["severity"] == "high"
    assert hits[0]["details"]["capture_one_sided"] is True
    assert hits[0]["details"]["answer_ratio"] is None


def test_horizontal_scan_two_sided_low_answer_is_critical(analyze):
    # Same 29-host sweep, but the capture DOES see return traffic elsewhere
    # (one unrelated completed handshake) -> two-sided tap. The scan record's
    # own answer_ratio is 0 (< critical threshold) -> critical, as before.
    packets = []
    t = 1_000_000.0
    for host in range(1, 30):
        pk = IP(src=LOCAL_IP, dst=f"10.0.50.{host}") / TCP(sport=51000, dport=445, flags="S")
        pk.time = t
        t += 0.1
        packets.append(pk)
    # Unrelated inbound SYN-ACK proves the tap sees the return path.
    packets.append(_syn_ack("10.0.0.9", "10.0.0.5", 443, 52000, t))
    results = analyze(packets)
    hits = find_alerts(results, title="Horizontal Port Scan")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["capture_one_sided"] is False


def test_horizontal_scan_massive_fanout_one_sided_still_critical(analyze):
    # >=60 hosts (threshold 20 * slow_multiplier 3) on a one-sided tap: fan-out
    # magnitude alone justifies critical even without handshake confirmation.
    packets = []
    t = 1_000_000.0
    for host in range(1, 65):  # 64 hosts >= 60
        pk = IP(src=LOCAL_IP, dst=f"10.0.60.{host}") / TCP(sport=51000, dport=445, flags="S")
        pk.time = t
        t += 0.1
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Horizontal Port Scan")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["capture_one_sided"] is True


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
