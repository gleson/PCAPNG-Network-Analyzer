"""IPv6 coverage for the streaming detectors.

pkt_view historically keyed the IPv6 header view only under scapy's IPv6
class, while every detector gates on `IP in pkt` — so ALL IPv6 traffic
(scans, exfil, beacons, brute force) was invisible. The view is now
dual-keyed under IP, making v6 transparent to the whole registry.

Address choice mirrors the conftest note for v4: Python's ipaddress treats
the 2001:db8::/32 documentation range as private, so the "external" side
must be a genuinely global address (Google DNS 2001:4860:4860::8888) and
the "local" side a ULA (fd00::/8).
"""

from scapy.all import IPv6, TCP
from scapy.layers.inet6 import ICMPv6EchoRequest

from conftest import find_alerts, has_alert

LOCAL_V6 = "fd00::5"
EXTERNAL_V6 = "2001:4860:4860::8888"


def test_ipv6_port_scan_fires(analyze):
    packets = []
    t = 1_000_000.0
    for port in range(20, 45):  # 25 distinct ports >= threshold 20
        pk = IPv6(src=EXTERNAL_V6, dst=LOCAL_V6) / TCP(
            sport=55555, dport=port, flags="S"
        )
        pk.time = t
        t += 0.01
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Port Scan Detected", category="scan")
    assert hits, "IPv6 SYN scan must be visible to the port-scan detector"
    assert hits[0]["details"]["src_ip"] == EXTERNAL_V6
    assert EXTERNAL_V6 in hits[0]["src_ips"]


def test_ipv6_ping_sweep_fires(analyze):
    packets = []
    t = 1_000_000.0
    for host in range(1, 17):  # 16 targets >= threshold 15
        pk = IPv6(src=LOCAL_V6, dst=f"fd00::1:{host:x}") / ICMPv6EchoRequest()
        pk.time = t
        t += 0.5
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="ICMP Ping Sweep", category="scan")
    assert hits, "ICMPv6 echo sweep must be visible to the ping-sweep detector"
    assert hits[0]["details"]["targets_count"] >= 15


def test_ipv6_beaconing_fires(analyze):
    packets = []
    t = 1_000_000.0
    for i in range(6):  # 6 connections at exact 60s intervals, zero jitter
        pk = IPv6(src=LOCAL_V6, dst=EXTERNAL_V6) / TCP(
            sport=40000 + i, dport=443, flags="S"
        )
        pk.time = t
        t += 60.0
        packets.append(pk)
    results = analyze(packets)
    assert has_alert(results, title="Beaconing Behavior Detected")


def test_clean_ipv6_traffic_stays_quiet(analyze):
    # A few ordinary v6 HTTPS handshakes: no scan/exfil alerts.
    packets = []
    t = 1_000_000.0
    for i in range(4):
        packets.append(IPv6(src=LOCAL_V6, dst=EXTERNAL_V6) / TCP(
            sport=40000 + i, dport=443, flags="S"))
        packets.append(IPv6(src=EXTERNAL_V6, dst=LOCAL_V6) / TCP(
            sport=443, dport=40000 + i, flags="SA"))
        packets.append(IPv6(src=LOCAL_V6, dst=EXTERNAL_V6) / TCP(
            sport=40000 + i, dport=443, flags="A"))
    for p in packets:
        p.time = t
        t += 7.0
    results = analyze(packets)
    cats = {a.get("category") for a in results.get("alerts", [])}
    assert "scan" not in cats
    assert "exfil" not in cats
