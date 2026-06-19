"""Post-detectors that read non-HTTP aggregator output.

- HighVolumeQuicNewDestDetector: reads results['quic_flows'] (QuicHttp2
  aggregator). QUIC is identified by the RFC 9000 long-header form (high bit
  of byte 0 set) + a known version. The cross-scan "newness" DB lookup fails
  safe offline, so a fresh dest always counts as new.
- IpMacChangesDetector: reads results['ip_mac_mapping'] (MacIp aggregator);
  a local IP bound to two MACs in one capture -> spoofing/churn.
"""

from scapy.all import IP, TCP, UDP, Raw, Ether

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert


# --- HighVolumeQuicNewDest -------------------------------------------------

def _quic(dst=EXTERNAL_IP, sport=55555):
    # Long-header (0xc0), version 0x00000001 (QUIC v1), padded.
    payload = b"\xc0\x00\x00\x00\x01" + b"\x00" * 20
    return IP(src=LOCAL_IP, dst=dst) / UDP(sport=sport, dport=443) / Raw(payload)


def test_high_volume_quic_new_dest_fires(analyze):
    # Lower the packet threshold so a handful of QUIC packets crosses it.
    packets = [_quic() for _ in range(4)]
    results = analyze(packets, settings={"thresholds": {"quic_high_volume_packets": 3}})
    hits = find_alerts(results, title="High-volume QUIC to new destination")
    assert hits
    assert hits[0]["details"]["destination"] == EXTERNAL_IP
    assert "quic_v1" in hits[0]["details"]["versions"]


def test_low_volume_quic_does_not_fire(analyze):
    # One packet, default thresholds -> below both byte and packet floors.
    results = analyze([_quic()])
    assert not has_alert(results, title="High-volume QUIC to new destination")


# --- IpMacChanges ----------------------------------------------------------

def test_local_ip_with_two_macs_is_high(analyze):
    packets = [
        Ether(src="aa:bb:cc:00:00:01") / IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=1, dport=80, flags="S"),
        Ether(src="aa:bb:cc:00:00:02") / IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=2, dport=80, flags="S"),
    ]
    results = analyze(packets)
    hits = find_alerts(results, title="IP with Multiple MAC Addresses", category="mac")
    assert hits
    assert hits[0]["severity"] == "high"
    assert hits[0]["details"]["mac_count"] >= 2


def test_single_mac_does_not_fire(analyze):
    packets = [
        Ether(src="aa:bb:cc:00:00:01") / IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=1, dport=80, flags="S"),
        Ether(src="aa:bb:cc:00:00:01") / IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=2, dport=80, flags="S"),
    ]
    results = analyze(packets)
    assert not has_alert(results, title="IP with Multiple MAC Addresses")
