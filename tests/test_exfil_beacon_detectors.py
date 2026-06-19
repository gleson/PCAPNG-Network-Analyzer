"""Tests for the exfiltration and beaconing detectors.

Volume exfil's default threshold is 10 MB; building that as real packet bytes
in a unit test is wasteful, so the threshold is lowered via settings. This
still exercises the byte-accounting, out/in ratio and alert-emission logic —
the threshold value itself is a config knob, not detection logic.
"""

from scapy.all import IP, TCP, Raw

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert


def test_volume_exfiltration_fires(analyze):
    settings = {"thresholds": {"exfil_min_bytes_out": 50_000, "exfil_min_ratio": 5.0}}
    packets = []
    t = 1_000_000.0
    payload = b"A" * 10_000
    # ~100 KB out, almost nothing in -> ratio well above 5x.
    for i in range(12):
        pk = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=51000, dport=443, flags="PA") / Raw(payload)
        pk.time = t
        t += 1.0
        packets.append(pk)
    # one small inbound packet
    ack = IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=443, dport=51000, flags="A")
    ack.time = t
    packets.append(ack)

    results = analyze(packets, settings)
    hits = find_alerts(results, category="exfil", title="Exfiltration")
    assert hits
    assert hits[0]["ip"] == LOCAL_IP
    assert hits[0]["details"]["bytes_out"] >= 50_000
    assert hits[0]["details"]["ratio"] >= 5.0


def test_beaconing_fires_on_regular_intervals(analyze):
    # Default: >=5 connections; perfectly regular intervals -> 0% jitter,
    # below the 10% jitter ceiling.
    packets = []
    t = 1_000_000.0
    for i in range(12):
        pk = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=52000 + i, dport=443, flags="S")
        pk.time = t
        t += 60.0  # exact 60s beacon
        packets.append(pk)
    results = analyze(packets)
    assert has_alert(results, category="beaconing")
