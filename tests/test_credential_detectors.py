"""Brute force, password-spraying-adjacent, and cleartext-credential detectors."""

import base64

from scapy.all import IP, TCP, Raw

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert


def test_ssh_brute_force_fires(analyze):
    # Default: >=10 SYN attempts to a target port within 60s from one source.
    packets = []
    t = 1_000_000.0
    for i in range(12):
        pk = IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=50000 + i, dport=22, flags="S")
        pk.time = t
        t += 1.0
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Brute Force", category="brute_force")
    assert hits
    assert "SSH" in hits[0]["title"]
    assert hits[0]["details"]["total_attempts"] >= 10


def test_few_ssh_attempts_do_not_fire(analyze):
    packets = []
    t = 1_000_000.0
    for i in range(5):  # below threshold
        pk = IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=50000 + i, dport=22, flags="S")
        pk.time = t
        t += 1.0
        packets.append(pk)
    results = analyze(packets)
    assert not has_alert(results, title="Brute Force")


def test_cleartext_ftp_credentials_fire(analyze):
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=40000, dport=21, flags="PA") / Raw(b"USER admin\r\n")
    results = analyze([pkt])
    hits = find_alerts(results, title="Cleartext Credentials", category="protocol")
    assert hits
    assert "FTP" in hits[0]["title"]


def test_cleartext_http_basic_auth_fires(analyze):
    # Guards the HTTP-Raw resurrection: scapy parses TCP/80 into the HTTP layer
    # (no Raw); pkt_view re-exposes the payload so the Basic header is seen.
    cred = base64.b64encode(b"admin:secret").decode()
    payload = f"GET /admin HTTP/1.1\r\nHost: t\r\nAuthorization: Basic {cred}\r\n\r\n".encode()
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=40001, dport=80, flags="PA") / Raw(payload)
    results = analyze([pkt])
    hits = find_alerts(results, title="Cleartext Credentials")
    assert hits
    assert "HTTP" in hits[0]["title"]
