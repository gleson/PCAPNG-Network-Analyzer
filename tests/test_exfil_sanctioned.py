"""Sanctioned-destination downgrade for the volume/ratio exfil detectors.

A large local->external upload to a destination that resolves (via TLS SNI or
HTTP Host seen in the SAME capture) to a sanctioned bulk service — cloud
backup, OS update, CDN, video/conferencing — is downgraded one severity notch
and annotated, NOT suppressed (attackers abuse cloud services too).
"""

from scapy.all import IP, TCP, Raw, UDP, DNS, DNSQR

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts

# Lowered so a compact fixture crosses the volume threshold.
_SETTINGS = {"thresholds": {"exfil_min_bytes_out": 200_000, "exfil_min_ratio": 5.0}}


def _upload(dst, mb_out=1.0, sport=40000):
    """~mb_out MiB out, a little in, local->external."""
    packets = []
    t = 1_000_000.0
    n = int(mb_out * 1024 * 1024 / 1400)
    for i in range(n):
        pk = IP(src=LOCAL_IP, dst=dst) / TCP(sport=sport, dport=443, flags="PA") / Raw(b"X" * 1400)
        pk.time = t
        t += 0.01
        packets.append(pk)
    # a trickle of inbound so ratio is finite and > threshold
    for i in range(3):
        pk = IP(src=dst, dst=LOCAL_IP) / TCP(sport=443, dport=sport, flags="A") / Raw(b"Y" * 100)
        pk.time = t
        t += 0.01
        packets.append(pk)
    return packets


def _client_hello_to(dst, sni, sport=40000):
    """Minimal TLS ClientHello carrying `sni`, client(LOCAL)->server(dst)."""
    # server_name extension: type 0x0000, one host_name entry.
    sni_b = sni.encode()
    server_name = b"\x00" + len(sni_b).to_bytes(2, "big") + sni_b
    sni_list = len(server_name).to_bytes(2, "big") + server_name
    ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    exts = len(ext).to_bytes(2, "big") + ext
    body = (
        b"\x03\x03" + b"\x00" * 32 + b"\x00"      # version + random + sid len
        + b"\x00\x02\x00\x2f"                      # cipher suites
        + b"\x01\x00"                              # compression
        + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs
    pk = IP(src=LOCAL_IP, dst=dst) / TCP(sport=sport, dport=443, flags="PA") / Raw(rec)
    pk.time = 999_999.0
    return pk


def test_exfil_to_unknown_dest_stays_high(analyze):
    results = analyze(_upload(EXTERNAL_IP, mb_out=1.0), _SETTINGS)
    hits = find_alerts(results, title="Possible Data Exfiltration")
    assert hits
    assert hits[0]["severity"] in ("high", "medium")
    assert not hits[0]["details"].get("likely_sanctioned")


def test_exfil_to_sanctioned_dest_is_downgraded(analyze):
    # ClientHello reveals the dst is dl.google.com (sanctioned bulk).
    packets = [_client_hello_to(EXTERNAL_IP, "dl.google.com")] + _upload(EXTERNAL_IP, mb_out=1.0)
    results = analyze(packets, _SETTINGS)
    hits = find_alerts(results, title="Possible Data Exfiltration")
    assert hits
    a = hits[0]
    assert a["details"]["likely_sanctioned"] is True
    assert a["details"]["sanctioned_match"] == "dl.google.com"
    # Downgraded from the un-annotated severity.
    assert a["details"]["severity_original"] in ("high", "medium")
    ladder = ["info", "low", "medium", "high", "critical"]
    assert ladder.index(a["severity"]) == ladder.index(a["details"]["severity_original"]) - 1


def test_exfil_to_fileshare_not_downgraded(analyze):
    # dropbox is a file-share (exfil channel) — NOT in the sanctioned list,
    # so it must keep full severity even though hostname is known.
    packets = [_client_hello_to(EXTERNAL_IP, "dropbox.com")] + _upload(EXTERNAL_IP, mb_out=1.0)
    results = analyze(packets, _SETTINGS)
    hits = find_alerts(results, title="Possible Data Exfiltration")
    assert hits
    assert not hits[0]["details"].get("likely_sanctioned")
    assert "dropbox.com" in hits[0]["details"].get("dest_hostnames", [])
