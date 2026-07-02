"""KnownBadJa4 (client JA4 / server JA4S) matching and IPv6 NDP spoofing.

JA4 is not practical to forge byte-accurately with scapy, so — as with the
JA3 test — we let the engine compute the JA4 from a crafted ClientHello, then
re-run declaring that fingerprint malicious via settings. NDP is deterministic
and built directly from ICMPv6 Neighbor Advertisements.
"""

from scapy.all import IP, TCP, Raw, IPv6
from scapy.layers.inet6 import (
    ICMPv6ND_NA, ICMPv6NDOptDstLLAddr,
)

from pcap_analyzer import PCAPAnalyzer
from conftest import LOCAL_IP, EXTERNAL_IP, build_pcap, find_alerts, has_alert

MAC_A = "aa:bb:cc:00:00:01"
MAC_B = "aa:bb:cc:00:00:02"
V6_TGT = "fd00::50"


# --- JA4 / JA4S -------------------------------------------------------------

def _client_hello(sni="example.com", sport=44100):
    sni_b = sni.encode()
    server_name = b"\x00" + len(sni_b).to_bytes(2, "big") + sni_b
    sni_list = len(server_name).to_bytes(2, "big") + server_name
    ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    exts = len(ext).to_bytes(2, "big") + ext
    body = (
        b"\x03\x03" + b"\x00" * 32 + b"\x00"
        + b"\x00\x02\x00\x2f"
        + b"\x01\x00"
        + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs
    pk = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=sport, dport=443, flags="PA") / Raw(rec)
    pk.time = 1_000_000.0
    return pk


def test_known_bad_ja4_fires(analyze, tmp_path):
    ch = _client_hello()
    # Discover the JA4 the engine computes.
    pcap = build_pcap([ch], tmp_path / "ja4.pcap")
    a = PCAPAnalyzer(pcap, {})
    a.analyze()
    chs = (a._tls_info or {}).get("client_hellos") or []
    assert chs and chs[0].get("ja4"), "engine must compute a JA4 for the fixture"
    ja4 = chs[0]["ja4"]

    results = analyze([_client_hello()], {"known_malicious_ja4": {ja4: "Test C2"}})
    hits = find_alerts(results, title="Known Malicious JA4", category="tls")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["ja4"] == ja4
    assert hits[0]["details"]["matches"] == "Test C2"


def test_unknown_ja4_does_not_fire(analyze):
    results = analyze([_client_hello()], {"known_malicious_ja4": {"tXXd0000_deadbeef_cafebabe": "nope"}})
    assert not has_alert(results, title="Known Malicious JA4")


# --- IPv6 NDP spoofing ------------------------------------------------------

def _na(tgt, mac, override=1, src="fd00::9"):
    return IPv6(src=src) / ICMPv6ND_NA(tgt=tgt, R=0, S=0, O=override) / ICMPv6NDOptDstLLAddr(lladdr=mac)


def test_ndp_mac_conflict_is_critical(analyze):
    packets = [_na(V6_TGT, MAC_A), _na(V6_TGT, MAC_B)]
    results = analyze(packets)
    hits = find_alerts(results, title="IPv6 NDP Spoofing", category="arp")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["old_mac"] == MAC_A
    assert hits[0]["details"]["new_mac"] == MAC_B


def test_stable_ndp_does_not_fire(analyze):
    packets = [_na(V6_TGT, MAC_A, override=0) for _ in range(3)]
    results = analyze(packets)
    assert not has_alert(results, title="IPv6 NDP Spoofing")


def test_unsolicited_na_flood_fires(analyze):
    # 5 override NAs from one MAC -> flood (threshold default 5).
    packets = [_na(f"fd00::{i:x}", MAC_A, override=1) for i in range(1, 6)]
    results = analyze(packets)
    hits = find_alerts(results, title="Unsolicited IPv6 NA Flood", category="arp")
    assert hits
    assert hits[0]["details"]["count"] >= 5
