"""Regression tests for KerberosAbuseStreamingDetector.

Bug found 2026-06-19: scapy dissects TCP/88 into KerberosTCPHeader (+ a
Kerberos ASN.1 layer for valid messages), stripping the 4-byte RFC4120 length
prefix and often removing the Raw layer entirely. The detector read
`pkt[Raw].load` then skipped 4 bytes for the prefix — so on scapy-parsed
captures it saw nothing (Raw gone) or a misaligned remainder (double-skip).
pkt_view now re-exposes the full TCP payload as Raw; these tests guard it.

A deliberately-malformed ASN.1 body is used so scapy leaves the message bytes
intact (the realistic semi-parse case); the detector's shallow byte-scan only
needs the application tag + the etype INTEGER signature.
"""

from scapy.all import IP, TCP, Raw

from conftest import LOCAL_IP


# eTYPE INTEGER encodings: RC4-HMAC=23 -> 02 01 17, AES256=18 -> 02 01 12.
_RC4_SIG = b"\x02\x01\x17"


def _krb_tcp(tag, etype_sig, src=LOCAL_IP, dst="10.0.0.10", sport=40000):
    """Build a TCP/88 segment carrying a Kerberos message with a 4-byte
    length prefix, the application tag, and an etype signature."""
    body = bytes([tag, 0x82, 0x01, 0x00]) + b"\x30\x82" + b"\x00" * 20 + etype_sig + b"\x00" * 40
    wire = len(body).to_bytes(4, "big") + body
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=88, flags="PA") / Raw(wire)


def test_kerberoasting_rc4_tgs_req_fires(analyze):
    # Tag 0x6c = TGS-REQ; RC4-only -> Kerberoasting (single request -> high).
    pkt = _krb_tcp(0x6C, _RC4_SIG)
    pkt.time = 1_000_000.0
    results = analyze([pkt])
    hits = [a for a in results["alerts"] if "Kerberoasting" in a["title"]]
    assert hits, "expected a Kerberoasting alert"
    assert hits[0]["category"] == "brute_force"
    assert hits[0]["details"]["tgs_req_rc4_only"] >= 1


def test_aes_tgs_req_does_not_fire_kerberoasting(analyze):
    # AES etype only -> legitimate modern AD, no Kerberoasting.
    pkt = _krb_tcp(0x6C, b"\x02\x01\x12")  # AES256
    pkt.time = 1_000_000.0
    results = analyze([pkt])
    assert not [a for a in results["alerts"] if "Kerberoasting" in a["title"]]
