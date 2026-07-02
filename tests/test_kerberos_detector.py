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


# --- AS-REP Roasting ---------------------------------------------------------

_KDC = "10.0.0.10"
# PA-DATA padata-type [1] INTEGER 2 = PA-ENC-TIMESTAMP (normal pre-auth logon).
_PA_ENC_TS = b"\xa1\x03\x02\x01\x02"


def _krb_msg(tag, extra=b"", src=LOCAL_IP, dst=_KDC, sport=40000, dport=88):
    """TCP/88 Kerberos message: 4-byte length prefix + tag + filler + extra."""
    body = bytes([tag, 0x82, 0x01, 0x00]) + b"\x30\x82" + b"\x00" * 20 + extra + b"\x00" * 40
    wire = len(body).to_bytes(4, "big") + body
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(wire)


def _asrep_alerts(results):
    return [a for a in results["alerts"] if "AS-REP Roasting" in a["title"]]


def test_asrep_roasting_fires_when_requests_lack_preauth(analyze):
    # Roasting profile: AS-REQs without PA-ENC-TIMESTAMP answered directly by
    # AS-REPs, zero PREAUTH_REQUIRED errors (GetNPUsers / kerbrute).
    pkts = []
    for i in range(5):
        pkts.append(_krb_msg(0x6A, sport=40000 + i))
        pkts.append(_krb_msg(0x6B, src=_KDC, dst=LOCAL_IP, sport=88, dport=40000 + i))
    results = analyze(pkts)
    hits = _asrep_alerts(results)
    assert hits
    assert hits[0]["details"]["as_req_with_preauth"] == 0


def test_asrep_with_preauth_requests_does_not_fire(analyze):
    # Regression (2026-07): clients with cached pre-auth send PA-ENC-TIMESTAMP
    # in their FIRST AS-REQ, so a busy KDC produced 5+ AS-REPs with zero
    # PREAUTH_REQUIRED errors in the window — the old trigger fired on every
    # mid-stream capture of normal logons.
    pkts = []
    for i in range(5):
        pkts.append(_krb_msg(0x6A, extra=_PA_ENC_TS, sport=41000 + i))
        pkts.append(_krb_msg(0x6B, src=_KDC, dst=LOCAL_IP, sport=88, dport=41000 + i))
    results = analyze(pkts)
    assert not _asrep_alerts(results)


def test_asrep_only_capture_does_not_fire(analyze):
    # One-sided tap: responses alone cannot prove the requests lacked
    # pre-auth (documented recall trade-off of the FP fix).
    pkts = [
        _krb_msg(0x6B, src=_KDC, dst=LOCAL_IP, sport=88, dport=42000 + i)
        for i in range(6)
    ]
    results = analyze(pkts)
    assert not _asrep_alerts(results)
