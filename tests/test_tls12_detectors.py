"""TLS 1.2 post-detectors: certificate, DoH, ALPN/port, obsolete version.

These need a TLS 1.2 handshake because the cert is sent in the clear (TLS 1.3
encrypts it). ``fixtures/tls12_handshake.pcap`` holds a real ClientHello
(TLS 1.2, ALPN h2, SNI ``settings-win.data.microsoft.com``) plus a real
``*.msedge.net`` Certificate message reassembled into a single record, with
IP/TCP addressing rewritten to the suite constants. The two were captured from
different real flows and paired on purpose: a client asking for one host while
the server presents a cert for another is exactly the CN/SNI-mismatch the
detector exists to catch (domain fronting / interception), and it fires
deterministically without depending on the wall clock.

- ``test_certificate_*``    -> TlsCertificateDetector (CN/SNI mismatch)
- ``test_doh_*``            -> DohDetector (SNI matches an operator DoH host)
- ``test_alpn_*``           -> AlpnPortInconsistencyDetector (h2 on a DB port)
- ``test_obsolete_tls_*``   -> OldTlsVersionDetector (synthetic TLS 1.0 hello)
"""

import os
import struct

from scapy.all import IP, TCP, Raw, rdpcap

from pcap_analyzer import PCAPAnalyzer
from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "tls12_handshake.pcap")
# The ClientHello packet's TLS bytes (record + handshake), reused below to
# re-stage the same fingerprint on a different TCP port.
_CH_LOAD = bytes(rdpcap(FIXTURE)[0][Raw].load)


def _run_file(settings=None):
    analyzer = PCAPAnalyzer(FIXTURE, settings or {})
    return analyzer.analyze(), analyzer


def _client_hello_v10():
    """Smallest valid TLS 1.0 ClientHello: version 0x0301, one cipher, no
    extensions -> the parser reads effective_version 0x0301 (no
    supported_versions to override it)."""
    body = (
        b"\x03\x01"          # client_version = TLS 1.0
        + b"\x11" * 32       # random
        + b"\x00"            # session id length 0
        + b"\x00\x02"        # cipher suites length
        + b"\x00\x2f"        # TLS_RSA_WITH_AES_128_CBC_SHA
        + b"\x01" + b"\x00"  # compression: 1 method, null
    )
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    return record


# --- Certificate -----------------------------------------------------------

def test_certificate_is_parsed():
    _, analyzer = _run_file()
    certs = analyzer._tls_info.get("certificates") or []
    assert len(certs) == 1
    leaf = certs[0]["chain"][0]
    assert leaf["cn"] == "*.msedge.net"
    assert leaf["issuer_cn"]  # CA-signed, not self-signed
    assert not leaf["self_signed"]


def test_certificate_cn_sni_mismatch_fires():
    results, _ = _run_file()
    hits = find_alerts(results, title="Certificate / SNI Mismatch", category="tls")
    assert hits
    assert hits[0]["severity"] == "high"
    assert hits[0]["details"]["sni"] == "settings-win.data.microsoft.com"
    assert hits[0]["details"]["cn"] == "*.msedge.net"


def test_valid_external_cert_not_self_signed_alert():
    # The cert is a real CA-signed leaf -> no self-signed / expired noise.
    results, _ = _run_file()
    assert not has_alert(results, title="Self-Signed")
    assert not has_alert(results, title="Invalid TLS Certificate Validity")


# --- DoH -------------------------------------------------------------------

def test_doh_fires_when_sni_matches_operator_host():
    # The ClientHello is on 443 with an SNI under data.microsoft.com; feeding
    # that suffix as an operator DoH host exercises the SNI-match signal.
    results, _ = _run_file({"doh_hosts": ["data.microsoft.com"]})
    hits = find_alerts(results, title="DoH")
    assert hits
    assert hits[0]["details"]["src"] == LOCAL_IP


def test_doh_silent_without_matching_host():
    results, _ = _run_file()
    assert not has_alert(results, title="DoH")


# --- ALPN / port inconsistency ---------------------------------------------

def test_alpn_h2_on_database_port_fires(analyze):
    # Same ClientHello (advertises h2) but on MySQL/3306 -> tunneling signal.
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=51002, dport=3306, flags="PA") / Raw(_CH_LOAD)
    results = analyze([pkt])
    hits = find_alerts(results, title="ALPN/Port Inconsistency", category="tls")
    assert hits
    assert hits[0]["severity"] == "high"


def test_alpn_h2_on_443_does_not_fire(analyze):
    # Port 443 is a normal web port -> h2 there is expected.
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=51002, dport=443, flags="PA") / Raw(_CH_LOAD)
    results = analyze([pkt])
    assert not has_alert(results, title="ALPN/Port Inconsistency")


# --- Obsolete TLS version --------------------------------------------------

def test_obsolete_tls10_fires(analyze):
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=51003, dport=443, flags="PA") / Raw(_client_hello_v10())
    results = analyze([pkt])
    hits = find_alerts(results, title="Obsolete TLS Version", category="tls")
    assert hits
    assert "TLS 1.0" in hits[0]["title"]
    assert hits[0]["details"]["version_raw"] == 0x0301


def test_tls12_handshake_not_flagged_obsolete():
    # The fixture's ClientHello is TLS 1.2 -> not obsolete.
    results, _ = _run_file()
    assert not has_alert(results, title="Obsolete TLS Version")
