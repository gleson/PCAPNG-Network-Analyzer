"""TLS fingerprint detectors: KnownBadJa3 / KnownBadJa3s.

Unlike the rest of the suite, these need a *real* TLS handshake: JA3/JA3S are
md5s over the exact ciphers/extensions/curves a stack offers, which is painful
to forge byte-accurate with scapy. So this one test uses a small checked-in
fixture, ``fixtures/tls_handshake.pcap``, carved from a real capture — one
ClientHello + one ServerHello, with the IP/TCP addressing rewritten to the
suite's LOCAL/EXTERNAL constants. JA3/JA3S cover only the TLS record (version,
ciphers, extensions, curves, formats), never the IPs or SNI, so the rewrite
keeps the fingerprints intact while leaking nothing about the source capture.

The detectors match a fingerprint against operator-supplied bad lists
(``settings['known_malicious_ja3']`` / ``['known_malicious_ja3s']``) plus the
SSLBL feed (offline here). Rather than hard-code the md5, each test discovers
the fingerprint the engine computes for the fixture, then re-runs with that
fingerprint marked malicious — so the assertion tracks the parser, not a
frozen constant.
"""

import os

from pcap_analyzer import PCAPAnalyzer

from conftest import find_alerts, has_alert

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "tls_handshake.pcap")


def _run(settings=None):
    """Run the engine on the fixture; return (results, analyzer)."""
    analyzer = PCAPAnalyzer(FIXTURE, settings or {})
    results = analyzer.analyze()
    return results, analyzer


def test_handshake_is_parsed():
    _results, analyzer = _run()
    chs = analyzer._tls_info.get("client_hellos") or []
    shs = analyzer._tls_info.get("server_hellos") or []
    assert len(chs) == 1 and len(shs) == 1
    assert chs[0]["ja3_md5"] and chs[0]["ja4"]
    assert shs[0]["ja3s_md5"] and shs[0]["ja4s"]
    # SNI is parsed out of the ClientHello (separate from the JA3 input).
    assert chs[0]["sni"]


def test_clean_handshake_raises_no_ja3_alert():
    results, _ = _run()
    assert not has_alert(results, title="Known Malicious JA3")


def test_known_malicious_ja3_fires_critical():
    # Discover the JA3 the engine computes, then mark it bad and re-run.
    _, analyzer = _run()
    ja3 = analyzer._tls_info["client_hellos"][0]["ja3_md5"]

    results, _ = _run({"known_malicious_ja3": {ja3: "Test-C2-Framework"}})
    hits = find_alerts(results, title="Known Malicious JA3 Fingerprint", category="tls")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["ja3_md5"] == ja3
    assert "Test-C2-Framework" in hits[0]["details"]["matches"]


def test_known_malicious_ja3s_fires_high():
    _, analyzer = _run()
    ja3s = analyzer._tls_info["server_hellos"][0]["ja3s_md5"]

    results, _ = _run({"known_malicious_ja3s": {ja3s: "Test-C2-Server"}})
    hits = find_alerts(results, title="Known Malicious JA3S Fingerprint", category="tls")
    assert hits
    assert hits[0]["severity"] == "high"
    assert hits[0]["details"]["ja3s_md5"] == ja3s


def test_unrelated_bad_ja3_does_not_fire():
    # A bad-list that doesn't contain our fixture's fingerprint stays silent.
    results, _ = _run({"known_malicious_ja3": {"00000000000000000000000000000000": "Other"}})
    assert not has_alert(results, title="Known Malicious JA3")
