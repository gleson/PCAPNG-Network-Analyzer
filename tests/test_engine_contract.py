"""Engine-level contract tests: registry shape, alert schema invariants, and
the behaviour of degenerate inputs (empty / clean traffic).

These don't target a single detector — they guard the framework so a refactor
that drops a detector from a registry, breaks the alert dict shape, or makes a
detector crash on benign traffic fails loudly.
"""

from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap

from pcap_analyzer import PCAPAnalyzer
from pcap_analyzer.detectors import STREAMING_DETECTORS, STREAMING_DETECTOR_NAMES
from pcap_analyzer.detectors.post import POST_DETECTORS
from pcap_analyzer.aggregators import STREAMING_AGGREGATORS

from conftest import LOCAL_IP, EXTERNAL_IP, alerts


VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}


def test_registry_counts():
    """Registry sizes are part of the engine's contract; a silent drop of a
    detector should fail here, not in production."""
    assert len(STREAMING_DETECTORS) == 32
    assert len(POST_DETECTORS) == 19
    assert len(STREAMING_AGGREGATORS) == 14


def test_streaming_detector_names_are_unique():
    names = [c.name for c in STREAMING_DETECTORS]
    assert len(names) == len(set(names)), "duplicate detector .name values"
    assert len(STREAMING_DETECTOR_NAMES) == len(names)


def test_every_streaming_detector_instantiates_and_has_update_finalize():
    # PCAPAnalyzer.__init__ does not open the file, so a dummy path is fine;
    # detectors read detection constants off the analyzer instance.
    analyzer = PCAPAnalyzer("does-not-exist.pcap", {})
    for cls in STREAMING_DETECTORS:
        det = cls(analyzer)
        assert callable(det.update)
        assert callable(det.finalize)


def test_empty_pcap_does_not_crash(tmp_path):
    pcap = tmp_path / "empty.pcap"
    wrpcap(str(pcap), [])
    results = PCAPAnalyzer(str(pcap), {}).analyze()
    assert results["alerts"] == []
    assert "summary" in results
    assert "ips" in results


def test_clean_traffic_raises_no_scan_or_exfil_alerts(analyze):
    """A handful of ordinary HTTPS connections must not trip scan/exfil/dns
    detectors — the canonical false-positive guard."""
    packets = []
    t = 1_000_000.0
    for i in range(5):
        # Full handshake to a normal web server: SYN, SYN-ACK, data.
        packets.append(IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=40000 + i, dport=443, flags="S"))
        packets.append(IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=443, dport=40000 + i, flags="SA"))
        packets.append(IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=40000 + i, dport=443, flags="A"))
    for p in packets:
        p.time = t
        t += 5.0
    results = analyze(packets)
    cats = {a.get("category") for a in alerts(results)}
    assert "scan" not in cats
    assert "exfil" not in cats


def test_all_emitted_alerts_satisfy_schema(analyze):
    """Whatever fires, every alert must carry a valid severity, a category,
    a non-empty title, and a details dict. Run against traffic that trips
    several detectors at once."""
    packets = []
    t = 1_000_000.0
    # Port scan: 25 ports from one source.
    for port in range(20, 45):
        pk = IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=55555, dport=port, flags="S")
        pk.time = t
        t += 0.01
        packets.append(pk)
    # A DNS query for good measure.
    dq = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / UDP(sport=33333, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.com")
    )
    dq.time = t
    packets.append(dq)

    results = analyze(packets)
    assert alerts(results), "expected at least one alert from scan traffic"
    for a in alerts(results):
        assert a.get("severity") in VALID_SEVERITIES, a
        assert a.get("category"), a
        assert a.get("title"), a
        assert isinstance(a.get("details", {}), dict), a
