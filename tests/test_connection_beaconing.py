"""In-connection beaconing detector (ConnectionBeaconingStreamingDetector).

Covers the gap the SYN-based BeaconingStreamingDetector cannot see: an
implant that opens ONE persistent TCP connection (HTTP2/WebSocket/keep-alive
C2) and checks in periodically inside it. The signal is periodicity of
client->server payload BURSTS within a single 4-tuple flow.
"""

from scapy.all import IP, TCP, Raw

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert

SPORT = 40001
DPORT = 443
TITLE = "In-Connection Beaconing"


def _data_pkt(t, size=200, sport=SPORT, src=LOCAL_IP, dst=EXTERNAL_IP):
    pk = IP(src=src, dst=dst) / TCP(sport=sport, dport=DPORT, flags="PA") / Raw(
        b"X" * size
    )
    pk.time = t
    return pk


def test_periodic_bursts_in_one_connection_fire(analyze):
    # 10 check-ins, exactly 30s apart, same size, ONE connection (no SYNs).
    # Exact clean interval + identical size -> phase-locked + uniform ->
    # critical. The SYN-based detector cannot fire here (zero SYN packets).
    packets = [_data_pkt(1_000_000.0 + i * 30.0) for i in range(10)]
    results = analyze(packets)
    hits = find_alerts(results, title=TITLE, category="beaconing")
    assert hits, "expected in-connection beaconing alert"
    a = hits[0]
    assert a["details"]["burst_count"] == 10
    assert a["details"]["method"] == "jitter"
    assert a["details"]["wallclock_phase_locked"] is True
    assert a["details"]["size_uniform"] is True
    assert a["severity"] == "critical"
    # Canonical schema sanity on the new detector.
    assert LOCAL_IP in a["src_ips"]
    assert EXTERNAL_IP in a["dst_ips"]
    assert DPORT in a["ports"]
    # And the classic SYN-based title must NOT be what fired.
    assert not has_alert(results, title="Beaconing Behavior Detected")


def test_multi_packet_checkins_group_into_bursts(analyze):
    # Each check-in is 3 packets within 1s; bursts must collapse to 10,
    # not 30 (burst gap default 5s).
    packets = []
    for i in range(10):
        base = 1_000_000.0 + i * 30.0
        for j in range(3):
            packets.append(_data_pkt(base + j * 0.4, size=180 + j))
    results = analyze(packets)
    hits = find_alerts(results, title=TITLE)
    assert hits
    assert hits[0]["details"]["burst_count"] == 10


def test_continuous_transfer_is_one_burst_and_silent(analyze):
    # A steady download/upload never idles past the burst gap -> 1 burst.
    packets = [_data_pkt(1_000_000.0 + i * 0.5, size=1400) for i in range(600)]
    results = analyze(packets)
    assert not has_alert(results, title=TITLE)


def test_irregular_human_traffic_is_silent(analyze):
    # Human-driven gaps: bursts exist but with wild jitter and no stable
    # period -> neither the jitter test nor autocorrelation may fire.
    gaps = [7, 61, 13, 118, 29, 44, 9, 83, 17, 52, 96, 23, 38, 71, 11, 47]
    packets = []
    t = 1_000_000.0
    for g in gaps:
        t += g
        packets.append(_data_pkt(t))
    results = analyze(packets)
    assert not has_alert(results, title=TITLE)


def test_tcp_keepalive_probes_do_not_count(analyze):
    # 1-byte keepalive probes every 45s are periodic but sub-min_payload;
    # they must not manufacture a beaconing alert.
    packets = [_data_pkt(1_000_000.0 + i * 45.0, size=1) for i in range(12)]
    results = analyze(packets)
    assert not has_alert(results, title=TITLE)


def test_below_min_duration_is_silent(analyze):
    # 8 bursts 10s apart = 70s duration < 120s min -> silent (too little
    # observation time to call it a beacon).
    packets = [_data_pkt(1_000_000.0 + i * 10.0) for i in range(8)]
    results = analyze(packets)
    assert not has_alert(results, title=TITLE)


def test_jittered_bursts_caught_by_autocorrelation(analyze):
    # ~20s period with ±20% alternating jitter: linear jitter test fails
    # (max deviation > 10%), but the binned autocorrelation still sees the
    # stable underlying period across 24 bursts.
    packets = []
    t = 1_000_000.0
    for i in range(24):
        t += 20.0 + (4.0 if i % 2 == 0 else -4.0)
        packets.append(_data_pkt(t, size=150))
    results = analyze(packets)
    hits = find_alerts(results, title=TITLE)
    assert hits
    assert hits[0]["details"]["method"] == "autocorrelation"
