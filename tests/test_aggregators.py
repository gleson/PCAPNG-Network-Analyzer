"""Streaming-aggregator output contract.

Aggregators don't emit alerts; they populate the ``results`` dict that the UI,
report generator and post-detectors consume. This module feeds one small mixed
capture (all with an Ethernet layer, so L2 mapping is clean) and asserts the
shape and content of the headline result sections: summary, protocol stats,
IP↔MAC mapping, asset inventory, and the QUIC/TCP-flow lists.
"""

from scapy.all import IP, IPv6, TCP, UDP, DNS, DNSQR, Raw, Ether

from conftest import LOCAL_IP, EXTERNAL_IP

MAC_LOCAL = "aa:bb:cc:00:00:01"
MAC_GW = "aa:bb:cc:00:00:fe"


def _mixed_capture():
    e = lambda smac: Ether(src=smac, dst=MAC_GW)
    return [
        e(MAC_LOCAL) / IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=40000, dport=443, flags="S"),
        e(MAC_GW) / IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=443, dport=40000, flags="SA"),
        e(MAC_LOCAL) / IP(src=LOCAL_IP, dst=EXTERNAL_IP) / UDP(sport=33333, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
        e(MAC_LOCAL) / IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=44444, dport=80, flags="PA")
        / Raw(b"GET / HTTP/1.1\r\nHost: t\r\nUser-Agent: m\r\n\r\n"),
    ]


def test_summary_contract(analyze):
    results = analyze(_mixed_capture())
    summary = results["summary"]
    assert summary["packet_count"] == 4
    assert summary["total_bytes"] > 0
    assert summary["duration"] >= 0
    assert summary["truncated"] is False


def test_protocol_stats_contract(analyze):
    results = analyze(_mixed_capture())
    protocols = results["protocols"]
    assert isinstance(protocols, list) and protocols
    for p in protocols:
        assert {"name", "packets", "bytes", "percentage"} <= set(p)
        assert p["packets"] > 0
    names = {p["name"] for p in protocols}
    assert "TCP" in names


def test_ip_mac_mapping_contract(analyze):
    results = analyze(_mixed_capture())
    mapping = results["ip_mac_mapping"]
    assert LOCAL_IP in mapping
    assert MAC_LOCAL in mapping[LOCAL_IP]


def test_asset_inventory_contract(analyze):
    results = analyze(_mixed_capture())
    assets = results["assets"]
    assert isinstance(assets, dict) and assets
    # Asset inventory is keyed by MAC; the local host's MAC should be present.
    assert MAC_LOCAL in assets


def test_flow_list_sections_present(analyze):
    results = analyze(_mixed_capture())
    # These sections are always emitted (possibly empty) so downstream
    # consumers can rely on their presence.
    assert isinstance(results.get("quic_flows"), list)
    assert isinstance(results.get("traffic_timeline"), list)


def test_ipv6_packet_counted_once_in_ip_stats(analyze):
    # Regression (2026-07): pkt_view dual-keys the IPv6 layer under IP, so the
    # old separate `if IP` + `if IPv6` blocks BOTH ran and every v6 packet was
    # counted twice (packets_sent=2, bytes doubled).
    src6, dst6 = "2001:db8::10", "2001:db8::20"
    pkt = (Ether(src=MAC_LOCAL, dst=MAC_GW)
           / IPv6(src=src6, dst=dst6) / TCP(sport=50000, dport=443, flags="S"))
    wire_len = len(pkt)
    results = analyze([pkt])

    by_ip = {e["ip"]: e for e in results["ips"]}
    assert src6 in by_ip and dst6 in by_ip
    assert by_ip[src6]["packets_sent"] == 1
    assert by_ip[src6]["bytes_sent"] == wire_len
    assert by_ip[dst6]["packets_received"] == 1
    assert by_ip[dst6]["bytes_received"] == wire_len
    # The transport protocol and the IPv6 tag must both survive the merge.
    assert {"TCP", "IPv6"} <= set(by_ip[src6]["protocols"])
    assert 443 in by_ip[src6]["ports"]


def test_quic_appears_in_protocol_stats(analyze):
    # Regression (2026-07): the QUIC branch read `u.payload` off the UDP layer
    # view (which has no payload attribute), so the AttributeError was
    # swallowed and QUIC never showed up in results['protocols'].
    quic_long_header = bytes([0xC3, 0x00, 0x00, 0x00, 0x01]) + b"\x00" * 40
    pkt = (IP(src=LOCAL_IP, dst=EXTERNAL_IP)
           / UDP(sport=51000, dport=443) / Raw(quic_long_header))
    results = analyze([pkt])
    names = {p["name"] for p in results["protocols"]}
    assert "QUIC" in names


def test_non_quic_udp_443_not_counted_as_quic(analyze):
    # High bit of byte 0 clear -> not a QUIC long header; must stay UDP-only.
    pkt = (IP(src=LOCAL_IP, dst=EXTERNAL_IP)
           / UDP(sport=51001, dport=443) / Raw(b"\x3f" + b"\x00" * 40))
    results = analyze([pkt])
    names = {p["name"] for p in results["protocols"]}
    assert "QUIC" not in names
