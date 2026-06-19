"""Streaming-aggregator output contract.

Aggregators don't emit alerts; they populate the ``results`` dict that the UI,
report generator and post-detectors consume. This module feeds one small mixed
capture (all with an Ethernet layer, so L2 mapping is clean) and asserts the
shape and content of the headline result sections: summary, protocol stats,
IP↔MAC mapping, asset inventory, and the QUIC/TCP-flow lists.
"""

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, Ether

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
