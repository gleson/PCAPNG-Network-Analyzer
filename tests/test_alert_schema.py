"""Canonical alert schema (alert_schema.normalize_alerts) + the two consumers
that key off it: cross-detector dedup (_core._dedupe_alerts) and SOC IP
matching (soc._collect_alert_ips).

The normalization exists because detectors disagree on endpoint field names
(src vs src_ip vs source_ip vs client_ip ...). Before it, dedup keyed on
details['src_ip']/['dst_ip'] only, so alerts from detectors using any other
name collapsed onto ('cat', 'title', '', '') and DISTINCT findings (different
hosts!) were silently merged. These tests pin the mapping table and the fixed
behaviour.
"""

from pcap_analyzer import PCAPAnalyzer
from pcap_analyzer.alert_schema import normalize_alert, normalize_alerts

from soc import _collect_alert_ips


def _alert(details=None, **top):
    a = {
        "severity": "high",
        "category": "test",
        "title": "Test Alert",
        "description": "",
        "details": details or {},
    }
    a.update(top)
    return a


# ---------------------------------------------------------------- mapping


def test_src_dst_scalar_variants_all_map():
    cases = [
        ({"src_ip": "10.0.0.1"}, "src_ips"),
        ({"source_ip": "10.0.0.1"}, "src_ips"),
        ({"src": "10.0.0.1"}, "src_ips"),
        ({"client_ip": "10.0.0.1"}, "src_ips"),
        ({"dst_ip": "10.0.0.1"}, "dst_ips"),
        ({"destination_ip": "10.0.0.1"}, "dst_ips"),
        ({"dst": "10.0.0.1"}, "dst_ips"),
        ({"target_ip": "10.0.0.1"}, "dst_ips"),
        ({"server_ip": "10.0.0.1"}, "dst_ips"),
        ({"kdc_ip": "10.0.0.1"}, "dst_ips"),
        ({"destination": "10.0.0.1"}, "dst_ips"),
    ]
    for details, field in cases:
        a = normalize_alert(_alert(details))
        assert a[field] == ["10.0.0.1"], (details, field, a)


def test_list_keys_and_dict_targets_map():
    a = normalize_alert(_alert({
        "targets": ["10.0.0.2", {"ip": "10.0.0.3"}],
        "hosts_sample": ["10.0.0.4"],
        "sources": ["10.0.0.9"],
    }))
    assert a["dst_ips"] == ["10.0.0.2", "10.0.0.3", "10.0.0.4"]
    assert a["src_ips"] == ["10.0.0.9"]


def test_peer_role_client_puts_peers_on_source_side():
    a = normalize_alert(_alert({
        "peer_ips": ["10.0.0.7"], "peer_role": "client",
        "dst_ip": "10.0.0.1",
    }))
    assert a["src_ips"] == ["10.0.0.7"]
    a2 = normalize_alert(_alert({"peer_ips": ["10.0.0.7"]}))
    assert a2["dst_ips"] == ["10.0.0.7"]


def test_alert_ip_fallback_fills_source_then_destination():
    # No endpoint fields at all → alert.ip is the source.
    a = normalize_alert(_alert({}, ip="10.0.0.5"))
    assert a["src_ips"] == ["10.0.0.5"] and a["dst_ips"] == []
    # Sources known, no destination, ip differs → ip is the destination.
    a2 = normalize_alert(_alert({"src": "10.0.0.5"}, ip="8.8.8.8"))
    assert a2["dst_ips"] == ["8.8.8.8"]
    # ip already on the source side must not leak into destinations.
    a3 = normalize_alert(_alert({"src": "10.0.0.5"}, ip="10.0.0.5"))
    assert a3["dst_ips"] == []


def test_non_ip_strings_are_excluded():
    a = normalize_alert(_alert({"src": "evil.example.com", "dst": ""}))
    assert a["src_ips"] == [] and a["dst_ips"] == []


def test_empty_alert_ip_backfilled_from_endpoints():
    a = normalize_alert(_alert({"src": "10.0.0.5"}, ip=""))
    assert a["ip"] == "10.0.0.5"


def test_ports_and_protocols():
    a = normalize_alert(_alert({
        "port": 445, "ports": [139, 445, 0, "445"], "protocol": "SMB",
    }))
    assert a["ports"] == [139, 445]
    assert a["protocols"] == ["SMB"]
    # 'sport' only counts when no other port key exists (JA3S case).
    a2 = normalize_alert(_alert({"sport": 8443}))
    assert a2["ports"] == [8443]
    a3 = normalize_alert(_alert({"sport": 51234, "dport": 443}))
    assert a3["ports"] == [443]


def test_cves_extracted_from_title_description_and_details():
    a = _alert(
        {"pattern": "Log4Shell (CVE-2021-44228)",
         "samples": [{"path": "/cve-2022-22965/x"}]},
    )
    a["description"] = "matches CVE 2021-26855 probe"
    normalize_alert(a)
    assert a["cves"] == [
        "CVE-2021-26855", "CVE-2021-44228", "CVE-2022-22965",
    ]


def test_normalize_alerts_survives_bad_entries():
    good = _alert({"src": "10.0.0.1"})
    bad = _alert(details="not-a-dict")
    out = normalize_alerts([good, bad])
    assert out[0]["src_ips"] == ["10.0.0.1"]
    assert out[1]["src_ips"] == []  # degraded, not crashed


# ---------------------------------------------------------------- dedup


def _dedupe(alerts_list):
    analyzer = PCAPAnalyzer("does-not-exist.pcap", {})
    normalize_alerts(alerts_list)
    analyzer.results["alerts"] = alerts_list
    analyzer._dedupe_alerts()
    return analyzer.results["alerts"]


def test_dedup_keeps_distinct_host_pairs_separate():
    """Regression: same title from different host pairs must NOT merge.
    Pre-fix, both landed on key ('cat','title','','') and collapsed."""
    out = _dedupe([
        _alert({"source_ip": "10.0.0.5", "destination_ip": "8.8.8.8",
                "destination_port": 443}, ip="10.0.0.5"),
        _alert({"source_ip": "10.0.0.9", "destination_ip": "1.1.1.1",
                "destination_port": 8443}, ip="10.0.0.9"),
    ])
    assert len(out) == 2


def test_dedup_merges_true_duplicates():
    out = _dedupe([
        _alert({"src": "10.0.0.5", "dst": "8.8.8.8", "port": 443}),
        _alert({"src": "10.0.0.5", "dst": "8.8.8.8", "port": 443}),
    ])
    assert len(out) == 1
    assert out[0]["count"] == 2


def test_dedup_same_pair_different_port_stays_separate():
    out = _dedupe([
        _alert({"src": "10.0.0.5", "dst": "8.8.8.8", "port": 443}),
        _alert({"src": "10.0.0.5", "dst": "8.8.8.8", "port": 8443}),
    ])
    assert len(out) == 2


# ---------------------------------------------------------------- SOC


def test_soc_collect_prefers_canonical_fields():
    a = normalize_alert(
        _alert({"dst": "8.8.8.8", "src": "10.0.0.5"}, ip="10.0.0.5"),
    )
    src, dst = _collect_alert_ips(a)
    assert src == {"10.0.0.5"}
    assert dst == {"8.8.8.8"}


def test_soc_collect_legacy_path_still_works():
    # Un-normalized alert (old DB blob): falls back to detail-key scan.
    src, dst = _collect_alert_ips(
        _alert({"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8"}),
    )
    assert src == {"10.0.0.5"}
    assert dst == {"8.8.8.8"}


def test_soc_dst_side_now_visible_for_dst_key_detectors():
    """Regression: detectors writing details['dst'] (beaconing, icmp_tunnel,
    volume_exfil, snmp_walk, dot...) had an invisible destination side."""
    a = normalize_alert(_alert({"src": "10.0.0.5", "dst": "8.8.8.8"}))
    _, dst = _collect_alert_ips(a)
    assert "8.8.8.8" in dst


def test_soc_dst_only_rule_matches_destination_ip_end_to_end():
    """Regression: a dst_only SOC rule against a beaconing-style alert
    (endpoints in source_ip/destination_ip) never matched pre-normalization."""
    from soc import tag_soc_alerts

    alert = normalize_alert(_alert(
        {"source_ip": "10.0.0.5", "destination_ip": "1.2.3.4"},
        ip="10.0.0.5",
    ))
    settings = {"soc_ips": [
        {"cidr": "1.2.3.0/24", "description": "SOC scanner",
         "match_mode": "dst_only"},
    ]}
    tagged = tag_soc_alerts({"alerts": [alert]}, settings)
    assert tagged == 1
    assert alert["soc_match"]["side"] == "dst"
