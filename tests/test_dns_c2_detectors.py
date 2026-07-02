"""DGA and Cobalt Strike DNS Beacon detectors."""

from scapy.all import IP, UDP, DNS, DNSQR

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert

# Scores 0.80 via analyzer._dga_score (>= 0.7 default threshold).
_DGA_LABEL = "kqxjzvbwfhdml"
# High-entropy (>3.0) label >= 20 chars for the CS beacon encoded subdomain.
_HE_LABEL = "x7gk29fjq8zm4ba1tr6wpdv5cnse3uhy"


def _dns_query(qname, src=LOCAL_IP, dst=EXTERNAL_IP, sport=33333):
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))


def test_dga_domain_fires(analyze):
    results = analyze([_dns_query(f"{_DGA_LABEL}.com")])
    hits = find_alerts(results, title="DGA", category="dns")
    assert hits
    assert hits[0]["details"]["max_score"] >= 0.7


def test_pronounceable_domain_does_not_fire_dga(analyze):
    results = analyze([_dns_query("marketing.example.com")])
    assert not has_alert(results, title="DGA")


def test_cobalt_strike_dns_beacon_fires(analyze):
    # post.<long high-entropy label>.<zone> -> CS DNS beacon (single hit = critical).
    results = analyze([_dns_query(f"post.{_HE_LABEL}.example.com")])
    hits = find_alerts(results, title="Cobalt Strike DNS Beacon", category="c2")
    assert hits
    assert hits[0]["details"]["prefix"] == "post"


def test_normal_subdomain_does_not_trigger_cs_beacon(analyze):
    results = analyze([_dns_query("api.cdn.example.com")])
    assert not has_alert(results, title="Cobalt Strike DNS Beacon")


# --- base-zone extraction under compound public suffixes --------------------

def test_base_zone_handles_compound_suffixes():
    from pcap_analyzer.constants import base_zone

    assert base_zone(["x", "evil", "co", "uk"]) == "evil.co.uk"
    assert base_zone(["a", "b", "evil", "com", "br"]) == "evil.com.br"
    assert base_zone(["evil", "com"]) == "evil.com"
    assert base_zone(["sub", "evil", "org"]) == "evil.org"
    # Generic rule: <functional-label>.<2-letter ccTLD> not in the curated set.
    assert base_zone(["x", "evil", "gov", "zz"]) == "evil.gov.zz"


def test_cs_beacon_parent_zone_is_registrable_domain(analyze):
    # Under .com.br the parent zone must be evil.com.br, NOT com.br —
    # otherwise unrelated Brazilian domains aggregate in one bucket and the
    # sinkhole recommendation points at the whole public suffix.
    results = analyze([_dns_query(f"post.{_HE_LABEL}.evil.com.br")])
    hits = find_alerts(results, title="Cobalt Strike DNS Beacon", category="c2")
    assert hits
    assert hits[0]["details"]["parent_zone"] == "evil.com.br"


def test_cumulative_dns_exfil_groups_by_registrable_zone(analyze):
    # >=100 distinct subdomains under ONE zone. With last-2-labels grouping,
    # `<sub>.evil.co.uk` would land in the `co.uk` bucket; the alert must
    # name evil.co.uk.
    packets = [
        _dns_query(f"chunk{i:04d}.evil.co.uk", sport=30000 + i)
        for i in range(105)
    ]
    results = analyze(packets)
    hits = find_alerts(results, title="Cumulative DNS Exfiltration")
    assert hits
    assert hits[0]["details"]["base_domain"] == "evil.co.uk"


def test_dga_score_uses_label_left_of_public_suffix(analyze):
    # The DGA-looking label sits directly above .com.br: the effective label
    # extracted must be the DGA string, not "com".
    results = analyze([_dns_query(f"{_DGA_LABEL}.com.br")])
    hits = find_alerts(results, title="DGA", category="dns")
    assert hits
    assert hits[0]["details"]["max_score"] >= 0.7
