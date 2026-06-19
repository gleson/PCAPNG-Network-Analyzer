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
