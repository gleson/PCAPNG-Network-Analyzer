"""Positive / negative tests for DNS-based detectors."""

from scapy.all import IP, UDP, DNS, DNSQR

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert


# 62-char first label, many distinct characters -> Shannon entropy > 3.5.
_HIGH_ENTROPY_LABEL = "x7gk29fjq8zm4ba1tr6wpdv5cnse3uhy0lk2jf8gq4mz7xb9dt3rw6pv1scn5e"


def _dns_query(qname, src=LOCAL_IP, dst=EXTERNAL_IP, sport=33333):
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=qname)
    )


def test_dns_tunneling_fires_on_long_high_entropy_subdomain(analyze):
    # Default: first label length > 50 chars AND entropy > 3.5.
    pkt = _dns_query(f"{_HIGH_ENTROPY_LABEL}.tunnel.example.com")
    results = analyze([pkt])
    hits = find_alerts(results, title="DNS Tunneling", category="dns")
    assert hits
    assert hits[0]["details"]["subdomain_length"] > 50
    assert hits[0]["details"]["entropy"] > 3.5


def test_short_subdomain_does_not_trigger_tunneling(analyze):
    pkt = _dns_query("www.example.com")
    results = analyze([pkt])
    assert not has_alert(results, title="DNS Tunneling")


def test_normal_dns_query_is_clean(analyze):
    # A handful of ordinary lookups must not emit any dns-category alert.
    packets = [_dns_query(name) for name in (
        "www.google.com", "api.github.com", "cdn.example.org",
    )]
    results = analyze(packets)
    assert not has_alert(results, category="dns")
