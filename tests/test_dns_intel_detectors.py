"""DNS-reputation streaming detectors: fast-flux, NXDOMAIN spike, suspicious TLD.

These three read structured DNS fields (answers, rcode, query name) directly
off the scapy ``DNS`` layer — UDP/53 is *not* re-bound by scapy to a dedicated
class, so ``DNS in pkt`` holds and no pkt_view resurrection is needed here.
"""

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert


def _dns_response(qname, answers, rcode=0, ttl=30, dst=LOCAL_IP, src=EXTERNAL_IP):
    """A DNS response (qr=1) carrying A records for ``qname`` -> ``answers``."""
    an = None
    for ip in answers:
        rr = DNSRR(rrname=qname, type="A", rdata=ip, ttl=ttl)
        an = rr if an is None else an / rr
    return (
        IP(src=src, dst=dst)
        / UDP(sport=53, dport=33333)
        / DNS(qr=1, rcode=rcode, qd=DNSQR(qname=qname), an=an)
    )


def _dns_query(qname, src=LOCAL_IP, dst=EXTERNAL_IP, sport=33333):
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=qname)
    )


# --- Fast-flux -------------------------------------------------------------

def test_fast_flux_domain_fires(analyze):
    # >= 8 distinct A records with a low average TTL -> fast-flux.
    ips = [f"45.{i}.10.{i}" for i in range(1, 11)]  # 10 distinct IPs
    results = analyze([_dns_response("flux.example.com", ips, ttl=30)])
    hits = find_alerts(results, title="Fast-Flux", category="dns")
    assert hits
    assert hits[0]["details"]["unique_ips"] >= 8
    assert hits[0]["details"]["avg_ttl_seconds"] <= 300


def test_few_ips_do_not_trigger_fast_flux(analyze):
    ips = ["45.1.10.1", "45.2.10.2", "45.3.10.3"]  # below min_ips (8)
    results = analyze([_dns_response("cdn.example.com", ips, ttl=30)])
    assert not has_alert(results, title="Fast-Flux")


def test_high_ttl_does_not_trigger_fast_flux(analyze):
    # Many IPs but a long TTL is a normal large CDN, not fast-flux.
    ips = [f"45.{i}.10.{i}" for i in range(1, 11)]
    results = analyze([_dns_response("cdn.example.com", ips, ttl=3600)])
    assert not has_alert(results, title="Fast-Flux")


# --- NXDOMAIN spike --------------------------------------------------------

def test_nxdomain_spike_fires(analyze):
    # >= 20 NXDOMAIN (rcode=3) responses to one client within 60s.
    packets = []
    t = 1_000_000.0
    for i in range(22):
        pk = _dns_response(f"x{i}.dga.example", [], rcode=3)
        pk.time = t
        t += 1.0
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="NXDOMAIN Spike", category="dns")
    assert hits
    assert hits[0]["details"]["nxdomain_in_window"] >= 20
    assert hits[0]["ip"] == LOCAL_IP


def test_few_nxdomain_do_not_fire(analyze):
    packets = []
    t = 1_000_000.0
    for i in range(5):  # below threshold (20)
        pk = _dns_response(f"x{i}.dga.example", [], rcode=3)
        pk.time = t
        t += 1.0
        packets.append(pk)
    results = analyze(packets)
    assert not has_alert(results, title="NXDOMAIN Spike")


# --- Suspicious TLD --------------------------------------------------------

def test_suspicious_tld_fires_high(analyze):
    # 5 distinct domains under a commonly-abused TLD -> high severity.
    packets = [_dns_query(f"malware{i}.xyz") for i in range(5)]
    results = analyze(packets)
    hits = find_alerts(results, title="Suspicious TLD", category="dns")
    assert hits
    assert hits[0]["details"]["tld"] == "xyz"
    assert hits[0]["details"]["domain_count"] >= 5
    assert hits[0]["severity"] == "high"


def test_reputable_tld_does_not_fire(analyze):
    results = analyze([_dns_query("api.example.com")])
    assert not has_alert(results, title="Suspicious TLD")
