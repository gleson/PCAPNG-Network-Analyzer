"""Tests for plaintext / insecure-protocol and lateral-movement detectors."""

from scapy.all import IP, UDP, TCP, DNSQR, DNSRR
from scapy.layers.llmnr import LLMNRResponse
from scapy.layers.netbios import NBNSHeader, NBNSQueryResponse

from conftest import LOCAL_IP, EXTERNAL_IP, has_alert


def test_insecure_ftp_protocol_fires(analyze):
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=50000, dport=21, flags="S")
    results = analyze([pkt])
    assert has_alert(results, title="Insecure Protocol: FTP", category="protocol")


def test_insecure_telnet_protocol_fires(analyze):
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=50000, dport=23, flags="S")
    results = analyze([pkt])
    assert has_alert(results, title="Insecure Protocol: Telnet", category="protocol")


def test_https_traffic_is_not_flagged_insecure(analyze):
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=50000, dport=443, flags="S")
    results = analyze([pkt])
    assert not has_alert(results, category="protocol")


def test_llmnr_poisoning_fires(analyze):
    # Default: >=10 LLMNR responses (UDP sport 5355, qr=1, ancount>0) from a
    # local host. Regression guard for the bug where the detector checked
    # `DNS in pkt` — scapy dissects LLMNR as LLMNRResponse, never DNS.
    packets = []
    t = 1_000_000.0
    for i in range(14):
        resp = (
            IP(src=LOCAL_IP, dst="10.0.0.100")
            / UDP(sport=5355, dport=50000 + i)
            / LLMNRResponse(qr=1, qdcount=1, ancount=1,
                            qd=DNSQR(qname="wpad"),
                            an=DNSRR(rrname="wpad", rdata=LOCAL_IP))
        )
        resp.time = t
        t += 0.5
        packets.append(resp)
    results = analyze(packets)
    assert has_alert(results, title="LLMNR", category="lateral")


def test_nbtns_poisoning_fires(analyze):
    # NBT-NS (UDP sport 137) responses are dissected as NBNSHeader; RESPONSE/
    # ANCOUNT map onto qr/ancount in the packet view.
    packets = []
    t = 1_000_000.0
    for i in range(12):
        resp = (
            IP(src=LOCAL_IP, dst="10.0.0.100")
            / UDP(sport=137, dport=50000 + i)
            / NBNSHeader(RESPONSE=1, ANCOUNT=1)
            / NBNSQueryResponse()
        )
        resp.time = t
        t += 0.5
        packets.append(resp)
    results = analyze(packets)
    assert has_alert(results, title="LLMNR", category="lateral")


def test_few_llmnr_responses_do_not_fire(analyze):
    # Below the default threshold of 10 responses.
    packets = []
    t = 1_000_000.0
    for i in range(5):
        resp = (
            IP(src=LOCAL_IP, dst="10.0.0.100")
            / UDP(sport=5355, dport=50000 + i)
            / LLMNRResponse(qr=1, qdcount=1, ancount=1,
                            qd=DNSQR(qname="wpad"),
                            an=DNSRR(rrname="wpad", rdata=LOCAL_IP))
        )
        resp.time = t
        t += 0.5
        packets.append(resp)
    results = analyze(packets)
    assert not has_alert(results, title="LLMNR")
