"""Host identity: IPv4 + IPv6 of one machine tied together by MAC.

Covers the pure resolver (pcap_analyzer.hosts), the streaming aggregator
(ARP / NDP / DHCP / Ethernet bindings and name discovery), the
multiple-address and binding-conflict alerts, and the host-level
exfiltration detector that sums IPv4 + IPv6 traffic of the same machine.
"""

from scapy.all import ARP, Ether, IP, IPv6, TCP, UDP, Raw
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest

from pcap_analyzer.hosts import (
    HostObservations, build_hosts, classify_ip, clean_host_name,
    ipv6_is_eui64_of, normalize_mac,
)

from conftest import find_alerts, has_alert

MAC_A = "00:1a:2b:3c:4d:5e"       # PDH02-like workstation
MAC_B = "00:1a:2b:3c:4d:5f"       # another workstation
MAC_GW = "00:aa:bb:cc:dd:01"      # router
V4_A = "192.168.50.55"
LL_A = "fe80::fb21:3bcc:4b6d:5b01"
GLOBAL_A = "2804:14c:1:2::55"
INTERNET_V4 = "8.8.8.8"
INTERNET_V6 = "2001:4860:4860::8888"


def _t(pkts, start=1_000_000.0, step=0.5):
    t = start
    for p in pkts:
        p.time = t
        t += step
    return pkts


def _hosts(results):
    return {h["host_key"]: h for h in results.get("hosts", [])}


def _ips(host):
    return {a["ip"] for a in host["addresses"]}


# --------------------------------------------------------------- pure logic

def test_classify_ip_scopes():
    assert classify_ip("192.168.1.10") == (4, "v4_private")
    assert classify_ip("100.64.1.1") == (4, "v4_private")
    assert classify_ip("169.254.3.3") == (4, "v4_link_local")
    assert classify_ip("8.8.8.8") == (4, "v4_public")
    assert classify_ip("fe80::1") == (6, "v6_link_local")
    assert classify_ip("fd00::1") == (6, "v6_ula")
    assert classify_ip("2001:db8::1") == (6, "v6_global")
    for bad in ("0.0.0.0", "255.255.255.255", "224.0.0.251", "ff02::1", "::", "x"):
        assert classify_ip(bad) == (None, None), bad


def test_mac_helpers():
    assert normalize_mac("00-1A-2B-3C-4D-5E") == MAC_A
    assert normalize_mac("ff:ff:ff:ff:ff:ff") is None
    assert normalize_mac("01:00:5e:00:00:fb") is None   # multicast
    assert ipv6_is_eui64_of("fe80::21a:2bff:fe3c:4d5e", MAC_A)
    assert not ipv6_is_eui64_of(LL_A, MAC_A)


def test_clean_host_name():
    assert clean_host_name("CDVHS02        ") == "CDVHS02"
    assert clean_host_name(b"laptop.local.") == "laptop"
    assert clean_host_name("wpad") is None
    assert clean_host_name("") is None


def test_router_mac_does_not_become_a_host_of_remote_ips():
    obs = HostObservations()
    obs.observe(MAC_GW, "192.168.50.1", "arp", 1.0)
    for i in range(10):  # routed traffic from other subnets / internet
        obs.observe(MAC_GW, f"10.9.0.{i}", "l2", 1.0)
    obs.observe(MAC_GW, INTERNET_V4, "l2", 1.0)
    hosts, ip_host, _ = build_hosts(obs)
    gw = [h for h in hosts if h["host_key"] == MAC_GW][0]
    assert gw["gateway_like"]
    assert _ips(gw) == {"192.168.50.1"}   # only what it proved via ARP
    assert "10.9.0.3" not in ip_host


def test_authoritative_binding_beats_observed():
    obs = HostObservations()
    obs.observe(MAC_B, V4_A, "l2", 5.0)
    obs.observe(MAC_A, V4_A, "arp", 1.0)
    _, ip_host, _ = build_hosts(obs)
    assert ip_host[V4_A] == MAC_A


def test_manual_binding_moves_ip_and_conflict_keeps_it():
    obs = HostObservations()
    obs.observe(MAC_A, V4_A, "arp", 1.0)
    obs.observe(MAC_B, "192.168.50.77", "arp", 1.0)
    # Manual: bind a v6 address to host A (not seen with any MAC) -> moves in.
    # Manual: bind B's IP to host A -> capture contradicts -> conflict.
    manual = [{"host_key": MAC_A, "ip": GLOBAL_A},
              {"host_key": MAC_A, "ip": "192.168.50.77"}]
    hosts, ip_host, conflicts = build_hosts(obs, manual=manual)
    assert ip_host[GLOBAL_A] == MAC_A
    assert ip_host["192.168.50.77"] == MAC_B
    assert conflicts == [{"ip": "192.168.50.77", "host_key": MAC_A,
                          "expected_mac": MAC_A, "observed_mac": MAC_B}]


def test_manual_host_without_mac_groups_ips():
    obs = HostObservations()
    manual = [{"host_key": "manual:srv1", "ip": "10.20.0.5"},
              {"host_key": "manual:srv1", "ip": "2001:db8::5"}]
    hosts, ip_host, _ = build_hosts(obs, manual=manual)
    assert ip_host["10.20.0.5"] == ip_host["2001:db8::5"] == "manual:srv1"
    assert hosts[0]["manual"] is True


def test_excluded_binding_is_dropped():
    obs = HostObservations()
    obs.observe(MAC_A, V4_A, "arp", 1.0)
    obs.observe(MAC_A, LL_A, "ndp", 1.0)
    _, ip_host, _ = build_hosts(obs, excluded=[{"host_key": MAC_A, "ip": LL_A}])
    assert V4_A in ip_host and LL_A not in ip_host


# ------------------------------------------------------ aggregator (engine)

def _arp(mac, ip):
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=mac, psrc=ip, pdst="192.168.50.1")


def _na(mac, ip):
    return (Ether(src=mac, dst="33:33:00:00:00:01") / IPv6(src=ip, dst="ff02::1")
            / ICMPv6ND_NA(tgt=ip, R=0, S=0, O=1) / ICMPv6NDOptDstLLAddr(lladdr=mac))


def test_dual_stack_host_is_one_machine(analyze):
    pkts = _t([
        _arp(MAC_A, V4_A),
        _na(MAC_A, LL_A),
        Ether(src=MAC_A) / IPv6(src=GLOBAL_A, dst=INTERNET_V6) / TCP(sport=40000, dport=443, flags="S"),
    ])
    results = analyze(pkts)
    host = _hosts(results)[MAC_A]
    assert _ips(host) == {V4_A, LL_A, GLOBAL_A}
    # Per-IP rows carry the host key so the UI can total them.
    # (ARP-only addresses carry no traffic, so check the IPv6 row.)
    rows = {r["ip"]: r for r in results["ips"]}
    assert rows[GLOBAL_A].get("host_key") == MAC_A
    assert not has_alert(results, title="Host with Multiple")


def test_dhcp_hostname_and_lease_are_learned(analyze):
    chaddr = bytes.fromhex(MAC_A.replace(":", ""))
    req = (Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
           / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=chaddr)
           / DHCP(options=[("message-type", 3), ("hostname", b"CDVHS02"), "end"]))
    ack = (Ether(src=MAC_GW, dst=MAC_A) / IP(src="192.168.50.1", dst=V4_A)
           / UDP(sport=67, dport=68) / BOOTP(op=2, chaddr=chaddr, yiaddr=V4_A)
           / DHCP(options=[("message-type", 5), "end"]))
    results = analyze(_t([req, ack]))
    host = _hosts(results)[MAC_A]
    assert host["discovered_name"] == "CDVHS02"
    assert host["name_source"] == "dhcp"
    assert V4_A in _ips(host)


def test_netbios_registration_names_the_host(analyze):
    reg = (Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / IP(src=V4_A, dst="192.168.50.255")
           / UDP(sport=137, dport=137) / NBNSHeader(OPCODE=5)
           / NBNSRegistrationRequest(QUESTION_NAME="CDVHS02", NB_ADDRESS=V4_A))
    results = analyze(_t([_arp(MAC_A, V4_A), reg]))
    assert _hosts(results)[MAC_A]["discovered_name"] == "CDVHS02"


def test_two_simultaneous_ipv4_is_medium(analyze):
    pkts = _t([_arp(MAC_A, V4_A), _arp(MAC_A, "192.168.50.56"),
               _arp(MAC_A, V4_A), _arp(MAC_A, "192.168.50.56")])
    hits = find_alerts(analyze(pkts), title="Host with Multiple IPv4 Addresses")
    assert hits and hits[0]["severity"] == "medium"
    assert hits[0]["details"]["simultaneous"] is True


def test_sequential_ipv4_is_low_dhcp_renewal(analyze):
    pkts = _t([_arp(MAC_A, V4_A), _arp(MAC_A, V4_A),
               _arp(MAC_A, "192.168.50.56"), _arp(MAC_A, "192.168.50.56")])
    hits = find_alerts(analyze(pkts), title="Host with Multiple IPv4 Addresses")
    assert hits and hits[0]["severity"] == "low"


def test_two_link_local_is_medium_but_many_globals_is_fine(analyze):
    pkts = [_arp(MAC_A, V4_A), _na(MAC_A, LL_A)]
    for i in range(4):  # privacy addresses rotating: normal
        pkts.append(Ether(src=MAC_A) / IPv6(src=f"2804:14c:1:2::{i + 1:x}", dst=INTERNET_V6)
                    / TCP(sport=40000 + i, dport=443, flags="S"))
    results = analyze(_t(pkts))
    assert not has_alert(results, title="Host with Multiple IPv6")
    results = analyze(_t([_na(MAC_A, LL_A), _na(MAC_A, "fe80::1234")]))
    hits = find_alerts(results, title="Host with Multiple IPv6 Link-Local")
    assert hits and hits[0]["severity"] == "medium"


def test_gateway_is_not_flagged_for_many_addresses(analyze):
    pkts = [_arp(MAC_GW, "192.168.50.1"), _arp(MAC_GW, "192.168.60.1")]
    pkts += [Ether(src=MAC_GW) / IP(src=INTERNET_V4, dst=V4_A) / TCP(sport=443, dport=40000, flags="A")]
    assert not has_alert(analyze(_t(pkts)), title="Host with Multiple IPv4")


def test_manual_binding_silences_and_conflict_alerts(analyze):
    settings = {"host_bindings": {"manual": [
        {"host_key": MAC_A, "ip": "192.168.50.56"},     # user accepts it
        {"host_key": MAC_A, "ip": "192.168.50.77"},     # but capture says B
    ]}}
    pkts = _t([_arp(MAC_A, V4_A), _arp(MAC_A, "192.168.50.56"),
               _arp(MAC_B, "192.168.50.77"), _arp(MAC_A, V4_A)])
    results = analyze(pkts, settings)
    assert not has_alert(results, title="Host with Multiple IPv4")
    hits = find_alerts(results, title="Manual Host Binding Conflict")
    assert hits and hits[0]["ip"] == "192.168.50.77"


def test_alerts_carry_host_key(analyze):
    pkts = _t([_arp(MAC_A, V4_A), _arp(MAC_A, "192.168.50.56"),
               _arp(MAC_A, V4_A), _arp(MAC_A, "192.168.50.56")])
    hits = find_alerts(analyze(pkts), title="Host with Multiple IPv4")
    assert hits[0]["details"]["host_key"] == MAC_A
    assert hits[0]["details"]["host_mac"] == MAC_A


# ------------------------------------------------------- host exfiltration

_EXFIL = {"thresholds": {"exfil_min_bytes_out": 60_000, "exfil_min_ratio": 5.0}}


def _upload(mac, src, dst, n, sport):
    return [Ether(src=mac) / (IPv6(src=src, dst=dst) if ":" in src else IP(src=src, dst=dst))
            / TCP(sport=sport, dport=443, flags="PA") / Raw(b"U" * 1000) for _ in range(n)]


def test_upload_split_between_ipv4_and_ipv6_is_caught(analyze):
    # 40 KB over IPv4 + 40 KB over IPv6: each below 60 KB, together above.
    # The DNS answer names both server addresses, so they are one destination.
    from scapy.all import DNS, DNSQR, DNSRR
    dns = (Ether(src=MAC_GW, dst=MAC_A) / IP(src="192.168.50.1", dst=V4_A) / UDP(sport=53, dport=33333)
           / DNS(qr=1, qd=DNSQR(qname="drop.example.com"),
                 an=DNSRR(rrname="drop.example.com", type="A", rdata="45.33.32.156")
                 / DNSRR(rrname="drop.example.com", type="AAAA", rdata="2a00:1450:4001::9")))
    pkts = [dns, _arp(MAC_A, V4_A), _na(MAC_A, LL_A)]
    pkts += _upload(MAC_A, V4_A, "45.33.32.156", 40, 41000)
    pkts += _upload(MAC_A, GLOBAL_A, "2a00:1450:4001::9", 40, 41001)
    results = analyze(_t(pkts, step=0.1), _EXFIL)
    assert not has_alert(results, title="Possible Data Exfiltration (Upload Volume)")
    hits = find_alerts(results, title="Possible Data Exfiltration (Host Aggregate)")
    assert hits
    d = hits[0]["details"]
    assert d["host_key"] == MAC_A
    assert set(d["contributing_ips"]) == {V4_A, GLOBAL_A}
    assert d["destination"] == "example.com"


def test_host_exfil_does_not_duplicate_per_pair_alert(analyze):
    pkts = [_arp(MAC_A, V4_A)] + _upload(MAC_A, V4_A, "45.33.32.156", 80, 41000)
    results = analyze(_t(pkts, step=0.1), _EXFIL)
    assert has_alert(results, title="Possible Data Exfiltration (Upload Volume)")
    assert not has_alert(results, title="Possible Data Exfiltration (Host Aggregate)")
