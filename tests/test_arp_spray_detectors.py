"""Layer-2 spoofing and password-spraying streaming detectors.

- ArpSpoofingStreamingDetector: an IP whose MAC changes (MITM) -> critical;
  a flood of gratuitous ARPs from one MAC -> high.
- PasswordSprayingStreamingDetector: one source touching many distinct hosts
  on an auth port with a single SYN each (the inverse of brute force) -> the
  lockout-evading spray pattern.
"""

from scapy.all import IP, TCP, ARP, Ether

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert

MAC_A = "aa:bb:cc:00:00:01"
MAC_B = "aa:bb:cc:00:00:02"


def _arp_reply(psrc, hwsrc, pdst="10.0.0.1"):
    return Ether(src=hwsrc) / ARP(op=2, psrc=psrc, hwsrc=hwsrc, pdst=pdst)


def _arp_request(psrc, hwsrc, pdst):
    return Ether(src=hwsrc) / ARP(op=1, psrc=psrc, hwsrc=hwsrc, pdst=pdst)


# --- ARP spoofing ----------------------------------------------------------

def test_single_arp_mac_change_is_medium_not_spoofing(analyze):
    # One clean A->B change is what DHCP reassignment / NIC swap look like:
    # reported, but not as a critical MITM.
    packets = [
        _arp_reply("10.0.0.50", MAC_A),
        _arp_reply("10.0.0.50", MAC_B),
    ]
    results = analyze(packets)
    assert not has_alert(results, title="ARP Spoofing Detected")
    hits = find_alerts(results, title="ARP IP-to-MAC Change", category="arp")
    assert hits
    assert hits[0]["severity"] == "medium"
    assert hits[0]["details"]["old_mac"] == MAC_A
    assert hits[0]["details"]["new_mac"] == MAC_B


def test_arp_flip_flop_is_critical(analyze):
    # Legit owner and attacker keep answering: A -> B -> A -> B.
    t = 1_000_000.0
    packets = []
    for i, mac in enumerate([MAC_A, MAC_B, MAC_A, MAC_B]):
        pk = _arp_reply("10.0.0.50", mac)
        pk.time = t + i * 10
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="ARP Spoofing Detected", category="arp")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["flip_flop"] is True


def test_arp_aggressive_reannounce_is_critical(analyze):
    # arpspoof-style: the new MAC re-claims the IP every 2s after taking it.
    t = 1_000_000.0
    first = _arp_reply("10.0.0.1", MAC_A)
    first.time = t
    packets = [first]
    for i in range(6):
        pk = _arp_reply("10.0.0.1", MAC_B, pdst="10.0.0.9")
        pk.time = t + 5 + i * 2
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="ARP Spoofing Detected", category="arp")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["max_claims_in_window"] >= 5


def test_arp_new_mac_keeping_its_own_ip_is_critical(analyze):
    # Attacker MAC_B owns 10.0.0.66 and ALSO starts answering for .50.
    t = 1_000_000.0
    seq = [("10.0.0.66", MAC_B), ("10.0.0.50", MAC_A),
           ("10.0.0.50", MAC_B), ("10.0.0.66", MAC_B)]
    packets = []
    for i, (ip, mac) in enumerate(seq):
        pk = _arp_reply(ip, mac, pdst="10.0.0.9")
        pk.time = t + i * 20
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="ARP Spoofing Detected", category="arp")
    assert hits
    assert "10.0.0.66" in hits[0]["details"]["new_mac_other_ips"]


def test_single_gateway_mac_change_is_high(analyze):
    packets = [
        _arp_reply("10.0.0.1", MAC_A, pdst="10.0.0.9"),
        _arp_reply("10.0.0.1", MAC_B, pdst="10.0.0.9"),
    ]
    results = analyze(packets)
    hits = find_alerts(results, title="ARP IP-to-MAC Change", category="arp")
    assert hits and hits[0]["severity"] == "high"


def test_stable_arp_does_not_fire(analyze):
    # Same IP, same MAC, repeated -> no spoofing.
    packets = [_arp_reply("10.0.0.50", MAC_A, pdst="10.0.0.9") for _ in range(4)]
    results = analyze(packets)
    assert not has_alert(results, title="ARP Spoofing Detected")


def test_gratuitous_arp_flood_fires(analyze):
    # Gratuitous ARP = pdst == psrc; >=5 from one MAC -> flood.
    packets = [_arp_reply("10.0.0.77", MAC_A, pdst="10.0.0.77") for _ in range(5)]
    results = analyze(packets)
    hits = find_alerts(results, title="Gratuitous ARP Flood", category="arp")
    assert hits
    assert hits[0]["details"]["count"] >= 5


def test_gratuitous_arp_flood_via_requests_fires(analyze):
    # GARP announcements are frequently sent as REQUESTS (op=1, psrc==pdst)
    # — poisoning tools use both forms. Was invisible when only op=2 counted.
    packets = [_arp_request("10.0.0.77", MAC_A, pdst="10.0.0.77")
               for _ in range(5)]
    results = analyze(packets)
    hits = find_alerts(results, title="Gratuitous ARP Flood", category="arp")
    assert hits
    assert hits[0]["details"]["count"] >= 5


def test_arp_mac_change_via_requests_is_detected(analyze):
    # Ownership claims in requests count too: same IP announced from two
    # MACs across who-has requests -> MITM signal.
    packets = [
        _arp_request("10.0.0.50", MAC_A, pdst="10.0.0.9"),
        _arp_request("10.0.0.50", MAC_B, pdst="10.0.0.9"),
    ]
    results = analyze(packets)
    assert has_alert(results, title="ARP IP-to-MAC Change")


def test_acd_probe_does_not_poison_mac_state(analyze):
    # DHCP/ACD probes use psrc 0.0.0.0 with the real MAC — NOT an ownership
    # claim. Two different MACs probing must not raise ARP spoofing, and a
    # later legitimate announce must not conflict with probe state.
    packets = [
        _arp_request("0.0.0.0", MAC_A, pdst="10.0.0.50"),
        _arp_request("0.0.0.0", MAC_B, pdst="10.0.0.50"),
        _arp_reply("10.0.0.50", MAC_A, pdst="10.0.0.9"),
    ]
    results = analyze(packets)
    assert not has_alert(results, title="ARP Spoofing Detected")
    assert not has_alert(results, title="ARP IP-to-MAC Change")


def test_sparse_gratuitous_arps_over_long_capture_do_not_flood(analyze):
    # A host re-announcing itself once every 10 min (DHCP renew / wake) is
    # normal; the flood counter is windowed, not lifetime.
    t = 1_000_000.0
    packets = []
    for i in range(8):
        pk = _arp_reply("10.0.0.77", MAC_A, pdst="10.0.0.77")
        pk.time = t + i * 600
        packets.append(pk)
    results = analyze(packets)
    assert not has_alert(results, title="Gratuitous ARP Flood")


# --- Password spraying -----------------------------------------------------

def test_password_spraying_smb_is_critical(analyze):
    # One source, a single SYN each against >=15 distinct hosts on SMB/445.
    packets = []
    t = 1_000_000.0
    for host in range(1, 17):  # 16 distinct targets (>= min_targets 15)
        pk = IP(src=EXTERNAL_IP, dst=f"10.0.0.{host}") / TCP(
            sport=50000 + host, dport=445, flags="S"
        )
        pk.time = t
        t += 1.0
        packets.append(pk)
    results = analyze(packets)
    hits = find_alerts(results, title="Password Spraying Detected", category="brute_force")
    assert hits
    assert "SMB" in hits[0]["title"]
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["distinct_targets"] >= 15


def test_few_spray_targets_do_not_fire(analyze):
    packets = []
    t = 1_000_000.0
    for host in range(1, 6):  # only 5 targets, below threshold
        pk = IP(src=EXTERNAL_IP, dst=f"10.0.0.{host}") / TCP(
            sport=50000 + host, dport=445, flags="S"
        )
        pk.time = t
        t += 1.0
        packets.append(pk)
    results = analyze(packets)
    assert not has_alert(results, title="Password Spraying Detected")
