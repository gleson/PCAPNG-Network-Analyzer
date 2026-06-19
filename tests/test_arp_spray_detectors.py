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


# --- ARP spoofing ----------------------------------------------------------

def test_arp_mac_change_is_critical(analyze):
    # Same IP announced first with MAC_A, then MAC_B -> MITM.
    packets = [
        _arp_reply("10.0.0.50", MAC_A),
        _arp_reply("10.0.0.50", MAC_B),
    ]
    results = analyze(packets)
    hits = find_alerts(results, title="ARP Spoofing Detected", category="arp")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["old_mac"] == MAC_A
    assert hits[0]["details"]["new_mac"] == MAC_B


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
