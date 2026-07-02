"""Covert-channel / tunneling streaming detectors.

- DoT (DNS-over-TLS, TCP/853)
- ModernTunnel: WireGuard handshake init, OpenVPN hard-reset, IP-layer
  encapsulation (GRE/IPIP/SIT) crossing the perimeter.

These identify tunnels by wire signature (port, fixed-length handshake,
opcode, IP protocol number), so the fixtures forge those bytes directly.
"""

from scapy.all import IP, TCP, UDP, Raw

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert


# --- DNS-over-TLS ----------------------------------------------------------

def test_dot_to_unknown_resolver_fires(analyze):
    # A public IP that is NOT in KNOWN_PUBLIC_DNS_RESOLVERS (8.8.8.8/1.1.1.1
    # are, so they can't stand in for an "unknown" resolver here).
    pkt = IP(src=LOCAL_IP, dst="45.33.32.156") / TCP(sport=40000, dport=853, flags="S")
    results = analyze([pkt])
    hits = find_alerts(results, title="DNS-over-TLS", category="dns")
    assert hits
    assert hits[0]["details"]["port"] == 853
    assert hits[0]["details"]["known_public_resolver"] is False


def test_dot_to_known_resolver_flagged_as_known(analyze):
    # 9.9.9.9 (Quad9) is in KNOWN_PUBLIC_DNS_RESOLVERS.
    pkt = IP(src=LOCAL_IP, dst="9.9.9.9") / TCP(sport=40001, dport=853, flags="S")
    results = analyze([pkt])
    hits = find_alerts(results, title="DNS-over-TLS")
    assert hits
    assert hits[0]["details"]["known_public_resolver"] is True


# --- WireGuard -------------------------------------------------------------

def test_wireguard_handshake_on_nonstandard_port_fires_high(analyze):
    # 148-byte init, message_type=1 (0x01000000 LE), port != 51820.
    payload = b"\x01\x00\x00\x00" + b"\x00" * 144
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / UDP(sport=33333, dport=33333) / Raw(payload)
    results = analyze([pkt])
    hits = find_alerts(results, title="WireGuard", category="tunneling")
    assert hits
    assert hits[0]["severity"] == "high"
    assert hits[0]["details"]["non_standard_port"] is True


def test_wireguard_wrong_length_does_not_fire(analyze):
    payload = b"\x01\x00\x00\x00" + b"\x00" * 32  # not 148 bytes
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / UDP(sport=33333, dport=33333) / Raw(payload)
    results = analyze([pkt])
    assert not has_alert(results, title="WireGuard")


# --- OpenVPN ---------------------------------------------------------------

def test_openvpn_hard_reset_on_nonstandard_port_fires(analyze):
    # First byte 0x38 -> opcode (0x38>>3)=7 (P_CONTROL_HARD_RESET_CLIENT_V2).
    payload = b"\x38" + b"\x00" * 23
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / UDP(sport=40000, dport=40000) / Raw(payload)
    results = analyze([pkt])
    hits = find_alerts(results, title="OpenVPN", category="tunneling")
    assert hits
    assert 7 in hits[0]["details"]["opcodes"]


def test_openvpn_server_reset_first_byte_fires(analyze):
    # 0x40 = P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8) on a non-web port.
    payload = b"\x40" + b"\x00" * 23
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / UDP(sport=40000, dport=40001) / Raw(payload)
    results = analyze([pkt])
    hits = find_alerts(results, title="OpenVPN", category="tunneling")
    assert hits
    assert 8 in hits[0]["details"]["opcodes"]


def test_quic_short_header_on_443_is_not_openvpn(analyze):
    # Regression (2026-07): a QUIC 1-RTT short header starts at 0x40-0x47 —
    # the same first byte as the OpenVPN server hard-reset — so every HTTP/3
    # flow on udp/443 raised a false "OpenVPN on Non-Standard UDP Port".
    for b0 in (0x40, 0x41, 0x45):
        payload = bytes([b0]) + b"\x00" * 30
        pkt = (IP(src=LOCAL_IP, dst=EXTERNAL_IP)
               / UDP(sport=52000, dport=443) / Raw(payload))
        results = analyze([pkt])
        assert not has_alert(results, title="OpenVPN"), hex(b0)


def test_openvpn_nonzero_key_id_does_not_fire(analyze):
    # 0x39 has opcode 7 but key_id=1 — hard-resets always carry key_id 0, so
    # matching the full first byte (not just the top 5 bits) must reject it.
    payload = b"\x39" + b"\x00" * 23
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP) / UDP(sport=40000, dport=40002) / Raw(payload)
    results = analyze([pkt])
    assert not has_alert(results, title="OpenVPN")


# --- IP-layer encapsulation ------------------------------------------------

def test_gre_encapsulation_to_external_fires(analyze):
    # IP proto 47 (GRE), one local endpoint and one external -> perimeter tunnel.
    pkt = IP(src=LOCAL_IP, dst=EXTERNAL_IP, proto=47) / Raw(b"\x00" * 16)
    results = analyze([pkt])
    hits = find_alerts(results, title="IP Encapsulation", category="tunneling")
    assert hits
    assert hits[0]["details"]["proto_name"] == "GRE"


def test_internal_gre_does_not_fire(analyze):
    # Both endpoints local -> not a perimeter-crossing tunnel.
    pkt = IP(src=LOCAL_IP, dst="10.0.0.9", proto=47) / Raw(b"\x00" * 16)
    results = analyze([pkt])
    assert not has_alert(results, title="IP Encapsulation")
