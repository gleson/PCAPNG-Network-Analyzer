"""ICS/OT protocol streaming detector.

Identifies industrial protocols by TCP port and, for Modbus/TCP (502), parses
the MBAP header + function code to separate reads from writes. A write function
code arriving from an external IP is the crown-jewel critical alert.
"""

from scapy.all import IP, TCP, Raw

from conftest import LOCAL_IP, LOCAL_IP_2, EXTERNAL_IP, find_alerts, has_alert


def _modbus(fc, src, dst, sport=40000):
    # MBAP: transaction(2) protocol(2)=0 length(2) unit(1) + function code(1).
    payload = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, fc]) + b"\x00" * 4
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=502, flags="PA") / Raw(payload)


def test_ics_protocol_presence_fires(analyze):
    # Any TCP traffic to an ICS port (502 = Modbus/TCP) -> presence alert.
    pkt = IP(src=LOCAL_IP, dst=LOCAL_IP_2) / TCP(sport=40000, dport=502, flags="S")
    results = analyze([pkt])
    hits = find_alerts(results, title="ICS/OT Protocol Detected", category="ics")
    assert hits
    assert hits[0]["details"]["protocol"] == "Modbus/TCP"


def test_modbus_write_from_external_is_critical(analyze):
    # FC 6 = Write Single Register, from an external IP to an internal PLC.
    pkt = _modbus(0x06, src=EXTERNAL_IP, dst=LOCAL_IP)
    results = analyze([pkt])
    hits = find_alerts(results, title="Modbus Write Function from External IP", category="ics")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert 6 in hits[0]["details"]["function_codes"]


def test_modbus_write_from_internal_not_critical(analyze):
    # Same write, but from an internal engineering workstation -> no critical.
    pkt = _modbus(0x06, src=LOCAL_IP_2, dst=LOCAL_IP)
    results = analyze([pkt])
    assert not has_alert(results, title="Modbus Write Function from External IP")


def test_modbus_read_from_external_not_critical(analyze):
    # FC 3 = Read Holding Registers is not a write -> no critical write alert.
    pkt = _modbus(0x03, src=EXTERNAL_IP, dst=LOCAL_IP)
    results = analyze([pkt])
    assert not has_alert(results, title="Modbus Write Function from External IP")
