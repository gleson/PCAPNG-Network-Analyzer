"""Regression tests for DCERPC lateral-movement pipe detection
(OperationalExposureStreamingDetector, SMB path).

Bug found 2026-06-19: the detector only scanned the Raw payload for the
literal ``\\PIPE\\`` — an SMB1 convention. Modern SMB2/3 (PsExec, Impacket)
carries the bare pipe name (e.g. ``svcctl``) as the UTF-16LE filename of a
CREATE request, with no ``\\PIPE\\`` on the wire; and scapy fully parses valid
SMB2 so the Raw payload is gone entirely. Net: SMB2/3 named-pipe lateral
movement was completely missed. pkt_view now extracts the SMB2 CREATE filename
and the detector matches it against DCERPC_LATERAL_PIPES; the SMB1 byte-scan
remains for legacy traffic.
"""

from scapy.all import IP, TCP, Raw
from scapy.layers.smb2 import SMB2_Header, SMB2_Create_Request
from scapy.layers.netbios import NBTSession

from conftest import LOCAL_IP

EXTERNAL_IP = "1.2.3.4"


def _smb2_create(name, src=EXTERNAL_IP, dst=LOCAL_IP, sport=40000):
    return (IP(src=src, dst=dst) / TCP(sport=sport, dport=445, flags="PA")
            / NBTSession() / SMB2_Header(Command=5)
            / SMB2_Create_Request(Buffer=[("Name", name)]))


def _pipe_alerts(results):
    return [a for a in results["alerts"]
            if a.get("category") == "lateral" and "PIPE" in a["title"].upper()]


def test_smb2_named_pipe_lateral_fires(analyze):
    pkt = _smb2_create("svcctl")
    pkt.time = 1_000_000.0
    results = analyze([pkt])
    hits = _pipe_alerts(results)
    assert hits, "expected a DCERPC lateral-movement pipe alert for SMB2 svcctl"
    assert hits[0]["details"]["pipe"] == "svcctl"


def test_smb2_benign_filename_does_not_fire(analyze):
    pkt = _smb2_create("report.docx", sport=40001)
    pkt.time = 1_000_000.0
    results = analyze([pkt])
    assert not _pipe_alerts(results)


def test_smb1_pipe_literal_still_detected(analyze):
    # Legacy SMB1 path: literal \PIPE\<name> in the raw payload.
    pkt = (IP(src=EXTERNAL_IP, dst=LOCAL_IP) / TCP(sport=40002, dport=445, flags="PA")
           / Raw(b"\xffSMB" + b"\x00" * 30 + b"\\PIPE\\lsarpc\x00"))
    pkt.time = 1_000_000.0
    results = analyze([pkt])
    hits = _pipe_alerts(results)
    assert hits
    assert hits[0]["details"]["pipe"] == "lsarpc"
