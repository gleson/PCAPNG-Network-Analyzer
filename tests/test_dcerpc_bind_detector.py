"""Tests for DcerpcBindStreamingDetector (new coverage, 2026-06-19).

Port 135 previously had only fan-out detection (InternalLateral: one host ->
many targets). A *targeted* DCERPC attack (one->one) binding a notorious
interface was invisible. This detector inspects the bind's abstract-syntax UUID
and flags known abuse primitives (PetitPotam, PrinterBug, DCSync, svcctl, ...).
"""

import uuid

from scapy.all import IP, TCP
from scapy.layers.dcerpc import (
    DceRpc5, DceRpc5Bind, DceRpc5Context, DceRpc5AbstractSyntax,
)

from conftest import LOCAL_IP, LOCAL_IP_2, find_alerts, has_alert

# UUIDs (see constants.DCERPC_DANGEROUS_INTERFACES).
EFSR_PETITPOTAM = "c681d488-d850-11d0-8c52-00c04fd90f7e"
DRSUAPI_DCSYNC = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
BENIGN_UNKNOWN = "00000000-0000-0000-0000-000000000000"


def _bind(uuid_str, src=LOCAL_IP, dst=LOCAL_IP_2, sport=40000):
    absyn = DceRpc5AbstractSyntax(if_uuid=uuid.UUID(uuid_str), if_version=1)
    ctx = DceRpc5Context(context_id=0, abstract_syntax=absyn)
    b = DceRpc5Bind(n_context_elem=1, context_elem=[ctx])
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=135, flags="PA") / DceRpc5(ptype=11) / b
    pkt.time = 1_000_000.0
    return pkt


def test_petitpotam_efsr_bind_fires(analyze):
    results = analyze([_bind(EFSR_PETITPOTAM)])
    hits = find_alerts(results, title="DCERPC Bind", category="lateral")
    assert hits
    assert hits[0]["severity"] == "high"
    assert hits[0]["details"]["interface_uuid"] == EFSR_PETITPOTAM
    assert hits[0]["mitre_attack"]["technique_id"] == "T1187"


def test_dcsync_drsuapi_bind_is_critical(analyze):
    results = analyze([_bind(DRSUAPI_DCSYNC)])
    hits = find_alerts(results, title="DCERPC Bind")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["mitre_attack"]["technique_id"] == "T1003.006"


def test_unknown_interface_does_not_fire(analyze):
    results = analyze([_bind(BENIGN_UNKNOWN)])
    assert not has_alert(results, title="DCERPC Bind")
