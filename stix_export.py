"""
Export scan results to STIX 2.1 bundles and MISP events.

Pure-stdlib generator: no `stix2` Python library dependency. We emit a
flat bundle of STIX 2.1 indicator objects derived from:

  - external IPs that triggered alerts (ipv4-addr / ipv6-addr indicators)
  - SNI / HTTP host artifacts (domain-name indicators)
  - JA3 / JA3S fingerprints (custom indicator with extension keys)

For MISP we produce an Event JSON with an Attribute list (compatible with
MISP's REST/import path: https://www.misp-project.org/openapi/).

Both outputs are pure JSON. The endpoint returns the bundle to the
browser as a download.
"""
import ipaddress
import uuid
from datetime import datetime


SPEC_VERSION = "2.1"


def _utcnow_iso():
    # STIX requires fractional seconds + 'Z'
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _new_id(typ):
    return f"{typ}--{uuid.uuid4()}"


def _identity():
    """Reporter identity for created_by_ref pointers."""
    ts = _utcnow_iso()
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": _new_id("identity"),
        "created": ts,
        "modified": ts,
        "name": "PCAP Analyzer",
        "identity_class": "system",
        "description": "Indicators derived from PCAP/PCAPNG capture analysis.",
    }


def _ip_pattern(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    typ = "ipv6-addr" if addr.version == 6 else "ipv4-addr"
    return f"[{typ}:value = '{ip}']"


def _domain_pattern(d):
    if not d or " " in d or "/" in d:
        return None
    return f"[domain-name:value = '{d}']"


def _make_indicator(ident_id, name, description, pattern, labels, kill_chain=None):
    ts = _utcnow_iso()
    obj = {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": _new_id("indicator"),
        "created": ts,
        "modified": ts,
        "created_by_ref": ident_id,
        "name": name,
        "description": description,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts,
        "indicator_types": labels,
    }
    if kill_chain:
        obj["kill_chain_phases"] = kill_chain
    return obj


# ============================================================
#  Public: STIX 2.1 bundle
# ============================================================

def to_stix_bundle(results, scan_id=None):
    """Return a STIX 2.1 bundle dict ready for json.dumps()."""
    if not results:
        results = {}

    identity = _identity()
    objects = [identity]

    alerts = results.get("alerts") or []
    observed = results.get("observed_artifacts") or {}
    summary = results.get("summary") or {}

    # ----- Per-IP indicators (only for IPs that have an alert attached) -----
    ip_alerts = {}
    for a in alerts:
        ip = a.get("ip")
        if not ip:
            continue
        ip_alerts.setdefault(ip, []).append(a)

    for ip, ip_a in ip_alerts.items():
        # Skip private IPs — they aren't useful as shareable IOCs.
        try:
            if ipaddress.ip_address(ip).is_private:
                continue
        except ValueError:
            continue
        pattern = _ip_pattern(ip)
        if not pattern:
            continue
        # Use the highest-severity alert title to label the indicator
        sev_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        worst = max(ip_a, key=lambda x: sev_rank.get(x.get("severity"), 0))
        kc = []
        mitre = worst.get("mitre_attack") or {}
        if mitre.get("tactic_name"):
            kc.append({
                "kill_chain_name": "mitre-attack",
                "phase_name": mitre["tactic_name"].lower().replace(" ", "-"),
            })
        objects.append(_make_indicator(
            ident_id=identity["id"],
            name=f"Suspicious IP {ip}",
            description=(
                f"{worst.get('title', 'alert')} (and {len(ip_a) - 1} more)"
                if len(ip_a) > 1 else worst.get("title", "alert")
            ),
            pattern=pattern,
            labels=["malicious-activity"],
            kill_chain=kc,
        ))

    # ----- Domain-name indicators from SNI + HTTP host -----
    seen_domains = set()
    for d in (observed.get("sni") or []) + (observed.get("http_host") or []):
        if not d or d in seen_domains:
            continue
        seen_domains.add(d)
        pattern = _domain_pattern(d)
        if not pattern:
            continue
        # Domains alone are not "malicious" — we ship them as anomalous
        # observations. Operators should triage before sharing externally.
        objects.append(_make_indicator(
            ident_id=identity["id"],
            name=f"Domain {d}",
            description="Observed in TLS SNI or HTTP Host header",
            pattern=pattern,
            labels=["anomalous-activity"],
        ))

    # ----- JA3 / JA3S as custom-pattern indicators -----
    for ja3 in observed.get("ja3") or []:
        pattern = f"[network-traffic:extensions.'tls-ext'.ja3 = '{ja3}']"
        objects.append(_make_indicator(
            ident_id=identity["id"],
            name=f"JA3 fingerprint {ja3[:8]}…",
            description="Client TLS fingerprint observed in this capture",
            pattern=pattern,
            labels=["anomalous-activity"],
        ))
    for ja3s in observed.get("ja3s") or []:
        pattern = f"[network-traffic:extensions.'tls-ext'.ja3s = '{ja3s}']"
        objects.append(_make_indicator(
            ident_id=identity["id"],
            name=f"JA3S fingerprint {ja3s[:8]}…",
            description="Server TLS fingerprint observed in this capture",
            pattern=pattern,
            labels=["anomalous-activity"],
        ))

    bundle = {
        "type": "bundle",
        "id": _new_id("bundle"),
        "objects": objects,
    }
    return bundle


# ============================================================
#  Public: MISP event
# ============================================================

def to_misp_event(results, scan_id=None):
    """
    Return a MISP-compatible event JSON. Uses the standard MISP attribute
    types: ip-dst, domain, x509-fingerprint-sha1 won't work for JA3 so we
    use the ja3-fingerprint-md5 type that the MISP community has adopted.
    """
    if not results:
        results = {}
    summary = results.get("summary") or {}
    alerts = results.get("alerts") or []
    observed = results.get("observed_artifacts") or {}

    attributes = []
    seen_values = set()

    def _push(typ, value, comment, category="Network activity"):
        key = (typ, value)
        if key in seen_values:
            return
        seen_values.add(key)
        attributes.append({
            "type": typ,
            "category": category,
            "to_ids": True,
            "value": value,
            "comment": comment,
        })

    for a in alerts:
        ip = a.get("ip")
        if not ip:
            continue
        try:
            if ipaddress.ip_address(ip).is_private:
                continue
        except ValueError:
            continue
        _push("ip-dst", ip, a.get("title") or "alert source")

    for d in observed.get("sni") or []:
        _push("domain", d, "TLS SNI", "Network activity")
    for d in observed.get("http_host") or []:
        _push("domain", d, "HTTP Host header", "Network activity")
    for ja3 in observed.get("ja3") or []:
        _push("ja3-fingerprint-md5", ja3, "Client TLS JA3", "Network activity")
    for ja3s in observed.get("ja3s") or []:
        _push("ja3s-fingerprint-md5", ja3s, "Server TLS JA3S", "Network activity")

    event = {
        "Event": {
            "info": (
                f"PCAP Analyzer scan #{scan_id}: "
                f"{summary.get('filename') or 'capture'}"
            ),
            "analysis": "1",
            "threat_level_id": "3",
            "distribution": "0",
            "date": (summary.get("analyzed_at") or _utcnow_iso())[:10],
            "Attribute": attributes,
        }
    }
    return event
