"""
User-defined detection rules.

Analysts can drop JSON rule files in `data/rules/` (one or many rules per
file) without touching code. Each rule declares match conditions over
packet headers and payload, an aggregation key + threshold, and the
alert template to emit when the threshold is met.

Goal: cover the 80% of "I want to detect when X talks to Y on port Z"
checks. Anything more complex still belongs in `pcap_analyzer.py`.

Schema (each rule):

  {
    "id": "telnet_external",                       # required, unique
    "name": "Telnet to External",                  # human label
    "severity": "high",                            # critical|high|medium|low
    "category": "protocol",                        # used for filtering / MITRE fallback
    "enabled": true,
    "match": {
      "protocol": "tcp",                           # tcp|udp|icmp|dns|any
      "dst_port": 23,
      "src_port": null,
      "src_cidr": "10.0.0.0/8",                    # source IP must lie in CIDR
      "dst_cidr": null,
      "direction": "outbound",                     # inbound|outbound|lateral|any
      "payload_contains": "USER ",                 # ASCII substring in raw payload
      "payload_regex": null                        # compiled if set; case-insensitive
    },
    "aggregate": {
      "key": "src+dst+dst_port",                   # how to group matched packets
      "min_count": 1,                              # alert when group has >= N
      "window_seconds": null                       # optional: only count within N s
    },
    "alert": {
      "title": "Telnet Connection",
      "description": "{src} -> {dst}:{dst_port} ({count} packets)",
      "recommendation": "Telnet is unencrypted; use SSH instead.",
      "mitre": {                                   # optional explicit override
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control"
      }
    }
  }

Empty / missing fields default to "match anything" — so a minimal rule
with just `dst_port: 4444` will fire on every packet matching that port.
"""
import glob
import ipaddress
import json
import os
import re
from collections import defaultdict
from datetime import datetime


DEFAULT_RULES_DIR = os.environ.get("PCAP_RULES_DIR", "data/rules")

VALID_PROTOCOLS = {"tcp", "udp", "icmp", "dns", "any"}
VALID_DIRECTIONS = {"inbound", "outbound", "lateral", "any"}
VALID_AGGREGATE_KEYS = {
    "src", "dst", "src+dst", "src+dst_port", "src+dst+dst_port",
}


# ============================================================
#  Loading & validation
# ============================================================

def load_rules(rules_dir=DEFAULT_RULES_DIR):
    """Read every rule file in *rules_dir* and return validated rule list.

    Picks up native JSON rules (``*.json``) plus imported Suricata
    (``*.rules`` / ``*.rule``) and Zeek (``*.sig`` / ``*.zeek``) files,
    parsing the latter through ``suricata_import``."""
    if not os.path.isdir(rules_dir):
        return []
    rules = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[user_rules] failed to read {path}: {e}")
            continue
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            print(f"[user_rules] {path}: top level must be object or array")
            continue
        for raw in data:
            try:
                rules.append(_normalize_rule(raw))
            except ValueError as e:
                print(f"[user_rules] {path}: invalid rule — {e}")

    # Imported Suricata / Zeek rule files
    import_globs = ("*.rules", "*.rule", "*.sig", "*.zeek")
    paths = []
    for pat in import_globs:
        paths.extend(glob.glob(os.path.join(rules_dir, pat)))
    if paths:
        try:
            from suricata_import import import_file
        except Exception as e:
            print(f"[user_rules] suricata_import unavailable: {e}")
            import_file = None
        if import_file is not None:
            for path in sorted(paths):
                try:
                    parsed = import_file(path)
                except Exception as e:
                    print(f"[user_rules] failed to import {path}: {e}")
                    continue
                for err in parsed.get("errors", []):
                    print(f"[user_rules] {path}: {err}")
                for raw in parsed.get("rules", []):
                    try:
                        rules.append(_normalize_rule(raw))
                    except ValueError as e:
                        print(f"[user_rules] {path}: invalid imported rule — {e}")

    return [r for r in rules if r.get("enabled", True)]


def _normalize_rule(raw):
    if not isinstance(raw, dict):
        raise ValueError("rule must be an object")
    if not raw.get("id"):
        raise ValueError("rule.id is required")
    rule = dict(raw)

    rule.setdefault("enabled", True)
    rule.setdefault("severity", "medium")
    rule.setdefault("category", "user-rule")
    rule.setdefault("match", {})
    rule.setdefault("aggregate", {})
    rule.setdefault("alert", {})

    m = rule["match"]
    proto = (m.get("protocol") or "any").lower()
    if proto not in VALID_PROTOCOLS:
        raise ValueError(f"match.protocol must be one of {sorted(VALID_PROTOCOLS)}")
    m["protocol"] = proto

    direction = (m.get("direction") or "any").lower()
    if direction not in VALID_DIRECTIONS:
        raise ValueError(f"match.direction must be one of {sorted(VALID_DIRECTIONS)}")
    m["direction"] = direction

    # Pre-compile CIDR / regex / contains for the hot loop
    if m.get("src_cidr"):
        m["_src_net"] = ipaddress.ip_network(m["src_cidr"], strict=False)
    if m.get("dst_cidr"):
        m["_dst_net"] = ipaddress.ip_network(m["dst_cidr"], strict=False)
    if m.get("payload_regex"):
        # A user-imported regex runs against packet payloads in the hot loop,
        # so a pathological pattern is a CPU-DoS (catastrophic backtracking).
        # A hard length cap bounds the blast radius without pulling in a
        # linear-time regex engine.
        regex_src = m["payload_regex"]
        if not isinstance(regex_src, str) or len(regex_src) > 512:
            raise ValueError("match.payload_regex must be a string of <= 512 chars")
        m["_payload_re"] = re.compile(regex_src.encode("utf-8"), re.IGNORECASE)
    if m.get("payload_contains"):
        m["_payload_contains_b"] = m["payload_contains"].encode("utf-8")

    agg = rule["aggregate"]
    key = agg.get("key") or "src+dst+dst_port"
    if key not in VALID_AGGREGATE_KEYS:
        raise ValueError(f"aggregate.key must be one of {sorted(VALID_AGGREGATE_KEYS)}")
    agg["key"] = key
    agg.setdefault("min_count", 1)
    if agg.get("window_seconds") is not None:
        agg["window_seconds"] = float(agg["window_seconds"])

    return rule


# ============================================================
#  Matching
# ============================================================

def _packet_5tuple(pkt):
    """
    Return (proto, src, dst, sport, dport, payload_bytes, ts).
    Lazy-imports scapy so the module is testable without it.
    """
    from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw
    if IP not in pkt:
        return None
    ip_layer = pkt[IP]
    src = ip_layer.src
    dst = ip_layer.dst
    sport = dport = None
    if TCP in pkt:
        proto = "tcp"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        proto = "udp"
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        if DNS in pkt:
            proto = "dns"
    elif ICMP in pkt:
        proto = "icmp"
    else:
        proto = "other"
    payload = b""
    if Raw in pkt:
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            payload = b""
    try:
        ts = float(pkt.time)
    except Exception:
        ts = 0.0
    return proto, src, dst, sport, dport, payload, ts


def _is_local(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _direction_matches(want, src, dst):
    if want == "any":
        return True
    src_local = _is_local(src)
    dst_local = _is_local(dst)
    if want == "outbound":
        return src_local and not dst_local
    if want == "inbound":
        return not src_local and dst_local
    if want == "lateral":
        return src_local and dst_local
    return True


def _packet_matches(rule, fivetuple):
    m = rule["match"]
    proto, src, dst, sport, dport, payload, _ts = fivetuple

    want_proto = m.get("protocol", "any")
    if want_proto != "any" and want_proto != proto:
        return False
    if m.get("src_port") is not None and m["src_port"] != sport:
        return False
    if m.get("dst_port") is not None and m["dst_port"] != dport:
        return False
    if "_src_net" in m:
        try:
            if ipaddress.ip_address(src) not in m["_src_net"]:
                return False
        except ValueError:
            return False
    if "_dst_net" in m:
        try:
            if ipaddress.ip_address(dst) not in m["_dst_net"]:
                return False
        except ValueError:
            return False
    if not _direction_matches(m.get("direction", "any"), src, dst):
        return False
    if "_payload_contains_b" in m:
        if m["_payload_contains_b"] not in payload:
            return False
    if "_payload_re" in m:
        if not m["_payload_re"].search(payload):
            return False
    return True


def _group_key(rule, fivetuple):
    proto, src, dst, sport, dport, _payload, _ts = fivetuple
    k = rule["aggregate"]["key"]
    if k == "src":
        return src
    if k == "dst":
        return dst
    if k == "src+dst":
        return f"{src}->{dst}"
    if k == "src+dst_port":
        return f"{src}:{dport}"
    return f"{src}->{dst}:{dport}"


# ============================================================
#  Public entrypoint
# ============================================================

def evaluate_user_rules(packets, settings=None, rules_dir=None):
    """
    Walk packets once per loaded rule and emit alerts.

    Returns a list of alert dicts ready to be merged into results['alerts'].
    Empty list if no rules loaded or no matches.
    """
    rules = load_rules(rules_dir or DEFAULT_RULES_DIR)
    if not rules:
        return []
    alerts = []
    now_iso = datetime.now().isoformat()

    # Pre-compute 5-tuples once and reuse for every rule. For huge captures
    # this trades memory for CPU; on a 300MB file it's < 100MB additional.
    five_tuples = []
    for pkt in packets:
        ft = _packet_5tuple(pkt)
        if ft is None:
            continue
        five_tuples.append(ft)

    for rule in rules:
        # group_key -> {count, first_ts, last_ts, sample_src, sample_dst, sample_dport}
        groups = defaultdict(lambda: {
            "count": 0, "first_ts": None, "last_ts": None,
            "src": None, "dst": None, "dport": None,
        })
        for ft in five_tuples:
            if not _packet_matches(rule, ft):
                continue
            key = _group_key(rule, ft)
            g = groups[key]
            g["count"] += 1
            if g["first_ts"] is None:
                g["first_ts"] = ft[6]
            g["last_ts"] = ft[6]
            if g["src"] is None:
                g["src"] = ft[1]
                g["dst"] = ft[2]
                g["dport"] = ft[4]

        agg = rule["aggregate"]
        min_count = int(agg.get("min_count", 1))
        window = agg.get("window_seconds")

        for group_id, g in groups.items():
            if g["count"] < min_count:
                continue
            if window is not None and g["first_ts"] and g["last_ts"]:
                span = g["last_ts"] - g["first_ts"]
                if span > window:
                    continue

            tmpl_ctx = {
                "src": g["src"], "dst": g["dst"], "dst_port": g["dport"],
                "count": g["count"], "rule_id": rule["id"],
                "rule_name": rule.get("name", rule["id"]),
            }
            alert_template = rule.get("alert") or {}
            try:
                title = (alert_template.get("title") or rule.get("name") or rule["id"]).format(**tmpl_ctx)
            except (KeyError, IndexError):
                title = alert_template.get("title") or rule.get("name") or rule["id"]
            try:
                desc = (alert_template.get("description") or
                        f"Rule {rule['id']} matched {g['count']} time(s)").format(**tmpl_ctx)
            except (KeyError, IndexError):
                desc = f"Rule {rule['id']} matched {g['count']} time(s)"

            alert = {
                "severity": rule.get("severity", "medium"),
                "category": rule.get("category", "user-rule"),
                "title": title,
                "description": desc,
                "ip": g["src"],
                "details": {
                    "rule_id": rule["id"],
                    "src": g["src"],
                    "dst": g["dst"],
                    "dst_port": g["dport"],
                    "match_count": g["count"],
                    "first_seen": g["first_ts"],
                    "last_seen": g["last_ts"],
                },
                "recommendation": alert_template.get("recommendation",
                                                     f"User rule {rule['id']} matched."),
                "timestamp": now_iso,
            }
            mitre = alert_template.get("mitre")
            if mitre:
                alert["mitre_attack"] = mitre
            alerts.append(alert)

    return alerts
