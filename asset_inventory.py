"""
Passive asset inventory: build a per-MAC fingerprint of every device seen
on the wire, without sending a single probe.

Three signal sources, in increasing order of specificity:

  1. **TTL initial value** (from any IP packet sent by the host). Real OSes
     use a narrow set of initial TTLs; we round the observed TTL up to the
     nearest known starting value (32, 64, 128, 255) and infer the family.

  2. **DHCP option 60 (vendor class identifier)** — in plaintext, often
     literally "MSFT 5.0", "android-dhcp-13", "dhcpcd-9.4.1", "udhcp 1.x".
     When present this is high-confidence.

  3. **DHCP option 55 (parameter request list)** — the order/contents of
     this list is OS-specific (Windows asks for a different mix than Linux
     or macOS). We fingerprint by hashing the list.

Persistence happens via database.record_assets, which upserts per MAC and
updates last_seen_at + scan_count. The PCAPAnalyzer surfaces what it
extracted in `results['assets']`.
"""
import hashlib
from collections import defaultdict


# ---------------------------------------------------------
# TTL families. Real OSes choose initial TTLs from a narrow set.
# Anything observed at or below `start` is assumed to have started at
# `start`, since hops only decrement.
# ---------------------------------------------------------
_TTL_FAMILIES = [
    (32,  "Older Windows / IoT (TTL=32)"),
    (64,  "Linux / macOS / Android / *BSD (TTL=64)"),
    (128, "Modern Windows (TTL=128)"),
    (255, "Solaris / network device (TTL=255)"),
]


def _classify_ttl(observed):
    """Return (initial, family_label) given an observed TTL byte."""
    if observed is None or observed <= 0:
        return None, None
    for start, label in _TTL_FAMILIES:
        if observed <= start:
            return start, label
    return None, None


# ---------------------------------------------------------
# DHCP option 60 — vendor class identifier. Vendors ship literal strings.
# Match prefixes (case-insensitive) and map to a canonical OS guess.
# ---------------------------------------------------------
_DHCP_VENDOR_PREFIXES = (
    ("msft",          "Windows"),
    ("microsoft",     "Windows"),
    ("android",       "Android"),
    ("dhcpcd",        "Linux"),
    ("udhcp",         "Linux/Embedded"),
    ("isc-dhclient",  "Linux"),
    ("debian",        "Linux (Debian)"),
    ("ubuntu",        "Linux (Ubuntu)"),
    ("apple",         "macOS / iOS"),
    ("ios",           "iOS"),
    ("playstation",   "PlayStation"),
    ("xbox",          "Xbox"),
    ("nintendo",      "Nintendo"),
    ("roku",          "Roku"),
    ("amazon",        "Amazon device"),
    ("kindle",        "Kindle"),
    ("samsung",       "Samsung device"),
    ("hp ",           "HP printer / device"),
    ("brother",       "Brother printer"),
    ("epson",         "Epson printer"),
    ("canon",         "Canon printer"),
    ("juniper",       "Juniper network device"),
    ("cisco",         "Cisco network device"),
    ("aruba",         "Aruba network device"),
    ("ubnt",          "Ubiquiti device"),
    ("mikrotik",      "MikroTik device"),
    ("vmware",        "VMware (virtual)"),
    ("kvm",           "KVM guest (virtual)"),
    ("xen",           "Xen guest (virtual)"),
)


def _classify_vendor_class(vendor):
    if not vendor:
        return None
    v = vendor.strip().lower()
    for prefix, label in _DHCP_VENDOR_PREFIXES:
        if v.startswith(prefix):
            return label
    return None


# ---------------------------------------------------------
# Public API
# ---------------------------------------------------------

def extract_assets(packets, results):
    """
    Walk the packet list, build a per-MAC asset record, and stash the
    result in results['assets']. Format:

        {
          "<mac>": {
            "mac": str,
            "ip_addresses": [ip, ...],
            "os_guess": str | None,
            "ttl_initial": int | None,
            "ttl_observed": int | None,
            "dhcp_vendor": str | None,
            "dhcp_hostname": str | None,
            "dhcp_param_list_hash": str | None,   # md5 of option 55
            "dhcp_param_list": [int, ...] | None
          }
        }
    """
    if results is None:
        results = {}

    # Lazy scapy import keeps unit-test friendliness
    from scapy.all import IP, TCP, Ether
    try:
        from scapy.layers.dhcp import DHCP
    except Exception:
        DHCP = None  # type: ignore

    # mac -> raw observations
    obs = defaultdict(lambda: {
        "ips": set(),
        "ttl_min": None,                 # smallest TTL observed = closest hop count
        "ttl_initial_candidates": set(), # set of inferred initial values
        "dhcp_vendor": None,
        "dhcp_hostname": None,
        "dhcp_param_list": None,
    })

    for pkt in packets:
        if Ether not in pkt:
            continue
        src_mac = (pkt[Ether].src or "").lower()
        if not src_mac or src_mac == "ff:ff:ff:ff:ff:ff" or src_mac == "00:00:00:00:00:00":
            continue
        # Skip multicast (low bit of first octet set)
        try:
            if int(src_mac.split(":", 1)[0], 16) & 0x01:
                continue
        except ValueError:
            continue

        rec = obs[src_mac]

        if IP in pkt:
            rec["ips"].add(pkt[IP].src)
            ttl = int(pkt[IP].ttl)
            if rec["ttl_min"] is None or ttl > rec["ttl_min"]:
                # Track the *largest* TTL we saw (closest to source's initial value)
                rec["ttl_min"] = ttl
            initial, _ = _classify_ttl(ttl)
            if initial:
                rec["ttl_initial_candidates"].add(initial)

        # DHCP option 55 / 60 / 12 (hostname)
        if DHCP is not None and DHCP in pkt:
            for opt in pkt[DHCP].options:
                if not isinstance(opt, tuple) or len(opt) < 2:
                    continue
                name, val = opt[0], opt[1]
                if name == "vendor_class_id":
                    try:
                        rec["dhcp_vendor"] = val.decode("utf-8", errors="ignore") if isinstance(val, (bytes, bytearray)) else str(val)
                    except Exception:
                        pass
                elif name == "hostname":
                    try:
                        rec["dhcp_hostname"] = val.decode("utf-8", errors="ignore") if isinstance(val, (bytes, bytearray)) else str(val)
                    except Exception:
                        pass
                elif name == "param_req_list":
                    # In scapy this can be a list[int] or bytes
                    if isinstance(val, (bytes, bytearray)):
                        rec["dhcp_param_list"] = list(val)
                    elif isinstance(val, (list, tuple)):
                        rec["dhcp_param_list"] = [int(x) for x in val]

    # Resolve fingerprints
    assets = {}
    for mac, rec in obs.items():
        ttl_observed = rec["ttl_min"]
        ttl_initial, ttl_label = (None, None)
        if rec["ttl_initial_candidates"]:
            # Pick the highest plausible initial TTL the host might have used
            # (e.g., observed 117 -> 128, not 32)
            ttl_initial = max(rec["ttl_initial_candidates"])
            _, ttl_label = _classify_ttl(ttl_initial)

        os_guess = _classify_vendor_class(rec["dhcp_vendor"]) or ttl_label

        param_hash = None
        if rec["dhcp_param_list"]:
            digest = hashlib.md5(bytes(rec["dhcp_param_list"])).hexdigest()
            # Keep first 16 hex chars — enough to fingerprint, short to store/index
            param_hash = digest[:16]

        assets[mac] = {
            "mac": mac,
            "ip_addresses": sorted(rec["ips"]),
            "os_guess": os_guess,
            "ttl_initial": ttl_initial,
            "ttl_observed": ttl_observed,
            "dhcp_vendor": rec["dhcp_vendor"],
            "dhcp_hostname": rec["dhcp_hostname"],
            "dhcp_param_list_hash": param_hash,
            "dhcp_param_list": rec["dhcp_param_list"],
        }

    results["assets"] = assets
    return assets
