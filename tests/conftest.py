"""Shared pytest fixtures and helpers for the PCAP analyzer test suite.

The detection engine (``PCAPAnalyzer``) is fully testable in isolation: it
takes a file path, runs a single streaming pass plus post-detectors, and
returns a ``results`` dict. No database, Celery, Redis or Flask is involved.

Fixture PCAPs are built programmatically with scapy (see ``build_pcap``) rather
than checked in as binary blobs, so each test reads like a spec for the traffic
it exercises and stays diffable.

Network-backed post-detectors (threat-intel feeds, JA3 SSLBL, CISA KEV) degrade
to a silent no-op when ``requests`` is missing or no API key is configured, so
the suite never reaches the network.
"""

import os
import sys

import pytest

# Ensure the project root is importable when pytest is invoked from anywhere.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from scapy.all import wrpcap  # noqa: E402

from pcap_analyzer import PCAPAnalyzer  # noqa: E402


# RFC1918 addresses are treated as "local" by the engine. The "external"
# addresses must be genuinely public: Python 3.12+ classifies the TEST-NET
# documentation ranges (203.0.113/24, 198.51.100/24) as is_private=True, so
# those would be mis-detected as local. Use real public IPs instead.
LOCAL_IP = "10.0.0.5"
LOCAL_IP_2 = "10.0.0.6"
EXTERNAL_IP = "8.8.8.8"
EXTERNAL_IP_2 = "1.1.1.1"


def _stamp(packets, start=1_000_000.0, step=0.01):
    """Assign monotonically increasing timestamps when a packet has none.

    Detectors that use sliding time windows read ``pkt.time``; scapy defaults
    it to capture-time, so tests that care about timing set it explicitly and
    this only fills the gaps.
    """
    t = start
    for pkt in packets:
        if not getattr(pkt, "time", None):
            pkt.time = t
        t += step
    return packets


def build_pcap(packets, path):
    """Write ``packets`` to ``path`` (a .pcap) and return the path as str."""
    _stamp(packets)
    wrpcap(str(path), packets)
    return str(path)


@pytest.fixture
def analyze(tmp_path):
    """Return ``run(packets, settings=None)`` -> results dict.

    Builds a temporary PCAP from the scapy packet list, runs the full
    analysis pipeline, and returns ``analyzer.results``.
    """

    counter = {"n": 0}

    def run(packets, settings=None):
        counter["n"] += 1
        pcap = tmp_path / f"fixture_{counter['n']}.pcap"
        build_pcap(packets, pcap)
        analyzer = PCAPAnalyzer(str(pcap), settings or {})
        return analyzer.analyze()

    return run


# --------------------------------------------------------------------------
# Assertion helpers
# --------------------------------------------------------------------------

def alerts(results):
    return results.get("alerts", [])


def titles(results):
    return [a.get("title", "") for a in alerts(results)]


def categories(results):
    return {a.get("category") for a in alerts(results)}


def find_alerts(results, *, title=None, category=None):
    """Return alerts matching a title substring and/or exact category."""
    out = []
    for a in alerts(results):
        if title is not None and title.lower() not in a.get("title", "").lower():
            continue
        if category is not None and a.get("category") != category:
            continue
        out.append(a)
    return out


def has_alert(results, *, title=None, category=None):
    return bool(find_alerts(results, title=title, category=category))
