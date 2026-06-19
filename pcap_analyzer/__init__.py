"""
PCAP Network Analyzer package.

Public API: PCAPAnalyzer — entry point used by app.py and celery_app.py.

This package was split from a single-file pcap_analyzer.py module. To avoid
breaking external imports, the historical name is preserved here. Internal
organization is incremental:

    pcap_analyzer/
        __init__.py        — re-exports PCAPAnalyzer
        pkt_view.py        — compact packet representation
        constants.py       — detection constants (ports, signatures, patterns)
        detectors/         — streaming detectors (one alert family per class)
        aggregators/       — streaming aggregators (results dict population)
        _analyzer.py       — orchestrator (PCAPAnalyzer)

`_core.py` is the legacy single-file implementation; everything still lives
there during the transitional period and gets re-exported here. As pieces are
extracted they will be imported from their new homes instead.
"""

from ._core import PCAPAnalyzer

__all__ = ["PCAPAnalyzer"]
