"""
PCAP Network Analyzer — orchestrator.

PCAPAnalyzer wires the single-pass pipeline: open the capture with PcapReader,
project each packet into a PktView, fan it out to streaming detectors and
streaming aggregators, then run the post-aggregator detectors and a handful of
post-processing helpers. All heavy lifting lives in sibling modules:

    pcap_analyzer.pkt_view      — compact packet representation
    pcap_analyzer.constants     — detection constants (ports, signatures, …)
    pcap_analyzer.tls           — ClientHello / ServerHello / Certificate parsers
    pcap_analyzer.aggregators   — streaming aggregators (populate results dict)
    pcap_analyzer.detectors     — streaming detectors (per-packet)
    pcap_analyzer.detectors.post — post-aggregator detectors (run after load)

This module retains only:
  - the analyze() entry point and progress plumbing,
  - five helpers reused by detectors (_calculate_entropy, _is_local_ip,
    _dga_score, _extract_dns_label, _binned_autocorrelation_peak),
  - post-processing steps (_classify_protocol_risks, _count_alerts_per_ip,
    _carve_files, _collect_observed_artifacts).

The legacy single-pass `_detect_*` / `_extract_*` methods were deleted once
their streaming or post equivalents covered them.
"""

import math
import os
import time
from collections import Counter
import ipaddress
from datetime import datetime

from scapy.all import PcapReader

from . import constants as _constants
from .pkt_view import (  # noqa: F401
    PktView,
    extract_pkt_view as _extract_pkt_view,
    _IPLayerView,
    _TCPLayerView,
    _UDPLayerView,
    _ICMPLayerView,
    _ARPLayerView,
    _EtherLayerView,
    _DNSAnswerView,
    _DNSLayerView,
    _DNSQRLayerView,
    _RawLayerView,
    _DHCPLayerView,
)
from .detectors import (  # noqa: F401
    StreamingDetector,
    STREAMING_DETECTORS,
    STREAMING_DETECTOR_NAMES,
)
from .detectors.post import POST_DETECTORS
from .aggregators import (  # noqa: F401
    StreamingAggregator,
    STREAMING_AGGREGATORS,
    STREAMING_AGGREGATOR_NAMES,
    STREAMING_PRECOMPUTE_NAMES,
)


# Hard cap on packets loaded into memory; large captures would otherwise OOM
# the worker. Override via env or PCAPAnalyzer settings.
DEFAULT_MAX_PACKETS = int(os.environ.get('PCAP_MAX_PACKETS', '5000000'))

# B.9: per-severity baseline confidence used when a detector doesn't set
# its own. Confidence is a 0-100 measure of evidence strength, ORTHOGONAL
# to severity (which describes impact-if-real). Critical/high alerts ship
# with higher baseline because the conditions that trigger them are
# typically narrow; medium/low are broader.
_CONFIDENCE_DEFAULT_BY_SEV = {
    'critical': 75,
    'high':     65,
    'medium':   55,
    'low':      45,
    'info':     40,
}


class PCAPAnalyzer:
    """Analyzes a single PCAP/PCAPNG file in one streaming pass."""

    # Detection constants bound as class attributes so `self.SUSPICIOUS_PORTS`
    # / `PCAPAnalyzer.JA3_GREASE` etc. continue to resolve unchanged.
    SUSPICIOUS_PORTS = _constants.SUSPICIOUS_PORTS
    SMB_PORTS = _constants.SMB_PORTS
    PROTOCOL_RISK = _constants.PROTOCOL_RISK
    SUSPICIOUS_TLDS = _constants.SUSPICIOUS_TLDS
    KNOWN_PUBLIC_DNS_RESOLVERS = _constants.KNOWN_PUBLIC_DNS_RESOLVERS
    DOH_HOSTS = _constants.DOH_HOSTS
    DOH_PROVIDER_IPS = _constants.DOH_PROVIDER_IPS
    KNOWN_DOH_JA3 = _constants.KNOWN_DOH_JA3
    ENGLISH_COMMON_BIGRAMS = _constants.ENGLISH_COMMON_BIGRAMS
    ENGLISH_BIGRAM_FREQ = _constants.ENGLISH_BIGRAM_FREQ
    ENGLISH_BIGRAM_EPSILON = _constants.ENGLISH_BIGRAM_EPSILON
    VOWELS = _constants.VOWELS
    TLS_VERSIONS = _constants.TLS_VERSIONS
    OLD_TLS_VERSIONS = _constants.OLD_TLS_VERSIONS
    JA3_GREASE = _constants.JA3_GREASE
    KNOWN_MALICIOUS_JA3 = _constants.KNOWN_MALICIOUS_JA3
    HTTP_METHODS = _constants.HTTP_METHODS
    SCANNER_USER_AGENTS = _constants.SCANNER_USER_AGENTS
    EXPLOIT_PATHS_HIGH = _constants.EXPLOIT_PATHS_HIGH
    EXPLOIT_PATHS_MEDIUM = _constants.EXPLOIT_PATHS_MEDIUM
    FILE_SHARE_HOSTS = _constants.FILE_SHARE_HOSTS
    LATERAL_PORTS = _constants.LATERAL_PORTS
    INJECTION_PATTERNS = _constants.INJECTION_PATTERNS
    COBALT_STRIKE_CHECKSUMS = _constants.COBALT_STRIKE_CHECKSUMS
    COBALT_STRIKE_DEFAULT_URIS = _constants.COBALT_STRIKE_DEFAULT_URIS
    COBALT_STRIKE_USER_AGENTS = _constants.COBALT_STRIKE_USER_AGENTS
    COBALT_STRIKE_SERVER_HEADERS = _constants.COBALT_STRIKE_SERVER_HEADERS
    COBALT_STRIKE_COOKIE_HINTS = _constants.COBALT_STRIKE_COOKIE_HINTS

    def __init__(self, filepath, settings=None, progress_callback=None):
        """
        Args:
            filepath: caminho do .pcap/.pcapng
            settings: dict de configurações (thresholds, etc.)
            progress_callback: callable(progress:int, message:str, **meta) ou None.
                Recebe atualizações de progresso durante analyze(). `meta`
                inclui phase, packet_count, elapsed_seconds, file_size.
        """
        self.filepath = filepath
        self.settings = settings or {}
        self.progress_callback = progress_callback
        self.packets = None
        self._tls_info = None
        self._http_info = None
        self._ssh_info = None
        self._start_time = None
        self._packet_count = 0
        self._file_size = 0
        self._current_phase = 'idle'
        self._last_emit_ts = 0.0
        self.results = {
            "summary": {},
            "ips": [],
            "protocols": [],
            "alerts": [],
            "traffic_timeline": [],
            "mac_ip_mapping": {},
            "ip_mac_mapping": {},
            "protocol_ips": {},
            "ip_protocols": [],
            "carved_files": [],
        }

    def _emit_progress(self, progress, message, phase=None, force=False,
                       **extra):
        """Throttled progress callback dispatch (~5 updates/s).

        force=True bypasses throttling for phase changes / completion.
        """
        if not self.progress_callback:
            return
        now = time.monotonic()
        if not force and (now - self._last_emit_ts) < 0.2:
            return
        self._last_emit_ts = now
        if phase is not None:
            self._current_phase = phase
        elapsed = (now - self._start_time) if self._start_time else 0.0
        meta = {
            'phase': self._current_phase,
            'packet_count': self._packet_count,
            'elapsed_seconds': round(elapsed, 1),
            'file_size': self._file_size,
        }
        meta.update(extra)
        try:
            self.progress_callback(int(progress), message, **meta)
        except Exception as cb_err:
            print(f"[pcap_analyzer] progress callback error: {cb_err}")

    @staticmethod
    def _reader_position(reader):
        """Best-effort underlying-file byte position. Used to derive load %."""
        try:
            f = getattr(reader, 'f', None)
            if f is None:
                return 0
            inner = getattr(f, 'fileobj', None) or f
            return inner.tell()
        except Exception:
            return 0

    def analyze(self):
        """Run the full pipeline. Returns self.results."""
        try:
            self._start_time = time.monotonic()
            try:
                self._file_size = os.path.getsize(self.filepath)
            except OSError:
                self._file_size = 0

            max_packets = int(
                (self.settings.get('thresholds') or {}).get(
                    'max_packets', DEFAULT_MAX_PACKETS,
                )
            )
            print(f"Loading packets from {self.filepath} "
                  f"(size={self._file_size} bytes, cap={max_packets})...")
            self._emit_progress(0, 'Loading packets...', phase='loading',
                                force=True)

            # True streaming: no full packet list in memory. Every PktView is
            # fed into streaming detectors + aggregators and dropped.
            self.packets = None
            loaded_count = 0
            truncated = False
            self._streaming_detectors = [
                cls(self) for cls in STREAMING_DETECTORS
            ]
            self._streaming_aggregators = [
                cls(self) for cls in STREAMING_AGGREGATORS
            ]
            with PcapReader(self.filepath) as reader:
                for i, pkt in enumerate(reader):
                    if i >= max_packets:
                        truncated = True
                        break
                    try:
                        view = _extract_pkt_view(pkt)
                    except Exception as ex:
                        print(f"[pcap_analyzer] view extract error pkt#{i}: "
                              f"{ex}")
                        continue
                    for det in self._streaming_detectors:
                        try:
                            det.update(view)
                        except Exception as ex:
                            print(f"[pcap_analyzer] streaming "
                                  f"{det.name} update error pkt#{i}: {ex}")
                    for agg in self._streaming_aggregators:
                        try:
                            agg.update(view)
                        except Exception as ex:
                            print(f"[pcap_analyzer] aggregator "
                                  f"{agg.name} update error pkt#{i}: {ex}")
                    loaded_count = i + 1
                    self._packet_count = loaded_count
                    if loaded_count % 5000 == 0:
                        pos = self._reader_position(reader)
                        if self._file_size > 0 and pos > 0:
                            load_frac = min(1.0, pos / self._file_size)
                            global_pct = int(load_frac * 40)
                        else:
                            global_pct = 0
                        self._emit_progress(
                            global_pct,
                            f'Loading packets... {loaded_count:,}',
                            bytes_read=pos,
                        )
            self._packet_count = loaded_count
            self._truncated = truncated
            if truncated:
                print(
                    f"WARNING: capture exceeded {max_packets} packets — "
                    f"analysis truncated. Increase PCAP_MAX_PACKETS or "
                    f"thresholds.max_packets to raise the cap."
                )
            print(f"Loaded {loaded_count} packets"
                  + (' (truncated)' if truncated else ''))
            self._emit_progress(40, f'Loaded {loaded_count:,} packets',
                                phase='loaded', force=True)

            self._emit_progress(45, 'Finalizing aggregators...',
                                phase='aggregators_finalize', force=True)
            for agg in self._streaming_aggregators:
                try:
                    agg.finalize(self.results)
                except Exception as ex:
                    print(f"[pcap_analyzer] aggregator "
                          f"{agg.name} finalize error: {ex}")

            self._emit_progress(55, 'Running security detections...',
                                phase='detections', force=True)
            self._run_detections()

            self._emit_progress(90, 'Classifying protocol risks...',
                                phase='classify', force=True)
            self._classify_protocol_risks()

            # traffic_timeline is populated by TimelineAggregator during load.

            self._emit_progress(94, 'Counting alerts per IP...',
                                phase='count_alerts', force=True)
            self._count_alerts_per_ip()
            self._compute_host_risk_scores()

            self._emit_progress(96, 'Collecting observed artifacts...',
                                phase='artifacts', force=True)
            self._collect_observed_artifacts()

            # Asset inventory is populated by AssetInventoryAggregator.
            self._emit_progress(98, 'Asset inventory (streaming)',
                                phase='assets', force=True)

            self._emit_progress(99, 'Carving files from HTTP flows...',
                                phase='carving', force=True)
            try:
                self._carve_files()
            except Exception as e:
                print(f"[pcap_analyzer] file carving failed: {e}")
                self.results['carved_files'] = []

            self._emit_progress(100, 'Analysis complete', phase='done',
                                force=True)
            return self.results

        except Exception as e:
            print(f"Error analyzing PCAP: {e}")
            raise

    # ------------------------------------------------------------------ run

    def _run_detections(self):
        """Finalize streaming detectors and run post-aggregator detectors."""
        alerts = []

        # Streaming detectors collected per-packet state during load. Finalize
        # turns that state into alerts.
        for det in getattr(self, '_streaming_detectors', None) or []:
            try:
                alerts.extend(det.finalize() or [])
            except Exception as e:
                print(f"[pcap_analyzer] streaming "
                      f"{det.name} finalize failed: {e}")

        # Expose the in-flight alerts list so cross-cutting detectors (KEV
        # enricher) can inspect and mutate alerts emitted earlier in the
        # pipeline. Streaming alerts are already collected above; the alias
        # is updated as POST_DETECTORS append their own findings.
        self._pending_alerts = alerts

        # Post-aggregator detectors run over precomputed _tls_info /
        # _http_info / ip_mac_mapping state — no per-packet loop.
        n_post = max(1, len(POST_DETECTORS))
        for idx, det_cls in enumerate(POST_DETECTORS):
            pct = 60 + int((idx / n_post) * 25)
            det = det_cls(self)
            self._emit_progress(pct, f'Detection: {det.name}',
                                phase=f'detect:{det.name}', force=True)
            try:
                alerts.extend(det.run() or [])
            except Exception as e:
                print(f"[pcap_analyzer] post {det.name} failed: {e}")

        # Statistical / ML alerts emitted by FlowAnomalyAggregator.
        self._emit_progress(86, 'Detection: flow_anomaly (streaming)',
                            phase='detect:flow_anomaly', force=True)
        flow_alerts = getattr(self, '_flow_anomaly_alerts', None)
        if flow_alerts:
            alerts.extend(flow_alerts)

        # User-defined rule matches emitted by UserRulesAggregator.
        self._emit_progress(88, 'Detection: user_rules (streaming)',
                            phase='detect:user_rules', force=True)
        ur_alerts = getattr(self, '_user_rules_alerts', None)
        if ur_alerts:
            alerts.extend(ur_alerts)

        # Timestamp policy (B.8 — 2026-05-19):
        # 1. Se o detector já cravou um `timestamp` ISO, respeita.
        # 2. Senão, se há `details.first_ts` (epoch float, em segundos),
        #    deriva o timestamp ISO a partir dele — é o tempo REAL do
        #    primeiro pacote que disparou o alerta, e habilita kill-chain
        #    cronológico em vez de "tempo da análise".
        # 3. Também levanta `first_ts`/`last_ts` para o topo do alerta
        #    (em ISO) para que correlation.py e a UI ordenem cronologica-
        #    mente sem precisar peneirar details.
        # 4. Fallback final: datetime.now() — usado por detectores que não
        #    têm vínculo com pacote específico (ex.: behavioral baseline).
        analysis_iso = datetime.now().isoformat()
        for alert in alerts:
            details = alert.get('details') or {}
            ft = details.get('first_ts')
            lt = details.get('last_ts')

            def _to_iso(ts_value):
                try:
                    ts_float = float(ts_value)
                except (TypeError, ValueError):
                    return None
                if ts_float <= 0:
                    return None
                try:
                    return datetime.fromtimestamp(ts_float).isoformat()
                except (OSError, OverflowError, ValueError):
                    return None

            first_iso = _to_iso(ft)
            last_iso = _to_iso(lt)
            if first_iso and 'first_ts' not in alert:
                alert['first_ts'] = first_iso
            if last_iso and 'last_ts' not in alert:
                alert['last_ts'] = last_iso
            if 'timestamp' not in alert:
                alert['timestamp'] = first_iso or analysis_iso

            # B.9 confidence default. Detectors with strong evidence set
            # this inline (beaconing, DGA, ...); for everything else we
            # derive a baseline from severity so the field is always
            # present and consumers (UI, triage) can sort/filter by it
            # without special-casing.
            if 'confidence' not in alert:
                sev = alert.get('severity', 'medium')
                alert['confidence'] = _CONFIDENCE_DEFAULT_BY_SEV.get(sev, 50)

        try:
            from mitre_attack import annotate_alerts
            annotate_alerts(alerts)
        except Exception as e:
            print(f"[pcap_analyzer] MITRE annotation failed: {e}")

        self.results["alerts"] = alerts

        # Asset-role-based suppression: roda DEPOIS de tudo (precisa de
        # results['ip_protocols'] e results['assets'] já populados pelos
        # aggregators) e rebaixa severity de alertas que são esperados
        # para o papel inferido do host. Não remove alertas — só anota
        # `suppressed_reason` e `severity_original`.
        try:
            from host_roles import apply_role_suppression
            apply_role_suppression(self.results)
        except Exception as e:
            print(f"[pcap_analyzer] role suppression failed: {e}")

        # SOC IP tagging: annotate alerts whose src/dst falls under a
        # registered SOC range with `soc_match`. Pure decoration — does
        # not change severity, suppression, or triage state. The analyst
        # uses the badge as a hint to bulk-mark false positives, which
        # then feed the FP classifier with clean labels.
        try:
            from soc import tag_soc_alerts
            tagged = tag_soc_alerts(self.results, self.settings)
            if tagged:
                print(f"[pcap_analyzer] SOC tagged {tagged} alert(s)")
        except Exception as e:
            print(f"[pcap_analyzer] SOC tagging failed: {e}")

        # Cross-detector deduplication: collapse alerts with the same
        # (category, title, src_ip, dst_ip) into a single entry. Keeps
        # the highest severity/confidence + concatenates samples (cap 10).
        try:
            self._dedupe_alerts()
        except Exception as e:
            print(f"[pcap_analyzer] dedup failed: {e}")

    # ------------------------------------------------------------ helpers

    # Severity ranking used by the dedup pass to keep the worst entry.
    _SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

    def _dedupe_alerts(self):
        """Collapse alerts with identical (category, title, src_ip, dst_ip).

        - Preserves the worst-severity / highest-confidence representative.
        - Sums `count` (defaults to 1 each) so the analyst sees how often the
          tuple fired.
        - Concatenates `samples` up to a cap of 10 (deduped by repr) so we
          don't lose evidence diversity.
        - Skips alerts that already explicitly set `dedupe=False` (rare —
          for cases where each instance is forensically distinct).

        Runs after annotate_alerts / role_suppression / soc tagging so the
        merged entry inherits MITRE, suppression markers, and the SOC badge
        from whichever sibling has them. Bumps `merged_count` for visibility.
        """
        alerts = list(self.results.get('alerts') or [])
        if not alerts:
            return

        merged = {}  # key -> alert dict
        order = []   # stable order of keys as first seen
        for a in alerts:
            if a.get('dedupe') is False:
                # Unique tag — keep as-is under a unique key.
                k = ('__nodedup__', id(a))
            else:
                details = a.get('details') or {}
                k = (
                    a.get('category') or '',
                    a.get('title') or '',
                    details.get('src_ip') or '',
                    details.get('dst_ip') or '',
                )
            existing = merged.get(k)
            if existing is None:
                a.setdefault('count', 1)
                merged[k] = a
                order.append(k)
                continue

            # Merge into `existing`.
            inc = a.get('count') or 1
            existing['count'] = (existing.get('count') or 1) + inc
            existing['merged_count'] = existing.get('merged_count', 1) + 1

            # Keep worst severity.
            cur_rank = self._SEV_RANK.get(existing.get('severity'), 0)
            new_rank = self._SEV_RANK.get(a.get('severity'), 0)
            if new_rank > cur_rank:
                existing['severity'] = a.get('severity')

            # Keep highest confidence.
            if (a.get('confidence') or 0) > (existing.get('confidence') or 0):
                existing['confidence'] = a.get('confidence')

            # Merge samples (cap 10, dedupe by repr).
            ex_samples = existing.get('samples') or []
            new_samples = a.get('samples') or []
            if new_samples:
                seen = {repr(s) for s in ex_samples}
                for s in new_samples:
                    if len(ex_samples) >= 10:
                        break
                    r = repr(s)
                    if r not in seen:
                        ex_samples.append(s)
                        seen.add(r)
                existing['samples'] = ex_samples

            # Inherit SOC badge / MITRE / suppression if missing.
            if not existing.get('soc_match') and a.get('soc_match'):
                existing['soc_match'] = a['soc_match']
            if not existing.get('mitre_attack') and a.get('mitre_attack'):
                existing['mitre_attack'] = a['mitre_attack']
            if not existing.get('suppressed_reason') and a.get('suppressed_reason'):
                existing['suppressed_reason'] = a['suppressed_reason']

        self.results['alerts'] = [merged[k] for k in order]

    @classmethod
    def _dga_score(cls, label):
        """Heurística DGA combinando entropia, comprimento, razão de consoantes,
        razão de dígitos e plausibilidade de bigramas em inglês. Retorna float
        entre 0.0 e 1.0 (>=0.7 = suspeito, >=0.85 = muito suspeito)."""
        if not label or len(label) < 6:
            return 0.0

        label = label.lower()
        score = 0.0

        entropy = cls._calculate_entropy(label)
        if entropy >= 4.0:
            score += 0.40
        elif entropy >= 3.5:
            score += 0.25
        elif entropy >= 3.0:
            score += 0.10

        if len(label) >= 16:
            score += 0.15
        elif len(label) >= 12:
            score += 0.10

        letters = [c for c in label if c.isalpha()]
        if letters:
            consonants = sum(1 for c in letters if c not in cls.VOWELS)
            consonant_ratio = consonants / len(letters)
            if consonant_ratio > 0.75:
                score += 0.15
            elif consonant_ratio > 0.65:
                score += 0.08

        digits = sum(1 for c in label if c.isdigit())
        digit_ratio = digits / len(label)
        if digit_ratio > 0.30:
            score += 0.10
        elif digit_ratio > 0.15:
            score += 0.05

        bigrams = [label[i:i + 2] for i in range(len(label) - 1)
                   if label[i].isalpha() and label[i + 1].isalpha()]
        if bigrams:
            # Average log10-probability of bigrams in the label against an
            # English frequency table. Real domains land near -2.0 (top
            # bigrams ~10^-1.5); algorithmic strings stay well below -3
            # because most pairs are absent and get the smoothed epsilon.
            import math
            eps = cls.ENGLISH_BIGRAM_EPSILON
            log_sum = 0.0
            for bg in bigrams:
                p = cls.ENGLISH_BIGRAM_FREQ.get(bg, eps)
                log_sum += math.log10(p)
            avg_loglik = log_sum / len(bigrams)
            if avg_loglik < -3.6:
                score += 0.30
            elif avg_loglik < -3.0:
                score += 0.20
            elif avg_loglik < -2.5:
                score += 0.10

        return min(score, 1.0)

    @staticmethod
    def _extract_dns_label(query):
        """Extrai o label efetivo (segundo nível), tratando ccTLD compostos."""
        parts = query.split('.')
        if len(parts) < 2:
            return None
        if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
            return parts[-3]
        return parts[-2]

    @staticmethod
    def _binned_autocorrelation_peak(timestamps, mean_interval):
        """
        Detect periodicity in arrival timestamps using binned-count
        autocorrelation. Returns (best_lag, peak_score, bins_per_period).

        Autocorrelation of raw IATs doesn't catch jittered beacons (IATs
        become i.i.d. random around the mean). Autocorrelation of a binned
        count series does: regular arrivals show up as a periodic spike
        pattern in counts, which survives per-arrival jitter as long as the
        underlying period is stable. We sweep multiple bin granularities
        (4, 6, 10 bins per period) and keep the best peak.
        """
        n = len(timestamps)
        if n < 8 or mean_interval <= 0:
            return None, 0.0, 0

        duration = timestamps[-1] - timestamps[0]
        if duration <= 0:
            return None, 0.0, 0

        best_overall = (None, 0.0, 0)

        for bins_per_period in (4, 6, 10):
            bin_size = mean_interval / bins_per_period
            if bin_size <= 0:
                continue

            num_bins = int(duration / bin_size) + 1
            if num_bins > 4096:
                bin_size = duration / 4096.0
                num_bins = 4096
                bins_per_period = max(1, int(round(mean_interval / bin_size)))
            if num_bins < 16:
                continue

            counts = [0] * num_bins
            t0 = timestamps[0]
            for ts in timestamps:
                idx = int((ts - t0) / bin_size)
                if idx >= num_bins:
                    idx = num_bins - 1
                counts[idx] += 1

            mean = sum(counts) / num_bins
            centered = [c - mean for c in counts]
            var = sum(x * x for x in centered)
            if var <= 0:
                continue

            candidate_lags = set()
            for harmonic in (1, 2):
                base = bins_per_period * harmonic
                low = max(2, int(base * 0.7))
                high = min(num_bins // 2, int(base * 1.3))
                for lag in range(low, high + 1):
                    candidate_lags.add(lag)
            if not candidate_lags:
                continue

            for lag in candidate_lags:
                s = sum(centered[i] * centered[i + lag]
                        for i in range(num_bins - lag))
                score = s / var
                if score > best_overall[1]:
                    best_overall = (lag, score, bins_per_period)

        return best_overall

    @staticmethod
    def _calculate_entropy(string):
        """Shannon entropy of a string/bytes. High entropy hints at
        randomness (DGA, encrypted payload, packed binary)."""
        if not string:
            return 0
        counter = Counter(string)
        length = len(string)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )

    @staticmethod
    def _is_local_ip(ip_str):
        """True if ip_str is a private/RFC1918 address."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    # --------------------------------------------------- post-processing

    def _classify_protocol_risks(self):
        """Bind PROTOCOL_RISK metadata onto each entry of results['protocols']."""
        for proto in self.results["protocols"]:
            risk, warning = self.PROTOCOL_RISK.get(
                proto["name"], ('medium', None),
            )
            proto["risk_level"] = risk
            proto["warning"] = warning

    def _count_alerts_per_ip(self):
        """Populate ip_data['alert_count'] for every IP in results['ips']."""
        alert_counts = Counter(
            alert["ip"] for alert in self.results["alerts"] if "ip" in alert
        )
        for ip_data in self.results["ips"]:
            ip_data["alert_count"] = alert_counts.get(ip_data["ip"], 0)

    def _compute_host_risk_scores(self):
        """Baseline risk score per IP. Reputation lands later in the slow
        queue, so the API re-runs compute_host_risk_scores after merging the
        cached reputation rows. Persisting an initial score in the DB blob
        means the IPs table is already orderable on first render."""
        try:
            from host_risk import compute_host_risk_scores
        except Exception as e:
            print(f"[pcap_analyzer] host_risk import failed: {e}")
            return
        compute_host_risk_scores(self.results)

    def _carve_files(self):
        """Extract files from reassembled HTTP flows into results['carved_files'].
        Hash lookup (VT / MalwareBazaar) runs later in the slow Celery queue —
        this method only does on-disk + hash work."""
        thresholds = self.settings.get('thresholds') or {}
        carving = self.settings.get('carving') or {}
        if carving.get('enabled') is False:
            self.results['carved_files'] = []
            return

        # Prefer the deeper buffers from FileCarvingFlowAggregator; fall back
        # to the shared 64 KiB tcp_flows for tiny files.
        tcp_flows = (
            getattr(self, '_carving_flows', None)
            or getattr(self, '_tcp_flows', None)
            or {}
        )
        if not tcp_flows:
            self.results['carved_files'] = []
            return

        try:
            default_root = os.path.join(
                os.environ.get('UPLOAD_FOLDER', 'data/uploads'),
                '..', 'artifacts',
            )
            base = (
                carving.get('artifacts_dir')
                or os.environ.get('CARVED_FILES_DIR')
                or os.path.normpath(default_root)
            )
            scan_key = os.path.splitext(os.path.basename(self.filepath))[0]
            artifacts_dir = os.path.join(base, scan_key)
        except Exception:
            artifacts_dir = 'data/artifacts/unknown'

        max_size = int(
            carving.get('max_file_size')
            or thresholds.get('carving_max_file_size')
            or 50 * 1024 * 1024
        )
        min_size = int(
            carving.get('min_file_size')
            or thresholds.get('carving_min_file_size')
            or 1024
        )

        try:
            from file_carving import carve_http_files
        except Exception as e:
            print(f"[pcap_analyzer] file_carving import failed: {e}")
            self.results['carved_files'] = []
            return

        carved = carve_http_files(
            tcp_flows,
            artifacts_dir=artifacts_dir,
            max_file_size=max_size,
            min_file_size=min_size,
        )
        self.results['carved_files'] = carved
        print(f"[pcap_analyzer] carved {len(carved)} file(s) → {artifacts_dir}")

    def _collect_observed_artifacts(self):
        """Aggregate every artifact seen — JA3/JA3S/SNI/HTTP-Host/MAC — into a
        single results['observed_artifacts'] block consumed by correlation
        (first-seen alerts) and the database layer (artifact_seen upsert).

        Only non-empty, non-broadcast, non-multicast values are kept. MACs
        are filtered to those with at least one local IP attached — an
        external MAC observation usually reflects the upstream router and
        isn't actionable as an asset event."""
        ja3 = set()
        ja3s = set()
        ja4 = set()
        ja4s = set()
        ja4h = set()
        hassh = set()
        hassh_server = set()
        sni = set()
        host = set()
        mac = set()

        if isinstance(self._tls_info, dict):
            for ch in self._tls_info.get('client_hellos') or []:
                if ch.get('ja3_md5'):
                    ja3.add(ch['ja3_md5'])
                if ch.get('ja4'):
                    ja4.add(ch['ja4'])
                v = ch.get('sni')
                if v:
                    sni.add(v.lower().strip())
            for sh in self._tls_info.get('server_hellos') or []:
                if sh.get('ja3s_md5'):
                    ja3s.add(sh['ja3s_md5'])
                if sh.get('ja4s'):
                    ja4s.add(sh['ja4s'])

        if isinstance(self._http_info, dict):
            for req in self._http_info.get('requests') or []:
                v = (req.get('host') or '').lower().strip()
                if ':' in v:
                    v = v.split(':', 1)[0]
                if v:
                    host.add(v)
                if req.get('ja4h'):
                    ja4h.add(req['ja4h'])

        if isinstance(self._ssh_info, dict):
            for kx in self._ssh_info.get('kexinits') or []:
                # The KEXINIT carries both hashes, but we only "attribute"
                # one to this peer based on direction. Mixing them would
                # double-count.
                if kx.get('is_server'):
                    if kx.get('hassh_server'):
                        hassh_server.add(kx['hassh_server'])
                else:
                    if kx.get('hassh'):
                        hassh.add(kx['hassh'])

        ip_mac_mapping = self.results.get('ip_mac_mapping') or {}
        local_macs = set()
        for ip_str, macs in ip_mac_mapping.items():
            if not self._is_local_ip(ip_str):
                continue
            for m in macs:
                if not m:
                    continue
                ml = m.lower()
                if ml in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
                    continue
                first_octet = ml.split(':', 1)[0]
                try:
                    if int(first_octet, 16) & 0x01:
                        continue
                except ValueError:
                    continue
                local_macs.add(ml)
        mac.update(local_macs)

        quic_dest = sorted(getattr(self, '_quic_external_dests', None) or [])

        self.results['observed_artifacts'] = {
            'ja3': sorted(ja3),
            'ja3s': sorted(ja3s),
            'ja4': sorted(ja4),
            'ja4s': sorted(ja4s),
            'ja4h': sorted(ja4h),
            'hassh': sorted(hassh),
            'hassh_server': sorted(hassh_server),
            'sni': sorted(sni),
            'http_host': sorted(host),
            'mac': sorted(mac),
            'quic_dest': quic_dest,
        }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m pcap_analyzer <pcap_file>")
        sys.exit(1)

    analyzer = PCAPAnalyzer(sys.argv[1])
    results = analyzer.analyze()

    print("\n=== SUMMARY ===")
    print(f"Packets: {results['summary'].get('packet_count')}")
    print(f"Duration: {results['summary'].get('duration', 0):.2f}s")
    print(f"IPs: {len(results['ips'])}")
    print(f"Protocols: {len(results['protocols'])}")
    print(f"Alerts: {len(results['alerts'])}")

    print("\n=== ALERTS ===")
    for alert in results['alerts']:
        print(f"[{alert['severity'].upper()}] {alert['title']}: "
              f"{alert['description']}")
