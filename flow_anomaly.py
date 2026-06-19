"""
Unsupervised flow-level anomaly detection.

Builds NetFlow-style features per (src, dst, dst_port, proto) tuple and
scores them with sklearn's IsolationForest. The model is fit on the
*current scan only* — it surfaces flows that look statistically different
from the rest of the same capture, without needing labeled data.

When sklearn is not installed the module degrades to a no-op. This keeps
the rest of the analyzer functional in minimal deployments.

Features per flow:
  - duration        : last - first packet timestamp (seconds)
  - packet_count    : total packets
  - byte_count      : total bytes
  - mean_pkt_size   : average packet length
  - std_pkt_size    : stddev of packet length
  - mean_iat        : mean inter-arrival-time
  - std_iat         : stddev of inter-arrival-time
"""
from collections import defaultdict
from datetime import datetime
import math


# ============================================================
#  Feature extraction
# ============================================================

def _proto_name(pkt, IP, TCP, UDP, ICMP):
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    return "OTHER"


def _build_flows(packets):
    """
    Yield (key, feature_vector) tuples. key is the flow identifier we use
    to attach an alert; feature_vector is the input to IsolationForest.
    """
    # Lazy-import scapy at call site to keep module import cheap.
    from scapy.all import IP, TCP, UDP, ICMP

    flows = defaultdict(lambda: {
        "timestamps": [],
        "sizes": [],
    })

    for pkt in packets:
        if IP not in pkt:
            continue
        src = pkt[IP].src
        dst = pkt[IP].dst
        if TCP in pkt:
            dport = int(pkt[TCP].dport)
            proto = "TCP"
        elif UDP in pkt:
            dport = int(pkt[UDP].dport)
            proto = "UDP"
        elif ICMP in pkt:
            dport = 0
            proto = "ICMP"
        else:
            continue

        key = (src, dst, dport, proto)
        flow = flows[key]
        flow["timestamps"].append(float(pkt.time))
        flow["sizes"].append(int(len(pkt)))

    keys = []
    features = []

    for key, flow in flows.items():
        ts = flow["timestamps"]
        sz = flow["sizes"]
        if len(ts) < 2:
            # Single-packet flows don't have a meaningful IAT or duration;
            # skipping keeps the feature space clean.
            continue
        ts.sort()
        duration = ts[-1] - ts[0]
        pkt_count = len(ts)
        byte_count = sum(sz)
        mean_size = byte_count / pkt_count
        std_size = _std(sz, mean_size)

        iats = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
        mean_iat = sum(iats) / len(iats)
        std_iat = _std(iats, mean_iat)

        keys.append(key)
        features.append([
            duration,
            pkt_count,
            byte_count,
            mean_size,
            std_size,
            mean_iat,
            std_iat,
        ])

    return keys, features


def _std(values, mean):
    if len(values) < 2:
        return 0.0
    s = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(s)


# ============================================================
#  Public entrypoint
# ============================================================

def detect_anomalous_flows(packets, settings=None):
    """
    Return a list of alerts. Empty list if sklearn is unavailable, the scan
    has too few flows to be meaningful, or no flows are anomalous.
    """
    settings = settings or {}
    thresholds = (settings.get("thresholds") or {})

    min_flows = int(thresholds.get("flow_anomaly_min_flows", 50))
    max_alerts = int(thresholds.get("flow_anomaly_max_alerts", 10))
    contamination = float(thresholds.get("flow_anomaly_contamination", 0.05))

    try:
        # Import lazily so a missing sklearn doesn't break the analyzer.
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return []

    keys, features = _build_flows(packets)
    if len(features) < min_flows:
        return []

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
    )
    model.fit(features)
    # decision_function: higher = more normal, lower = more anomalous.
    scores = model.decision_function(features)
    predictions = model.predict(features)  # -1 anomaly, +1 normal

    indexed = list(zip(range(len(keys)), scores, predictions))
    anomalies = [(i, s) for (i, s, p) in indexed if p == -1]
    anomalies.sort(key=lambda x: x[1])  # most negative = most anomalous first

    now = datetime.now().isoformat()
    alerts = []
    for idx, score in anomalies[:max_alerts]:
        src, dst, dport, proto = keys[idx]
        feat = features[idx]
        duration, pkt_count, byte_count, mean_size, std_size, mean_iat, std_iat = feat

        # Severity scales with how negative the score is. IsolationForest's
        # decision_function typically lives in roughly [-0.3, 0.3] for this
        # feature space, so -0.15 is a strong outlier.
        if score <= -0.15:
            severity = "high"
        elif score <= -0.05:
            severity = "medium"
        else:
            severity = "low"

        alerts.append({
            "severity": severity,
            "category": "anomaly",
            "title": "Anomalous Flow (Isolation Forest)",
            "description": (
                f"Flow {src} -> {dst}:{dport}/{proto} is statistically distinct "
                f"from the rest of the capture "
                f"(score {score:.3f}, {pkt_count} pkts, {byte_count} bytes, "
                f"duration {duration:.1f}s)"
            ),
            "ip": src,
            "details": {
                "src": src,
                "dst": dst,
                "dst_port": dport,
                "protocol": proto,
                "anomaly_score": round(float(score), 4),
                "duration_seconds": round(duration, 3),
                "packet_count": pkt_count,
                "byte_count": byte_count,
                "mean_packet_size": round(mean_size, 2),
                "std_packet_size": round(std_size, 2),
                "mean_inter_arrival_seconds": round(mean_iat, 4),
                "std_inter_arrival_seconds": round(std_iat, 4),
            },
            "recommendation": (
                "This flow is an outlier in the unsupervised statistical model. "
                "Use this as a triage hint, not a verdict — investigate the "
                "src/dst pair and confirm whether the deviation has a benign "
                "explanation (large transfer, long-lived session) or signals "
                "covert activity (low-and-slow exfil, beacon over uncommon port)."
            ),
            "timestamp": now,
        })

    return alerts
