"""
Outbound notification fanout.

After a scan saves, this module is called with the scan's alerts. For each
enabled webhook it filters alerts by min_severity + categories and posts
them to the channel — Slack/Teams (incoming-webhook URL), generic HTTP
POST, Syslog CEF over UDP/TCP, or SMTP email.

All transports use stdlib only (urllib, socket, smtplib) so no extra runtime
dependency. Errors are recorded back on the webhook row but never raised:
notification failure must not break alert persistence. Dispatch happens on
a background thread so the request thread isn't blocked on remote endpoints.
"""
import ipaddress
import json
import os
import smtplib
import socket
import ssl
import threading
import time
from datetime import datetime
from email.message import EmailMessage
from urllib import request as urlrequest
from urllib.error import URLError
from urllib.parse import urlparse

import database as db


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Cap how many alerts go to a single channel per scan. Slack/Teams/email
# are unusable when flooded with hundreds of messages; this gives the
# operator the highest-severity sample.
MAX_ALERTS_PER_CHANNEL = 25

# Per-call HTTP timeout (seconds). Webhooks should be fast or skipped.
HTTP_TIMEOUT_SECONDS = 5

# Default Syslog facility/severity if extra config doesn't override.
DEFAULT_SYSLOG_FACILITY = 14  # "log alert"
DEFAULT_SYSLOG_SEVERITY = 4   # "warning"


def _alert_id_tag(alert):
    """'#1234 ' display prefix for an alert, or '' when it has no DB id yet.

    The id lets an operator track and refer back to a specific alert from
    any channel; save_scan writes it onto the alert dict before dispatch.
    """
    aid = alert.get("id")
    return f"#{aid} " if aid not in (None, "") else ""


# ============================================================
#  Public entrypoint
# ============================================================

def dispatch_alerts_for_scan(scan_id, results, settings=None):
    """
    Fan out the scan's alerts to every enabled webhook. Returns immediately;
    actual sending runs on a daemon thread.

    Caller can pass settings to expose SMTP config without us having to
    reload from disk. If None, email channels look it up themselves.
    """
    if not results:
        return
    alerts = results.get("alerts") or []
    if not alerts:
        return
    try:
        webhooks = db.list_webhooks(enabled_only=True)
    except Exception as e:
        print(f"[notifications] failed to load webhooks: {e}")
        return
    if not webhooks:
        return

    summary = results.get("summary") or {}
    context = {
        "scan_id": scan_id,
        "filename": summary.get("filename"),
        "analyzed_at": summary.get("analyzed_at"),
        "total_alerts": len(alerts),
    }

    # Daemon thread: don't block the upload response on remote calls.
    t = threading.Thread(
        target=_dispatch_thread,
        args=(webhooks, alerts, context, settings or {}),
        daemon=True,
    )
    t.start()


def _dispatch_thread(webhooks, alerts, context, settings):
    for hook in webhooks:
        try:
            filtered = _filter_alerts(alerts, hook)
            if not filtered:
                continue
            filtered = filtered[:MAX_ALERTS_PER_CHANNEL]
            err = _send_to_webhook(hook, filtered, context, settings)
            db.mark_webhook_result(hook["id"], error=err)
        except Exception as e:
            db.mark_webhook_result(hook["id"], error=f"unexpected: {e}")


def _filter_alerts(alerts, hook):
    floor = SEVERITY_RANK.get(hook.get("min_severity", "high"), 2)
    cats_csv = hook.get("categories")
    categories = None
    if cats_csv:
        categories = {c.strip() for c in cats_csv.split(",") if c.strip()}

    out = []
    for a in alerts:
        sev = SEVERITY_RANK.get(a.get("severity"), 0)
        if sev < floor:
            continue
        if categories and a.get("category") not in categories:
            continue
        out.append(a)
    # Highest-severity alerts first
    out.sort(key=lambda a: -SEVERITY_RANK.get(a.get("severity"), 0))
    return out


# ============================================================
#  Per-channel sending
# ============================================================

def _send_to_webhook(hook, alerts, context, settings):
    """
    Returns None on success, error string on failure.
    """
    ttype = hook.get("type")
    target = hook.get("target")
    extra = hook.get("extra") or {}
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except (TypeError, ValueError):
            extra = {}

    try:
        if ttype == "slack":
            _send_slack(target, alerts, context)
        elif ttype == "teams":
            _send_teams(target, alerts, context)
        elif ttype == "generic":
            _send_generic(target, alerts, context)
        elif ttype == "syslog":
            _send_syslog(target, alerts, context, extra)
        elif ttype == "email":
            _send_email(target, alerts, context, settings)
        else:
            return f"unknown webhook type: {ttype}"
    except Exception as e:
        return f"{type(e).__name__}: {e}"
    return None


# ---- Slack ----

def _send_slack(url, alerts, context):
    blocks = [
        {"type": "header", "text": {"type": "plain_text",
                                    "text": f"PCAP Analyzer: {len(alerts)} alert(s) "
                                            f"from {context.get('filename') or 'scan'}"}},
    ]
    for a in alerts[:10]:  # Slack block limit ~50; we keep it readable
        title = a.get("title", "?")
        sev = a.get("severity", "?")
        ip = a.get("ip") or "-"
        desc = (a.get("description") or "")[:300]
        id_tag = _alert_id_tag(a)
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"*[{sev.upper()}] {id_tag}{title}*\n*src:* `{ip}`\n{desc}"},
        })
    if len(alerts) > 10:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn",
                          "text": f"... and {len(alerts) - 10} more alert(s)"}],
        })
    payload = {"blocks": blocks, "text": f"PCAP Analyzer: {len(alerts)} alert(s)"}
    _http_post_json(url, payload)


# ---- Microsoft Teams ----

def _send_teams(url, alerts, context):
    facts = []
    for a in alerts[:10]:
        facts.append({
            "name": f"[{(a.get('severity') or '').upper()}] {_alert_id_tag(a)}{a.get('title', '?')}",
            "value": f"src `{a.get('ip') or '-'}` — {(a.get('description') or '')[:200]}",
        })
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": _teams_theme_color(alerts),
        "summary": f"PCAP Analyzer: {len(alerts)} alerts",
        "title": f"PCAP Analyzer: {len(alerts)} alert(s) from {context.get('filename') or 'scan'}",
        "sections": [{"facts": facts}],
    }
    if len(alerts) > 10:
        payload["sections"].append({
            "text": f"... and {len(alerts) - 10} more alert(s) suppressed from this card",
        })
    _http_post_json(url, payload)


def _teams_theme_color(alerts):
    top = max((SEVERITY_RANK.get(a.get("severity"), 0) for a in alerts), default=0)
    return {0: "808080", 1: "F1C232", 2: "FF8C00", 3: "C00000"}.get(top, "808080")


# ---- Generic JSON POST ----

def _send_generic(url, alerts, context):
    payload = {
        "context": context,
        "alert_count": len(alerts),
        "alerts": alerts,
    }
    _http_post_json(url, payload)


# ---- Syslog CEF ----

def _send_syslog(target, alerts, context, extra):
    """
    target = "host:port" — UDP by default, TCP if extra.protocol == 'tcp'.
    Emits one CEF line per alert.
    """
    host, _, port_s = target.partition(":")
    port = int(port_s or "514")
    protocol = (extra.get("protocol") or "udp").lower()
    facility = int(extra.get("facility", DEFAULT_SYSLOG_FACILITY))

    sock = None
    try:
        if protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(HTTP_TIMEOUT_SECONDS)
            sock.connect((host, port))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        for a in alerts:
            line = _format_cef(a, facility)
            data = (line + "\n").encode("utf-8", errors="replace")
            if protocol == "tcp":
                sock.sendall(data)
            else:
                sock.sendto(data, (host, port))
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass


def _format_cef(alert, facility):
    """
    CEF line: <PRI>timestamp host CEF:0|Vendor|Product|Version|Signature|Name|Severity|Extension
    Severity is 0..10; we map low/medium/high/critical to 3/5/7/10.
    """
    sev_map = {"low": 3, "medium": 5, "high": 7, "critical": 10}
    cef_sev = sev_map.get(alert.get("severity"), 5)
    pri = facility * 8 + DEFAULT_SYSLOG_SEVERITY
    ts = datetime.utcnow().strftime("%b %d %H:%M:%S")
    host = socket.gethostname()
    sig = (alert.get("category") or "alert").replace("|", "_")
    name = (alert.get("title") or "Alert").replace("|", "_").replace("\n", " ")

    # CEF extensions: standard CEF keys when we can map, free-form otherwise.
    ext_pairs = [
        ("externalId", str(alert.get("id") or "")),
        ("src", alert.get("ip") or ""),
        ("msg", (alert.get("description") or "").replace("\n", " ").replace("=", "_")[:512]),
    ]
    details = alert.get("details") or {}
    for k in ("dst", "dst_port", "destination_ip", "destination_port"):
        v = details.get(k)
        if v not in (None, ""):
            ext_pairs.append((k, str(v)))
    ext = " ".join(f"{k}={v}" for k, v in ext_pairs if v != "")
    return (
        f"<{pri}>{ts} {host} CEF:0|PCAPAnalyzer|PCAPAnalyzer|1.0"
        f"|{sig}|{name}|{cef_sev}|{ext}"
    )


# ---- Email (SMTP) ----

def _send_email(target, alerts, context, settings):
    smtp_cfg = (settings.get("smtp") or {}) if settings else {}
    host = smtp_cfg.get("host")
    if not host:
        raise RuntimeError("smtp.host not configured in settings.json -> 'smtp'")
    port = int(smtp_cfg.get("port", 587))
    user = smtp_cfg.get("user")
    password = smtp_cfg.get("password")
    sender = smtp_cfg.get("from") or user
    use_tls = bool(smtp_cfg.get("starttls", True))

    msg = EmailMessage()
    msg["Subject"] = (
        f"[PCAPAnalyzer] {len(alerts)} alert(s) from "
        f"{context.get('filename') or 'scan'}"
    )
    msg["From"] = sender
    msg["To"] = target

    body_lines = [
        f"Scan ID: {context.get('scan_id')}",
        f"File:    {context.get('filename')}",
        f"Time:    {context.get('analyzed_at')}",
        f"Alerts:  {len(alerts)}",
        "",
    ]
    for a in alerts:
        body_lines.append(
            f"[{(a.get('severity') or '').upper():8s}] {_alert_id_tag(a)}{a.get('title')}")
        body_lines.append(f"  src: {a.get('ip') or '-'}")
        if a.get("description"):
            body_lines.append(f"  {a['description']}")
        body_lines.append("")
    msg.set_content("\n".join(body_lines))

    with smtplib.SMTP(host, port, timeout=HTTP_TIMEOUT_SECONDS) as s:
        if use_tls:
            s.starttls(context=ssl.create_default_context())
        if user and password:
            s.login(user, password)
        s.send_message(msg)


# ============================================================
#  Helpers
# ============================================================

# Outbound SSRF guard. Webhook URLs are analyst-configured, so the server must
# not be coaxed into requesting loopback/private/link-local space (cloud
# metadata endpoints, internal admin panels) or non-HTTP schemes (file://,
# gopher://). Set PCAP_ALLOW_PRIVATE_WEBHOOKS=1 when the alerting stack
# genuinely lives on the same private subnet.
_ALLOW_PRIVATE_WEBHOOKS = os.environ.get("PCAP_ALLOW_PRIVATE_WEBHOOKS") == "1"


def _assert_safe_url(url):
    """Raise ValueError if *url* is not a safe outbound HTTP(S) target."""
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"webhook URL scheme must be http or https, got {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise ValueError("webhook URL has no host")
    if _ALLOW_PRIVATE_WEBHOOKS:
        return
    try:
        infos = socket.getaddrinfo(
            host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as e:
        raise ValueError(f"cannot resolve webhook host {host!r}: {e}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise ValueError(
                f"webhook host {host!r} resolves to non-public address "
                f"{ip} — blocked to prevent SSRF")


def _http_post_json(url, payload):
    _assert_safe_url(url)
    body = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # urllib raises HTTPError/URLError on failure; let it propagate so the
    # caller records the message verbatim.
    with urlrequest.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
        # Drain to ensure server sees the full request as completed
        resp.read(2048)
