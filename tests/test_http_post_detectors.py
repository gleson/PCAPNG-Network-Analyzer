"""HTTP-derived post-detectors.

All of these read ``analyzer._http_info``, populated by HttpInfoAggregator from
the request payload. On TCP/80 scapy consumes Raw into its HTTP layer, so this
whole family depends on the pkt_view HTTP-Raw resurrection (see
test_http_exploit_detector.py) — these fixtures double as regression cover for
that fix on a second port-80 path.

Covered: ScannerUserAgent, ExploitPaths, UnusualHttpMethod, HttpInjection,
FileShareUpload, CobaltStrike (checksum8 stager URI).
"""

from scapy.all import IP, TCP, Raw

from conftest import LOCAL_IP, EXTERNAL_IP, find_alerts, has_alert


def _http(method, path, host="target.local", ua="curl/8.0", dport=80):
    body = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n\r\n"
    ).encode()
    return IP(src=LOCAL_IP, dst=EXTERNAL_IP) / TCP(sport=44444, dport=dport, flags="PA") / Raw(body)


# --- ScannerUserAgent ------------------------------------------------------

def test_scanner_user_agent_is_critical(analyze):
    results = analyze([_http("GET", "/", ua="Nikto/2.1.5")])
    hits = find_alerts(results, title="Security Scanner User-Agent", category="http")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert "nikto" in hits[0]["details"]["matched_signatures"]


def test_benign_user_agent_does_not_fire(analyze):
    results = analyze([_http("GET", "/", ua="Mozilla/5.0")])
    assert not has_alert(results, title="Security Scanner User-Agent")


# --- ExploitPaths ----------------------------------------------------------

def test_env_file_path_is_high(analyze):
    results = analyze([_http("GET", "/.env")])
    hits = find_alerts(results, title="Sensitive/Exploit Path", category="http")
    assert hits
    assert hits[0]["severity"] == "high"


def test_wp_login_path_is_medium(analyze):
    results = analyze([_http("GET", "/wp-login.php")])
    hits = find_alerts(results, title="Sensitive/Exploit Path", category="http")
    assert hits
    assert hits[0]["severity"] == "medium"


# --- UnusualHttpMethod -----------------------------------------------------

def test_trace_method_is_flagged(analyze):
    results = analyze([_http("TRACE", "/")])
    hits = find_alerts(results, title="Unusual HTTP Method: TRACE", category="http")
    assert hits
    assert hits[0]["severity"] == "high"


# --- HttpInjection ---------------------------------------------------------

def test_sql_injection_pattern_fires(analyze):
    # URL-encoded so the space doesn't truncate the request-line path.
    results = analyze([_http("GET", "/search?q=1%20union%20select%201,2")])
    hits = find_alerts(results, title="HTTP Attack Pattern", category="http")
    assert hits
    assert "SQL Injection" in hits[0]["title"]


# --- FileShareUpload -------------------------------------------------------

def test_paste_service_host_fires(analyze):
    results = analyze([_http("POST", "/upload", host="pastebin.com")])
    hits = find_alerts(results, title="File-Share / Paste Service", category="exfil")
    assert hits
    assert hits[0]["severity"] == "medium"


# --- CobaltStrike (checksum8) ----------------------------------------------

def test_cobalt_strike_checksum8_stager_is_critical(analyze):
    # "/0," -> path chars sum to 92 (mod 256) = the CS x86 stager checksum.
    results = analyze([_http("GET", "/0,")])
    hits = find_alerts(results, title="Cobalt Strike Malleable C2 Profile", category="c2")
    assert hits
    assert hits[0]["severity"] == "critical"
    assert hits[0]["details"]["checksum_hits"]


def test_normal_get_does_not_trigger_cobalt(analyze):
    results = analyze([_http("GET", "/index.html")])
    assert not has_alert(results, title="Cobalt Strike")
