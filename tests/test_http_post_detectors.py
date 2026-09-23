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


def _http(method, path, host="target.local", ua="curl/8.0", dport=80,
          src=LOCAL_IP, dst=EXTERNAL_IP):
    body = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n\r\n"
    ).encode()
    return IP(src=src, dst=dst) / TCP(sport=44444, dport=dport, flags="PA") / Raw(body)


# --- ScannerUserAgent ------------------------------------------------------

def test_vuln_scanner_user_agent_is_high(analyze):
    results = analyze([_http("GET", "/", ua="Nikto/2.1.5")])
    hits = find_alerts(results, title="Security Scanner User-Agent", category="http")
    assert hits
    assert hits[0]["severity"] == "high"
    assert "nikto" in hits[0]["details"]["matched_signatures"]


def test_external_recon_user_agent_is_medium(analyze):
    # zgrab/masscan sweep every public IP daily: background noise from outside.
    results = analyze([_http("GET", "/", ua="Mozilla/5.0 zgrab/0.x",
                             src=EXTERNAL_IP, dst=LOCAL_IP)])
    hits = find_alerts(results, title="Security Scanner User-Agent")
    assert hits and hits[0]["severity"] == "medium"


def test_internal_recon_user_agent_is_high(analyze):
    # The same recon tool run FROM an internal host is internal recon.
    results = analyze([_http("GET", "/", ua="Mozilla/5.0 zgrab/0.x",
                             src=LOCAL_IP, dst="10.0.0.9")])
    hits = find_alerts(results, title="Security Scanner User-Agent")
    assert hits and hits[0]["severity"] == "high"


def test_crawler_user_agent_is_low(analyze):
    results = analyze([_http("GET", "/", ua="Mozilla/5.0 (compatible; MJ12bot/v1.4.8)",
                             src=EXTERNAL_IP, dst=LOCAL_IP)])
    hits = find_alerts(results, title="Security Scanner User-Agent")
    assert hits and hits[0]["severity"] == "low"


def test_benign_user_agent_does_not_fire(analyze):
    results = analyze([_http("GET", "/", ua="Mozilla/5.0")])
    assert not has_alert(results, title="Security Scanner User-Agent")


# --- ExploitPaths ----------------------------------------------------------

def test_env_file_path_is_high(analyze):
    results = analyze([_http("GET", "/.env")])
    hits = find_alerts(results, title="Sensitive/Exploit Path", category="http")
    assert hits
    assert hits[0]["severity"] == "high"


def test_wp_login_path_inbound_is_medium(analyze):
    results = analyze([_http("GET", "/wp-login.php", src=EXTERNAL_IP, dst=LOCAL_IP)])
    hits = find_alerts(results, title="Sensitive/Exploit Path", category="http")
    assert hits
    assert hits[0]["severity"] == "medium"


def test_wp_login_path_outbound_is_low(analyze):
    # Internal user administering their own externally-hosted WordPress.
    results = analyze([_http("GET", "/wp-login.php")])
    hits = find_alerts(results, title="Sensitive/Exploit Path", category="http")
    assert hits
    assert hits[0]["severity"] == "low"


def test_spa_asset_config_json_does_not_fire(analyze):
    results = analyze([_http("GET", "/assets/config.json")])
    assert not has_alert(results, title="Sensitive/Exploit Path")


def test_root_config_json_is_high(analyze):
    results = analyze([_http("GET", "/config.json", src=EXTERNAL_IP, dst=LOCAL_IP)])
    hits = find_alerts(results, title="Sensitive/Exploit Path")
    assert hits and hits[0]["severity"] == "high"


def test_wp_config_backup_probe_is_high(analyze):
    results = analyze([_http("GET", "/blog/wp-config.php.bak", src=EXTERNAL_IP, dst=LOCAL_IP)])
    hits = find_alerts(results, title="Sensitive/Exploit Path")
    assert hits and hits[0]["severity"] == "high"


def test_web_config_needs_path_boundary(analyze):
    results = analyze([_http("GET", "/web.configuration/help", src=EXTERNAL_IP, dst=LOCAL_IP)])
    assert not has_alert(results, title="Sensitive/Exploit Path")


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
    assert hits[0]["details"]["upload_seen"] is True


def test_paste_service_get_is_low(analyze):
    results = analyze([_http("GET", "/raw/abc", host="pastebin.com")])
    hits = find_alerts(results, title="File-Share / Paste Service")
    assert hits and hits[0]["severity"] == "low"


def test_discord_and_firefox_sync_are_not_file_share(analyze):
    results = analyze([_http("POST", "/api/v9/x", host="discord.com"),
                       _http("POST", "/v1/sync", host="sync.firefox.com")])
    assert not has_alert(results, title="File-Share / Paste Service")


# --- HttpInjection direction / XSS scope ------------------------------------

def test_xss_markup_in_body_does_not_fire(analyze):
    body = (
        "POST /wp-admin/post.php HTTP/1.1\r\nHost: blog.example\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "content=<p>hi</p><script>ga()</script>"
    ).encode()
    pkt = IP(src=LOCAL_IP, dst="10.0.0.9") / TCP(sport=44444, dport=80, flags="PA") / Raw(body)
    results = analyze([pkt])
    assert not has_alert(results, title="HTTP Attack Pattern: XSS")


def test_xss_in_path_inbound_is_high(analyze):
    results = analyze([_http("GET", "/q?s=<script>alert(1)</script>",
                             src=EXTERNAL_IP, dst=LOCAL_IP)])
    hits = find_alerts(results, title="HTTP Attack Pattern: XSS")
    assert hits and hits[0]["severity"] == "high"


def test_outbound_injection_pattern_drops_one_notch(analyze):
    results = analyze([_http("GET", "/search?q=1%20union%20select%201,2")])
    hits = find_alerts(results, title="HTTP Attack Pattern: SQL Injection (URL-encoded)")
    assert hits and hits[0]["severity"] == "medium"
    assert hits[0]["details"]["outbound"] is True


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


def test_long_path_matching_checksum_does_not_trigger_cobalt(analyze):
    # Regression (2026-07): ~0.8% of ALL paths sum to 92/93 mod 256, so a
    # benign long URL could raise a critical CS alert on its own. Stager URIs
    # are short single-segment strings; the shape gate must reject this path
    # even though its checksum8 matches.
    path = "/aaaaaaaaaaII"  # 12 chars, sums to 92 (mod 256)
    assert sum(map(ord, path[1:])) % 256 == 92
    results = analyze([_http("GET", path)])
    assert not has_alert(results, title="Cobalt Strike")


def test_dotted_path_matching_checksum_does_not_trigger_cobalt(analyze):
    # An extension dot means a real resource, not a generated stager URI.
    path = "/a.al"  # 4 chars, sums to 92 (mod 256)
    assert sum(map(ord, path[1:])) % 256 == 92
    results = analyze([_http("GET", path)])
    assert not has_alert(results, title="Cobalt Strike")
