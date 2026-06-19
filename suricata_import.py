"""
Suricata / Zeek rule importer.

Translates Suricata `.rules` lines and Zeek `.sig` signatures into the
JSON rule schema already consumed by ``user_rules.py``. This lets the
analyst tap into the huge ecosystem of community rules (ET Open,
FrankenSnort, custom Zeek signatures) without hand-rewriting each rule.

Scope is intentionally conservative — only fields that map cleanly to
our matcher are honored:

  Suricata          ->  user_rules.match / aggregate / alert
  ----------------------------------------------------------
  proto             ->  match.protocol  (tcp/udp/icmp, http->tcp, dns->dns)
  dst_port          ->  match.dst_port  (single port only; ranges/lists -> any)
  src_port          ->  match.src_port  (idem)
  src/dst addr      ->  match.src_cidr / dst_cidr or direction
  content:"..."     ->  match.payload_contains  (first content kept)
  pcre:"/.../i"     ->  match.payload_regex
  msg:"..."         ->  alert.title
  sid:N             ->  rule.id  (prefixed "suricata_<sid>")
  classtype:X       ->  severity (mapped table) + category
  reference:cve,Y   ->  alert.description suffix
  priority:N        ->  severity (overrides classtype if present)

Anything we cannot model (flowbits, byte_test, stream sticky buffers,
threshold, http_uri offsets, ...) is preserved in ``alert.description``
as a hint but does NOT narrow matching. Imported rules therefore err on
the side of firing more often than the source rule would in Suricata
proper — flag and review.

Public entrypoints:
  parse_suricata_text(text)  -> {"rules": [...], "errors": [...]}
  parse_zeek_text(text)      -> {"rules": [...], "errors": [...]}
  import_file(path)          -> auto-detect by extension/header
"""
from __future__ import annotations

import os
import re


# ============================================================
#  Severity / category maps
# ============================================================

# Suricata classtype -> our severity bucket
_CLASSTYPE_SEVERITY = {
    "attempted-admin": "critical",
    "successful-admin": "critical",
    "successful-user": "critical",
    "trojan-activity": "critical",
    "shellcode-detect": "critical",
    "web-application-attack": "critical",
    "attempted-user": "high",
    "successful-recon-largescale": "high",
    "successful-dos": "high",
    "attempted-dos": "high",
    "attempted-recon": "high",
    "policy-violation": "high",
    "credential-theft": "high",
    "exploit-kit": "critical",
    "malware-cnc": "critical",
    "command-and-control": "critical",
    "bad-unknown": "medium",
    "network-scan": "medium",
    "protocol-command-decode": "medium",
    "misc-attack": "medium",
    "misc-activity": "low",
    "not-suspicious": "low",
    "unknown": "medium",
    "default-login-attempt": "medium",
}

# Suricata priority -> severity
_PRIORITY_SEVERITY = {1: "critical", 2: "high", 3: "medium", 4: "low"}


# ============================================================
#  Suricata parser
# ============================================================

# Header: action proto src_addr src_port -> dst_addr dst_port (...)
_HEADER_RE = re.compile(
    r"""^
    \s*
    (?P<action>alert|drop|reject|pass|log)
    \s+
    (?P<proto>\S+)
    \s+
    (?P<src_addr>\S+)
    \s+
    (?P<src_port>\S+)
    \s+
    (?P<dir>->|<>)
    \s+
    (?P<dst_addr>\S+)
    \s+
    (?P<dst_port>\S+)
    \s*
    \((?P<opts>.*)\)
    \s*$
    """,
    re.VERBOSE,
)

# Suricata content "|hh hh|" hex escape
_HEX_ESCAPE = re.compile(r"\|([0-9a-fA-F\s]+)\|")


def _split_options(blob):
    """Split a Suricata option block by ';' while respecting quoted strings.
    Returns a list of raw "key:value" or bare-keyword tokens, stripped."""
    tokens = []
    buf = []
    in_quote = False
    escape = False
    for ch in blob:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
            continue
        if ch == ";" and not in_quote:
            token = "".join(buf).strip()
            if token:
                tokens.append(token)
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        tokens.append(tail)
    return tokens


def _kv(token):
    """Split a single option token into (key, value)."""
    idx = token.find(":")
    if idx < 0:
        return token.strip().lower(), None
    key = token[:idx].strip().lower()
    val = token[idx + 1:].strip()
    if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        val = val[1:-1]
    return key, val


def _decode_content(raw):
    """Translate Suricata content escapes into a literal byte string.
    ``foo|0a 0d|bar`` -> ``b"foo\\n\\rbar"``. Unknown escapes are left as-is."""
    def sub(match):
        hexpart = match.group(1).replace(" ", "")
        if len(hexpart) % 2:
            return match.group(0).encode("latin-1", errors="replace")
        try:
            return bytes.fromhex(hexpart)
        except ValueError:
            return match.group(0).encode("latin-1", errors="replace")

    out = bytearray()
    pos = 0
    for m in _HEX_ESCAPE.finditer(raw):
        out.extend(raw[pos:m.start()].encode("utf-8", errors="replace"))
        out.extend(sub(m))
        pos = m.end()
    out.extend(raw[pos:].encode("utf-8", errors="replace"))
    return bytes(out)


def _addr_to_cidr(addr):
    """Turn a Suricata address token into a CIDR string or None.
    We support: literal IP, CIDR, $HOME_NET, $EXTERNAL_NET, ``any``, ``!any``.
    Lists / negations / variables we don't understand return None (= match any)."""
    if not addr or addr == "any":
        return None
    if addr.startswith("$"):
        return None  # variable, handled at direction level
    if "[" in addr or "!" in addr or "," in addr:
        return None  # lists/negations not supported
    return addr  # literal IP or CIDR (ipaddress will parse on normalize)


def _addr_kind(addr):
    """Classify an addr token into ``home`` | ``external`` | ``any`` | ``literal``."""
    if not addr or addr == "any":
        return "any"
    a = addr.upper()
    if "HOME_NET" in a or "LAN" in a or "INTERNAL" in a:
        return "home"
    if "EXTERNAL_NET" in a or "EXTERNAL" in a:
        return "external"
    return "literal"


def _direction_from_addrs(src_addr, dst_addr):
    """Infer outbound / inbound / lateral / any from Suricata HOME/EXTERNAL hints."""
    s = _addr_kind(src_addr)
    d = _addr_kind(dst_addr)
    if s == "home" and d == "external":
        return "outbound"
    if s == "external" and d == "home":
        return "inbound"
    if s == "home" and d == "home":
        return "lateral"
    return "any"


def _port_to_int(port_tok):
    """Parse a Suricata port token. Single integer -> int. Anything else -> None."""
    if not port_tok or port_tok == "any":
        return None
    if port_tok.startswith("$"):
        return None
    if port_tok.isdigit():
        return int(port_tok)
    return None  # ranges, lists, negations -> match any


def _normalize_proto(proto, dst_port):
    """Map a Suricata proto token to the user_rules vocabulary."""
    p = (proto or "").lower()
    if p in ("tcp", "udp", "icmp"):
        return p
    if p == "dns":
        return "dns"
    if p in ("http", "tls", "ssl", "smtp", "ftp", "ssh", "smb", "imap", "pop3"):
        return "tcp"
    if p == "ip":
        return "any"
    return "any"


def parse_suricata_line(line):
    """Parse one Suricata rule line. Returns a rule dict ready for
    ``user_rules._normalize_rule``. Raises ValueError on a structurally
    broken rule (missing header / sid / msg)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _HEADER_RE.match(line)
    if not m:
        raise ValueError("malformed rule header")

    action = m.group("action").lower()
    if action == "pass":
        return None  # we don't model pass rules

    tokens = _split_options(m.group("opts"))
    opts = [_kv(t) for t in tokens]

    msg = sid = priority = classtype = None
    content = None
    content_nocase = False
    pcre = pcre_flags = None
    references = []
    metadata_kvs = []
    unsupported_hints = []

    last_key = None
    for key, val in opts:
        if key == "msg":
            msg = val
        elif key == "sid":
            sid = val
        elif key == "priority":
            try:
                priority = int(val)
            except (TypeError, ValueError):
                pass
        elif key == "classtype":
            classtype = val
        elif key == "content" and content is None:
            content = val  # keep first content as the match anchor
            last_key = "content"
            continue
        elif key == "nocase" and last_key == "content":
            content_nocase = True
        elif key == "pcre" and pcre is None:
            # Form: "/pattern/flags"
            if val:
                if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
                    val = val[1:-1]
                if val.startswith("!"):
                    val = val[1:]  # negated pcre; we drop the negation
                if val.startswith("/"):
                    closing = val.rfind("/")
                    if closing > 0:
                        pcre = val[1:closing]
                        pcre_flags = val[closing + 1:]
        elif key == "reference":
            references.append(val)
        elif key == "metadata":
            metadata_kvs.append(val or "")
        elif key in (
            "flowbits", "threshold", "detection_filter", "byte_test",
            "byte_jump", "isdataat", "stream_size", "flow", "ssl_state",
            "http_uri", "http_header", "http_client_body", "http_cookie",
            "file_data", "tls.cert_subject", "tls.sni",
        ):
            # These narrow matches in Suricata but we cannot model them faithfully.
            unsupported_hints.append(key)
        last_key = key

    if not sid:
        raise ValueError("rule has no sid")
    if not msg:
        msg = f"Suricata rule {sid}"

    # Severity: explicit priority wins, then classtype, else medium
    severity = "medium"
    if priority and priority in _PRIORITY_SEVERITY:
        severity = _PRIORITY_SEVERITY[priority]
    elif classtype and classtype in _CLASSTYPE_SEVERITY:
        severity = _CLASSTYPE_SEVERITY[classtype]

    # Drop rules => higher severity bump
    if action == "drop" and severity == "medium":
        severity = "high"

    src_port = _port_to_int(m.group("src_port"))
    dst_port = _port_to_int(m.group("dst_port"))
    proto = _normalize_proto(m.group("proto"), dst_port)

    match = {
        "protocol": proto,
        "src_port": src_port,
        "dst_port": dst_port,
        "src_cidr": _addr_to_cidr(m.group("src_addr")),
        "dst_cidr": _addr_to_cidr(m.group("dst_addr")),
        "direction": _direction_from_addrs(m.group("src_addr"), m.group("dst_addr")),
    }
    if content:
        # Decode hex escapes; if the result is pure ASCII keep it as text so
        # the normalize step can encode it itself.
        decoded = _decode_content(content)
        try:
            text = decoded.decode("ascii")
            match["payload_contains"] = text
        except UnicodeDecodeError:
            # Fall back to a regex that matches the literal bytes; user_rules
            # compiles the regex against raw bytes.
            escaped = "".join(f"\\x{b:02x}" for b in decoded)
            match["payload_regex"] = escaped
        if content_nocase and "payload_contains" in match:
            # user_rules contains-match is case-sensitive; promote to regex.
            match["payload_regex"] = re.escape(match.pop("payload_contains"))
    if pcre and "payload_regex" not in match:
        match["payload_regex"] = pcre

    desc_extra = []
    if references:
        desc_extra.append("refs: " + ", ".join(references[:3]))
    if unsupported_hints:
        desc_extra.append(
            "unsupported keys (rule may fire more broadly than Suricata): "
            + ", ".join(sorted(set(unsupported_hints)))
        )

    rule = {
        "id": f"suricata_{sid}",
        "name": msg,
        "severity": severity,
        "category": classtype or "imported",
        "enabled": True,
        "match": {k: v for k, v in match.items() if v is not None},
        "aggregate": {"key": "src+dst+dst_port", "min_count": 1},
        "alert": {
            "title": msg,
            "description": (
                "{src} -> {dst}:{dst_port} matched Suricata sid:" + str(sid)
                + (f" ({'; '.join(desc_extra)})" if desc_extra else "")
            ),
            "recommendation": (
                f"Imported from Suricata sid:{sid}. Review the upstream rule "
                "for full context before responding."
            ),
        },
    }

    # Carry CVE references into MITRE description so they show up in reports
    cves = [r for r in references if r.lower().startswith("cve,")]
    if cves:
        rule["alert"]["description"] += " [" + ", ".join(
            "CVE-" + c.split(",", 1)[1] for c in cves if "," in c
        ) + "]"

    return rule


def parse_suricata_text(text):
    """Parse a whole Suricata .rules buffer. Returns
    ``{"rules": [...], "errors": [{"line": N, "error": str}]}``.
    Multi-line rules (trailing backslash) are joined first."""
    rules = []
    errors = []
    # Join continuation lines (`\` at EOL)
    joined = []
    pending = ""
    for i, raw in enumerate(text.splitlines(), start=1):
        if raw.rstrip().endswith("\\"):
            pending += raw.rstrip()[:-1] + " "
            continue
        full = (pending + raw).strip() if pending else raw
        pending = ""
        joined.append((i, full))
    if pending:
        joined.append((len(joined) + 1, pending))

    for lineno, line in joined:
        if not line or line.startswith("#"):
            continue
        try:
            rule = parse_suricata_line(line)
            if rule:
                rules.append(rule)
        except ValueError as e:
            errors.append({"line": lineno, "error": str(e)})
    return {"rules": rules, "errors": errors}


# ============================================================
#  Zeek signature parser
# ============================================================

# signature SID { ...directives... }
_ZEEK_SIG_RE = re.compile(
    r"signature\s+(?P<sid>[\w\-\.]+)\s*\{(?P<body>[^}]*)\}",
    re.IGNORECASE | re.DOTALL,
)


def _zeek_directives(body):
    """Yield (directive, value) pairs from a Zeek signature body."""
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # directive value (free-form; payload uses /regex/ syntax)
        parts = line.split(None, 1)
        if len(parts) == 1:
            yield parts[0].lower(), ""
        else:
            yield parts[0].lower(), parts[1].strip()


def parse_zeek_signature(sid, body):
    """Translate one Zeek signature block."""
    match = {"protocol": "any", "direction": "any"}
    msg = f"Zeek signature {sid}"
    severity = "medium"

    for directive, value in _zeek_directives(body):
        v = value.rstrip(";").strip()
        # `ip-proto == tcp`
        if directive == "ip-proto":
            tok = v.replace("==", "").strip()
            if tok in ("tcp", "udp", "icmp"):
                match["protocol"] = tok
        elif directive in ("dst-port", "dst_port"):
            tok = v.replace("==", "").strip()
            port = _port_to_int(tok)
            if port is not None:
                match["dst_port"] = port
        elif directive in ("src-port", "src_port"):
            tok = v.replace("==", "").strip()
            port = _port_to_int(tok)
            if port is not None:
                match["src_port"] = port
        elif directive in ("src-ip", "src_ip"):
            tok = v.replace("==", "").strip()
            cidr = _addr_to_cidr(tok)
            if cidr:
                match["src_cidr"] = cidr
        elif directive in ("dst-ip", "dst_ip"):
            tok = v.replace("==", "").strip()
            cidr = _addr_to_cidr(tok)
            if cidr:
                match["dst_cidr"] = cidr
        elif directive in ("payload", "http-request", "http-reply-body",
                            "http-header", "tcp-state"):
            # /regex/ form
            if v.startswith("/") and v.rfind("/") > 0:
                match["payload_regex"] = v[1:v.rfind("/")]
        elif directive == "event":
            msg = v.strip('"') or msg
        elif directive in ("requires-signature", "requires-reverse-signature"):
            pass  # cross-signature flow tracking not supported

    return {
        "id": f"zeek_{sid}",
        "name": msg,
        "severity": severity,
        "category": "imported-zeek",
        "enabled": True,
        "match": {k: v for k, v in match.items() if v is not None},
        "aggregate": {"key": "src+dst+dst_port", "min_count": 1},
        "alert": {
            "title": msg,
            "description": "{src} -> {dst}:{dst_port} matched Zeek signature " + sid,
            "recommendation": (
                f"Imported from Zeek signature {sid}. Verify the upstream "
                "signature for full context."
            ),
        },
    }


def parse_zeek_text(text):
    """Parse a Zeek .sig buffer into normalized rules."""
    rules = []
    errors = []
    for m in _ZEEK_SIG_RE.finditer(text):
        sid = m.group("sid")
        try:
            rules.append(parse_zeek_signature(sid, m.group("body")))
        except Exception as e:  # noqa: BLE001
            errors.append({"sid": sid, "error": str(e)})
    return {"rules": rules, "errors": errors}


# ============================================================
#  Format auto-detection
# ============================================================

def detect_format(text, filename=None):
    """Return ``"suricata"`` or ``"zeek"`` based on filename or content."""
    if filename:
        low = filename.lower()
        if low.endswith(".sig") or low.endswith(".zeek"):
            return "zeek"
        if low.endswith(".rules") or low.endswith(".rule"):
            return "suricata"
    head = text.lstrip()[:512]
    if re.match(r"^\s*signature\s+\S+\s*\{", head, re.IGNORECASE):
        return "zeek"
    return "suricata"


def import_text(text, fmt=None, filename=None):
    """Parse a rules buffer in either format. Returns parsed-rules dict."""
    fmt = fmt or detect_format(text, filename)
    if fmt == "zeek":
        result = parse_zeek_text(text)
    else:
        result = parse_suricata_text(text)
    result["format"] = fmt
    return result


def import_file(path):
    """Read *path* and parse it. Format inferred from extension."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    return import_text(text, filename=path)
